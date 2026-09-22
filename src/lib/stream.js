// 每个机构一条只增的签名事件流，记录间以 SHA-256 哈希链相连。
// 名单更新、凭证吊销、互认关系暂停/恢复、验签钥轮换都以事件形式存在；
// 接收方按 (issuer, seq) 验签、补缺、去重，离线恢复后得到同一状态。
import { createHash } from 'node:crypto';
import { b64url, canonicalJSON } from './encoding.js';
import { signPayload, openEnvelope } from './envelope.js';
import { publicKeyFromJwk } from './keyring.js';

export const EVENT_KINDS = new Set([
  'sanction.list.updated', // 名单条目增量
  'rule.floor.updated', // 各审核范围最低规则版本
  'credential.revoked', // 凭证吊销
  'relationship.suspended', // 合规负责人暂停互认
  'relationship.resumed',
  'key.rotated', // 验签公钥轮换公告（由旧钥签名，形成轮换锚链）
]);

function recordHash(record) {
  return b64url(
    createHash('sha256')
      .update(canonicalJSON({
        iss: record.iss,
        seq: record.seq,
        ts: record.ts,
        kind: record.kind,
        kid: record.kid,
        body: record.body,
        prev: record.prev,
      }))
      .digest(),
  );
}

// 本机构自己的事件流（持有私钥）。
export class LocalEventStream {
  constructor(issuer, keyResolver, records = []) {
    this.issuer = issuer;
    // keyResolver(kid) -> SignKeyObject；轮换后默认取当前钥。
    this.keyResolver = keyResolver;
    this.records = records;
  }

  // signKid：本事件用哪把钥签名（密钥轮换事件必须用旧钥 predecessor）。
  append(kind, body, ts, signKid = null) {
    if (!EVENT_KINDS.has(kind)) throw new Error(`未知事件类型 ${kind}`);
    const last = this.records[this.records.length - 1];
    const record = {
      iss: this.issuer,
      seq: last ? last.seq + 1 : 1,
      ts,
      kind,
      kid: signKid ?? this.keyResolver().kid,
      body,
      prev: last ? last.hash : null,
    };
    record.hash = recordHash(record);
    record.envelope = signPayload(stripEnvelope(record), this.keyResolver(record.kid).privateKey);
    this.records.push(record);
    return record;
  }

  // 同步给对端的最小数据：只有信封。
  exportSince(seq = 0) {
    return this.records.filter((r) => r.seq > seq).map((r) => r.envelope);
  }
}

function stripEnvelope(record) {
  const { envelope, ...rest } = record;
  return rest;
}

// 多机构事件流的接收侧：验签、查重、查缺、哈希链校验、轮换钥学习。
export class ReplicatedLog {
  constructor(baseResolveKey) {
    // baseResolveKey(iss, kid) -> KeyObject，来自带外建立的初始公钥目录。
    this.baseResolveKey = baseResolveKey;
    // iss -> Map(seq -> record)
    this.streams = new Map();
    this.ingested = new Set(); // `${iss}:${seq}` 幂等去重
    // 通过已验签的 key.rotated 事件学到的新公钥：`${iss}:${kid}` -> KeyObject
    this.learnedKeys = new Map();
  }

  resolveKey(iss, kid) {
    const learned = this.learnedKeys.get(`${iss}:${kid}`);
    if (learned) return learned;
    return this.baseResolveKey(iss, kid);
  }

  _bucket(issuer) {
    let bucket = this.streams.get(issuer);
    if (!bucket) {
      bucket = new Map();
      this.streams.set(issuer, bucket);
    }
    return bucket;
  }

  // 单条摄入。重复信封静默跳过；跳号、断链、伪签一律抛异常并拒绝（不产生部分应用）。
  ingest(envelope) {
    const { payload } = openEnvelope(envelope, (p) => {
      if (p.kind === 'key.rotated') {
        // 轮换公告本身由旧钥签名：body.predecessor 只能在已信任钥中选，伪造仍不可行。
        return this.resolveKey(p.iss, p.body.predecessor);
      }
      return this.resolveKey(p.iss, p.kid);
    });
    const record = payload;
    for (const key of ['iss', 'seq', 'ts', 'kind', 'kid', 'body', 'prev', 'hash']) {
      if (record[key] === undefined) throw new Error('事件记录缺少字段');
    }
    if (!EVENT_KINDS.has(record.kind)) throw new Error(`未知事件类型 ${record.kind}`);
    const id = `${record.iss}:${record.seq}`;
    if (this.ingested.has(id)) return { duplicate: true, record };
    const bucket = this._bucket(record.iss);
    const expectedSeq = bucket.size + 1;
    if (record.seq !== expectedSeq) {
      throw new Error(`事件流 ${record.iss} 跳号：期望 ${expectedSeq}，收到 ${record.seq}`);
    }
    if (recordHash(record) !== record.hash) throw new Error(`事件 ${id} 哈希不匹配`);
    const prev = bucket.size ? [...bucket.values()][bucket.size - 1].hash : null;
    if ((record.prev ?? null) !== prev) throw new Error(`事件 ${id} 哈希链断裂`);

    if (record.kind === 'key.rotated') {
      const b = record.body;
      if (b.predecessor !== record.kid) throw new Error(`事件 ${id} 轮换公告签名钥与前驱不一致`);
      this.learnedKeys.set(`${record.iss}:${b.kid}`, publicKeyFromJwk(b.jwk));
    }

    bucket.set(record.seq, { ...record, envelope });
    this.ingested.add(id);
    return { duplicate: false, record };
  }

  ingestMany(envelopes) {
    const applied = [];
    for (const envelope of envelopes) {
      const result = this.ingest(envelope);
      if (!result.duplicate) applied.push(result.record);
    }
    return applied;
  }

  // 离线恢复：返回某机构已持久化的最后序号，对端据此只补发缺口。
  highWatermark(issuer) {
    const bucket = this.streams.get(issuer);
    return bucket ? bucket.size : 0;
  }

  // 确定性全序：按 (ts, iss, seq) 排序，使不同机构以不同到达顺序摄入也得到相同折叠结果。
  orderedRecords() {
    const all = [];
    for (const bucket of this.streams.values()) {
      for (const record of bucket.values()) all.push(record);
    }
    return all.sort((a, b) => a.ts - b.ts || a.iss.localeCompare(b.iss) || a.seq - b.seq);
  }
}
