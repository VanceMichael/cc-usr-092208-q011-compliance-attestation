// 参与机构节点：在本地保留完整客户档案，跨境链路只交换最小证明。
// 节点组装密钥环、签名事件流与复制日志，对外提供签发、验签、质疑、补充、
// 吊销、暂停互认、幂等付款门禁与审计报告。
import { createHash } from 'node:crypto';
import { KeyRing, publicKeyFromJwk } from './keyring.js';
import { LocalEventStream, ReplicatedLog } from './stream.js';
import { signPayload, openEnvelope } from './envelope.js';
import { issuePseudonym, orderFingerprint, nonce } from './identity.js';
import {
  buildCredential,
  assertWellFormed,
  evidenceDigest,
} from './attestation.js';
import { foldState, evaluatePayment } from './state.js';
import { b64url, canonicalJSON, utf8 } from './encoding.js';

export { evidenceDigest, orderFingerprint, nonce };

export class Institution {
  constructor(id, { clock = () => Math.floor(Date.now() / 1000) } = {}) {
    this.id = id;
    this.clock = clock;
    this.ring = KeyRing.initialize(id, 'k1', clock());
    this.stream = new LocalEventStream(id, (kid) => this.ring.keys.get(kid ?? this.ring.currentKid));
    // 带外建立的初始公钥目录：peerId -> Map(kid -> KeyObject)
    this.directory = new Map();
    this.replicated = new ReplicatedLog((iss, kid) => {
      if (iss === this.id) return this.ring.getPublic(kid);
      const peer = this.directory.get(iss);
      const key = peer?.get(kid);
      if (!key) throw new Error(`没有 ${iss} 的可信公钥 ${kid}`);
      return key;
    });

    this.rotationSecrets = new Map(); // `${peerId}:${epoch}` -> secret
    this.pseudonymIndex = new Map(); // `${peerId}:${epoch}` -> Map(subjectId -> pseudonym)
    this.epochByPeer = new Map();
    this.issued = new Map(); // jti -> { credential, compact, order, subjectId, peerId }
    this.seenCredentials = new Map(); // 接收侧验签过的凭证 jti -> payload
    this.subjectMaterial = new Map(); // subjectId -> 本地材料（永不出境）
    this.payments = new Map(); // idempotencyKey -> 付款记录
    this.consumedOneTime = new Set(); // 已使用的一次性凭证 jti
    this.supplements = new Map(); // jti -> [补充证明]
  }

  // ---- 带外信任建立 ----
  bootstrapWith(peer) {
    this._trust(peer);
    peer._trust(this);
  }

  _trust(peer) {
    let keys = this.directory.get(peer.id);
    if (!keys) {
      keys = new Map();
      this.directory.set(peer.id, keys);
    }
    for (const k of peer.ring.keys.values()) keys.set(k.kid, k.publicKey);
  }

  // ---- 验签钥轮换：轮换公告由旧钥签名，沿哈希链传播 ----
  rotateSigningKey(newKid = `k${this.ring.keys.size + 1}`, ts = this.clock()) {
    const predecessor = this.ring.currentKid;
    this.ring.rotate(newKid, ts);
    const record = this.stream.append('key.rotated', {
      kid: newKid,
      predecessor,
      jwk: this.ring.publicJwk(newKid),
    }, ts, predecessor);
    this.replicated.ingest(record.envelope);
    return newKid;
  }

  // 本机构发布的事件同时进入自己的复制状态，保证“我宣布的底线/暂停”在我这里同样生效。
  _publish(kind, body, ts, signKid = null) {
    const record = this.stream.append(kind, body, ts, signKid);
    this.replicated.ingest(record.envelope);
    return record;
  }

  // ---- 可轮换客户标识 ----
  setRotationSecret(peerId, epoch, secret) {
    this.rotationSecrets.set(`${peerId}:${epoch}`, secret);
    this.epochByPeer.set(peerId, epoch);
  }

  pseudonymFor(subjectId, peerId, epoch = this.epochByPeer.get(peerId)) {
    const secret = this.rotationSecrets.get(`${peerId}:${epoch}`);
    if (!secret) throw new Error(`未配置与 ${peerId} 在轮换周期 ${epoch} 的秘密`);
    const key = `${peerId}:${epoch}`;
    let index = this.pseudonymIndex.get(key);
    if (!index) {
      index = new Map();
      this.pseudonymIndex.set(key, index);
    }
    let pn = index.get(subjectId);
    if (!pn) {
      pn = issuePseudonym({
        institutionId: this.id,
        subjectId,
        peerInstitutionId: peerId,
        rotationEpoch: epoch,
        rotationSecret: secret,
      });
      index.set(subjectId, pn);
    }
    return pn;
  }

  // 轮换后旧周期假名不再签发；新旧假名之间仅凭链路上的标识无法关联。
  advanceEpoch(peerId, newEpoch, newSecret) {
    this.setRotationSecret(peerId, newEpoch, newSecret);
  }

  // ---- 本地材料登记（仅本地） ----
  noteSubject(subjectId, material) {
    this.subjectMaterial.set(subjectId, material);
  }

  // ---- 审核结论签发 ----
  issueCredential({
    subjectId,
    peerId,
    order,
    scopes,
    ruleVersions,
    findings,
    ttlSeconds = 3600,
    restrictions = [],
    parentJti = null,
    ts = this.clock(),
  }) {
    if (!this.subjectMaterial.has(subjectId)) throw new Error('本地缺少客户材料，不能凭空签发');
    const pseudonym = this.pseudonymFor(subjectId, peerId);
    const boundOrder = { ...order, payer_pseudonym: order.payer_pseudonym ?? pseudonym, payee_pseudonym: order.payee_pseudonym };
    if (!boundOrder.payee_pseudonym) throw new Error('订单缺少收款方假名');
    const fp = orderFingerprint(boundOrder);
    const jti = `jti:${nonce(16)}`;
    const evidence = scopes.map((scope) => ({
      scope,
      ruleVersion: ruleVersions[scope],
      digest: evidenceDigest(scope, ruleVersions[scope], findings[scope]),
    }));
    const payload = buildCredential({
      jti,
      issuer: this.id,
      audience: peerId,
      subjectPseudonym: pseudonym,
      orderFingerprint: fp,
      scopes,
      ruleVersions,
      evidence,
      issuedAt: ts,
      expiresAt: ts + ttlSeconds,
      restrictions,
      parentJti,
      kid: this.ring.currentKid,
    });
    const compact = signPayload(payload, this.ring.current.privateKey);
    this.issued.set(jti, { credential: payload, compact, order: boundOrder, subjectId, peerId });
    return { credential: payload, compact, order: boundOrder, orderFingerprint: fp };
  }

  // ---- 事件发布（名单 / 规则底线 / 吊销 / 暂停） ----
  publishSanctions(listVersion, { added = [], removed = [] } = {}, ts = this.clock()) {
    return this._publish('sanction.list.updated', {
      list_version: listVersion,
      added,
      removed,
    }, ts);
  }

  publishRuleFloor(floors, ts = this.clock()) {
    return this._publish('rule.floor.updated', { floors }, ts);
  }

  revokeCredential(jti, reason = '', ts = this.clock()) {
    const entry = this.issued.get(jti);
    if (!entry) throw new Error('只有签发方能够吊销凭证');
    return this._publish('credential.revoked', { jti, reason }, ts);
  }

  suspendWith(peerId, reason = '', ts = this.clock()) {
    return this._publish('relationship.suspended', { peer: peerId, reason }, ts);
  }

  resumeWith(peerId, ts = this.clock()) {
    return this._publish('relationship.resumed', { peer: peerId }, ts);
  }

  // ---- 跨境同步与离线恢复 ----
  syncTo(peer) {
    const since = peer.replicated.highWatermark(this.id);
    const envelopes = this.stream.exportSince(since);
    if (envelopes.length) peer.receiveSync(envelopes);
    // 同步后让对端学习到本机构全部历史公钥（含轮换后新钥），保证旧凭证仍可验。
    peer._trust(this);
    return envelopes.length;
  }

  receiveSync(envelopes) {
    return this.replicated.ingestMany(envelopes);
  }

  state() {
    return foldState(this.replicated.orderedRecords());
  }

  // ---- 接收方验签 ----
  verifyCredential(compact) {
    const { payload } = openEnvelope(compact, (p) => this.replicated.resolveKey(p.iss, p.kid));
    assertWellFormed(payload);
    this.seenCredentials.set(payload.jti, payload);
    return payload;
  }

  // ---- 质疑与补充核验（最小披露：只回应被质疑范围的证据摘要） ----
  challenge(peerId, compact, questions, ts = this.clock()) {
    const credential = this.verifyCredential(compact);
    const challenge = {
      typ: 'compliance-challenge/v1',
      challenge_id: `chl:${nonce(12)}`,
      iss: this.id,
      aud: credential.iss,
      jti: credential.jti,
      scopes: questions.scopes ?? credential.scopes,
      items: questions.items ?? [],
      iat: ts,
      kid: this.ring.currentKid,
    };
    return { challenge, compact: signPayload(challenge, this.ring.current.privateKey), peerId };
  }

  respondToChallenge(challengeEnvelope, { reveal = {}, ts = this.clock() } = {}) {
    const { payload: challenge } = openEnvelope(challengeEnvelope, (p) => this.replicated.resolveKey(p.iss, p.kid));
    if (challenge.typ !== 'compliance-challenge/v1' || challenge.aud !== this.id) {
      throw new Error('质疑请求不受支持或非发给本机构');
    }
    const entry = this.issued.get(challenge.jti);
    if (!entry) throw new Error('凭证并非由本机构签发');
    const asked = challenge.scopes ?? [];
    const outOfScope = asked.filter((s) => !entry.credential.scopes.includes(s));
    if (outOfScope.length) throw new Error(`质疑超出凭证审核范围：${outOfScope.join(',')}`);
    // 只返回被质疑范围的证据摘要；reveal 中的字段必须由签发方显式点名，绝不倾倒客户档案。
    const evidence = entry.credential.evidence.filter((e) => challenge.scopes.includes(e.scope));
    const response = {
      typ: 'compliance-supplement/v1',
      challenge_id: challenge.challenge_id,
      iss: this.id,
      aud: challenge.iss,
      jti: challenge.jti,
      evidence,
      reveal,
      iat: ts,
      kid: this.ring.currentKid,
    };
    return signPayload(response, this.ring.current.privateKey);
  }

  acceptSupplement(supplementEnvelope) {
    const { payload } = openEnvelope(supplementEnvelope, (p) => this.replicated.resolveKey(p.iss, p.kid));
    if (payload.typ !== 'compliance-supplement/v1' || payload.aud !== this.id) {
      throw new Error('补充证明不受支持或非发给本机构');
    }
    const known = this.seenCredentials.get(payload.jti);
    if (known && payload.evidence.some((e) => !known.scopes.includes(e.scope))) {
      throw new Error('补充证明超出凭证审核范围');
    }
    const list = this.supplements.get(payload.jti) ?? [];
    list.push(payload);
    this.supplements.set(payload.jti, list);
    return payload;
  }

  // 流头检查点：签发方对“当前事件流末端”的签名证明。
  // 付款前接收方核对水位与其一致，无法取得（签发方离线）或落后（恢复未完成）一律不放行。
  provideStreamHead(ts = this.clock()) {
    const last = this.stream.records[this.stream.records.length - 1];
    const head = {
      typ: 'stream-head/v1',
      iss: this.id,
      seq: last ? last.seq : 0,
      hash: last ? last.hash : null,
      iat: ts,
      kid: this.ring.currentKid,
    };
    return { head, compact: signPayload(head, this.ring.current.privateKey) };
  }

  // ---- 付款门禁：幂等、fail-closed，返回签名决策回执 ----
  requestPayment({
    credential: compact,
    order,
    streamHead: headEnvelope,
    maxHeadAgeSeconds = 120,
    idempotencyKey,
    localScreening = null,
    ts = this.clock(),
  }) {
    const credential = this.verifyCredential(compact);
    const boundOrder = {
      ...order,
      payer_pseudonym: order.payer_pseudonym ?? credential.sub,
    };
    const fp = orderFingerprint(boundOrder);
    const key = idempotencyKey ?? `pay:${credential.jti}:${fp}`;
    const cached = this.payments.get(key);
    // 重复请求：时区或重试造成的重复一律返回首次的一致结论，绝不二次放行。
    if (cached) return { ...cached, duplicate: true };

    const reasons = [];
    let head = null;
    if (!headEnvelope) {
      reasons.push({ code: 'stream_head_missing', detail: '未能取得签发方流头，无法确认吊销/名单已同步' });
    } else {
      try {
        const opened = openEnvelope(headEnvelope, (p) => this.replicated.resolveKey(p.iss, p.kid));
        head = opened.payload;
        if (head.typ !== 'stream-head/v1' || head.iss !== credential.iss) {
          reasons.push({ code: 'stream_head_invalid', detail: '流头与凭证签发方不一致' });
        } else {
          const watermark = this.replicated.highWatermark(head.iss);
          if (watermark !== head.seq) {
            reasons.push({ code: 'stream_behind', detail: `本地水位 ${watermark}，签发方流头 ${head.seq}，需先完成离线恢复` });
          } else if (ts - head.iat > maxHeadAgeSeconds) {
            reasons.push({ code: 'stream_head_stale', detail: `流头已过期 ${ts - head.iat}s` });
          }
        }
      } catch (err) {
        reasons.push({ code: 'stream_head_invalid', detail: err.message });
      }
    }

    const verdict = evaluatePayment({
      credential,
      signatureVerified: true,
      signerIssuer: credential.iss,
      selfId: this.id,
      expectedOrderFp: fp,
      order: boundOrder,
      now: ts,
      state: this.state(),
      localScreening,
      consumedOneTimeJtis: this.consumedOneTime,
    });
    reasons.push(...verdict.reasons);

    const decision = reasons.length ? 'block' : 'release';
    const receipt = {
      typ: 'payment-decision/v1',
      decision_key: key,
      decision,
      reasons,
      credential_jti: credential.jti,
      subject_pseudonym: credential.sub,
      issuer: credential.iss,
      order_fp: fp,
      evaluated_at: verdict.evaluated_at,
      rule_versions: verdict.rule_versions,
      scopes: verdict.scopes,
      issuer_stream_seq: head?.seq ?? null,
      stream_watermarks: Object.fromEntries(
        [...this.replicated.streams.entries()].map(([iss, bucket]) => [iss, bucket.size]),
      ),
    };
    receipt.receipt = signPayload(stripReceiptSig(receipt), this.ring.current.privateKey);
    this.payments.set(key, receipt);
    if (decision === 'release' && credential.restrictions.some((r) => r.type === 'one_time')) {
      this.consumedOneTime.add(credential.jti);
    }
    return { ...receipt, duplicate: false };
  }

  // ---- 审计：只汇总与该笔资金相关的凭证与事件，不泄露无关交易/客户信息 ----
  auditReport(idempotencyKey) {
    const receipt = this.payments.get(idempotencyKey);
    if (!receipt) throw new Error('找不到该付款决策');
    const { receipt: _, ...unsignedReceipt } = receipt;
    const relevant = [];
    for (const record of this.replicated.orderedRecords()) {
      if (this._eventRelates(record, receipt)) relevant.push(this._redact(record, receipt));
    }
    return {
      receipt: unsignedReceipt,
      explanation: explain(receipt.decision, receipt.reasons),
      relevant_events: relevant,
      supplements: this.supplements.get(receipt.credential_jti) ?? [],
    };
  }

  _eventRelates(record, receipt) {
    switch (record.kind) {
      case 'credential.revoked':
        return record.body.jti === receipt.credential_jti;
      case 'sanction.list.updated':
        return (record.body.added ?? []).some((e) => e.pseudonym === receipt.subject_pseudonym);
      case 'rule.floor.updated':
        return true; // 底线事件不含客户信息，且决定 release/block 的规则口径
      case 'relationship.suspended':
      case 'relationship.resumed':
        return record.body.peer === receipt.issuer;
      case 'key.rotated':
        return record.iss === receipt.issuer;
      default:
        return false;
    }
  }

  _redact(record, receipt) {
    if (record.kind !== 'sanction.list.updated') return record;
    return {
      ...record,
      body: {
        ...record.body,
        added: (record.body.added ?? []).filter((e) => e.pseudonym === receipt.subject_pseudonym),
        removed: (record.body.removed ?? []).filter((e) => e.pseudonym === receipt.subject_pseudonym),
      },
    };
  }
}

function stripReceiptSig(receipt) {
  const { receipt: _, ...unsigned } = receipt;
  return unsigned;
}

function explain(decision, reasons) {
  if (decision === 'release') {
    return '凭证验签通过、在有效期内、订单绑定一致、名单/吊销/暂停/规则底线/流新鲜度全部无命中，故放行。';
  }
  return `阻断依据：${reasons.map((r) => `${r.code}（${r.detail}）`).join('；')}。`;
}

export function digestOf(value) {
  return `sha256:${b64url(createHash('sha256').update(utf8(canonicalJSON(value))).digest())}`;
}
