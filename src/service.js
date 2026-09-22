import { buildCredentialBody, signCredential, verifyCredentialSignature, REQUIRED_SCOPES } from './credential.js';
import { canonicalize, sha256Hex } from './crypto.js';
import { toIsoUtc } from './time.js';
import { checkRestrictions } from './restrictions.js';

// 机构侧互认服务参考实现：签发、验签、质疑、吊销、暂停、同步与付款门禁。
// 原始客户档案与订单明细留在本机构，跨机构链路只交换凭证与事件这类最小证明。
// 付款门禁在任何不确定情形下一律阻断，恢复一致后才放行。
export class InstitutionService {
  constructor({ institutionId, keyPair, now = () => Date.now(), maxSyncAgeMs = 5 * 60 * 1000 }) {
    if (!institutionId) throw new Error('缺少机构标识');
    if (!keyPair?.publicKeyPem || !keyPair?.privateKeyPem) throw new Error('缺少机构密钥对');
    this.id = institutionId;
    this.keyPair = keyPair;
    this.now = now;
    this.maxSyncAgeMs = maxSyncAgeMs;
    this.events = new Map(); // seq -> 事件，只增不改
    this.credentials = new Map(); // credential_id -> { credential, status }
    this.idempotencyKeys = new Map(); // 幂等键 -> { payloadDigest, credentialId }
    this.peers = new Map(); // 机构标识 -> { publicKeyPem, active, appliedSeq, announcedSeq, lastSyncAtMs }
    this.challenges = new Map(); // 质疑标识 -> { challengeId, credentialId, orderRef, reason, status }
    this.orders = new Map(); // 订单伪名 -> { digest, version }
    this.listEpoch = 1; // 共享名单纪元，名单更新即递增
    this.auditRecords = [];
  }

  headSeq() {
    return this.events.size;
  }

  // ---- 互认关系：合规负责人可暂停与恢复 ----

  registerPeer(peerId, publicKeyPem) {
    this.peers.set(peerId, { publicKeyPem, active: true, appliedSeq: 0, announcedSeq: 0, lastSyncAtMs: null });
  }

  pausePeer(peerId, actor) {
    const peer = this.#peer(peerId);
    peer.active = false;
    this.#emit('RELATIONSHIP_PAUSED', { peer: peerId, actor });
  }

  resumePeer(peerId, actor) {
    const peer = this.#peer(peerId);
    peer.active = true;
    this.#emit('RELATIONSHIP_RESUMED', { peer: peerId, actor });
  }

  // ---- 名单与订单 ----

  bumpListEpoch() {
    this.listEpoch += 1;
    this.#emit('LIST_UPDATED', { list_epoch: this.listEpoch });
  }

  registerOrder(orderRef, orderDigest) {
    this.orders.set(orderRef, { digest: orderDigest, version: 1 });
  }

  changeOrder(orderRef, newDigest) {
    const order = this.orders.get(orderRef);
    if (!order) throw new Error(`未知订单:${orderRef}`);
    if (order.digest === newDigest) return;
    order.digest = newDigest;
    order.version += 1;
    for (const record of this.credentials.values()) {
      if (record.credential?.order_ref === orderRef && record.status === 'active') record.status = 'superseded';
    }
    this.#emit('ORDER_SUPERSEDED', { order_ref: orderRef, order_version: order.version });
  }

  // ---- 凭证签发：同一幂等键重复请求返回原凭证，载荷不同即冲突 ----

  issueCredential(params) {
    const peer = this.#peer(params.audience);
    if (!peer.active) throw new Error(`互认关系已暂停:${params.audience}`);
    const payloadDigest = sha256Hex(canonicalize({ ...params, issuer: this.id }));
    const existing = this.idempotencyKeys.get(params.idempotencyKey);
    if (existing) {
      if (existing.payloadDigest !== payloadDigest) throw new Error(`幂等键冲突:${params.idempotencyKey}`);
      return this.credentials.get(existing.credentialId).credential;
    }
    const body = buildCredentialBody({
      ...params,
      issuer: this.id,
      listEpoch: this.listEpoch,
      issuerHead: this.headSeq() + 1,
    });
    const credential = signCredential(body, this.keyPair.privateKeyPem);
    this.credentials.set(credential.credential_id, { credential, status: 'active' });
    this.idempotencyKeys.set(params.idempotencyKey, { payloadDigest, credentialId: credential.credential_id });
    this.#emit('CREDENTIAL_ISSUED', { credential });
    return credential;
  }

  revokeCredential(credentialId, reason) {
    const record = this.credentials.get(credentialId);
    if (!record || record.credential?.issuer !== this.id) throw new Error(`只能吊销本机构签发的凭证:${credentialId}`);
    if (record.status !== 'active') return; // 重复吊销幂等
    record.status = 'revoked';
    this.#emit('CREDENTIAL_REVOKED', { credential_id: credentialId, reason });
  }

  // ---- 接收与验签 ----

  receiveCredential(credential) {
    const existing = this.credentials.get(credential.credential_id);
    if (existing) {
      if (!existing.credential) existing.credential = credential; // 吊销先到的墓碑补全凭证体
    } else {
      this.credentials.set(credential.credential_id, { credential, status: 'active' });
    }
    const peer = this.peers.get(credential.issuer);
    if (peer && credential.issuer_head > peer.announcedSeq) peer.announcedSeq = credential.issuer_head;
  }

  verifyCredential(credentialId, atMs = this.now()) {
    const record = this.credentials.get(credentialId);
    if (!record) return { ok: false, reasons: ['CREDENTIAL_UNKNOWN'] };
    if (!record.credential) {
      return { ok: false, reasons: [record.status === 'revoked' ? 'CREDENTIAL_REVOKED' : 'CREDENTIAL_UNKNOWN'] };
    }
    const { credential } = record;
    const isSelf = credential.issuer === this.id;
    const peer = isSelf ? null : this.peers.get(credential.issuer);
    if (!isSelf && !peer) return { ok: false, reasons: ['ISSUER_UNTRUSTED'] };
    const reasons = [];
    const publicKeyPem = isSelf ? this.keyPair.publicKeyPem : peer.publicKeyPem;
    if (!verifyCredentialSignature(credential, publicKeyPem)) reasons.push('SIGNATURE_INVALID');
    if (peer && !peer.active) reasons.push('RELATIONSHIP_PAUSED');
    if (record.status === 'revoked') reasons.push('CREDENTIAL_REVOKED');
    if (record.status === 'superseded') reasons.push('ORDER_SUPERSEDED');
    if (atMs < Date.parse(credential.not_before)) reasons.push('WINDOW_NOT_YET_VALID');
    if (atMs >= Date.parse(credential.not_after)) reasons.push('WINDOW_EXPIRED');
    if (credential.list_epoch < this.listEpoch) reasons.push('LIST_STALE');
    if (this.#hasOpenChallenge(credentialId)) reasons.push('CHALLENGE_OPEN');
    return { ok: reasons.length === 0, reasons };
  }

  // ---- 质疑与补充核验 ----

  openChallenge(credentialId, reason) {
    const record = this.credentials.get(credentialId);
    if (!record?.credential) throw new Error(`未知凭证:${credentialId}`);
    const existing = [...this.challenges.values()].find((c) => c.credentialId === credentialId && c.status === 'open');
    if (existing) return existing.challengeId; // 重复质疑幂等
    const challengeId = `chg_${sha256Hex(`${this.id}|${credentialId}|${reason}`).slice(0, 16)}`;
    this.challenges.set(challengeId, {
      challengeId,
      credentialId,
      orderRef: record.credential.order_ref,
      reason,
      status: 'open',
    });
    this.#emit('CHALLENGE_OPENED', { challenge_id: challengeId, credential_id: credentialId, reason });
    return challengeId;
  }

  respondChallenge(challengeId, responseDigest) {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new Error(`未知质疑:${challengeId}`);
    if (challenge.status !== 'open') return;
    challenge.status = 'resolved';
    challenge.responseDigest = responseDigest;
    this.#emit('CHALLENGE_RESOLVED', { challenge_id: challengeId, response_digest: responseDigest });
  }

  // ---- 事件同步与离线恢复 ----

  // 付款指令等报文可携带签发方当前事件水位，接收方据此发现自己落后。
  noteAnnouncedHead(peerId, head) {
    const peer = this.#peer(peerId);
    peer.announcedSeq = Math.max(peer.announcedSeq, head);
  }

  syncFrom(peerService) {
    const peer = this.#peer(peerService.id);
    for (const event of peerService.events.values()) {
      if (event.seq <= peer.appliedSeq) continue;
      this.#apply(event, peerService.id);
      peer.appliedSeq = event.seq;
    }
    peer.announcedSeq = peerService.headSeq();
    peer.lastSyncAtMs = this.now();
  }

  // ---- 付款门禁：任何一项不满足即阻断，并留下可审计的原因 ----

  gateDecision({ orderRef, requiredScopes = REQUIRED_SCOPES, context = {} }) {
    const atMs = this.now();
    const reasons = [];
    const records = [...this.credentials.values()].filter((r) => r.credential && r.credential.order_ref === orderRef);
    const usable = [];
    const failures = [];
    const involvedIssuers = new Set();

    for (const record of records) {
      const { credential } = record;
      if (credential.issuer !== this.id) involvedIssuers.add(credential.issuer);
      const verdict = this.verifyCredential(credential.credential_id, atMs);
      if (verdict.ok) usable.push(credential);
      else failures.push({ id: credential.credential_id, reasons: verdict.reasons });
    }

    // 审核范围必须被可用凭证完整覆盖；覆盖不全时附上失败原因解释
    const covered = new Set(usable.flatMap((c) => c.scopes));
    const missing = requiredScopes.filter((scope) => !covered.has(scope));
    for (const scope of missing) reasons.push(`SCOPE_MISSING:${scope}`);
    if (missing.length > 0) {
      for (const failure of failures) {
        for (const reason of failure.reasons) reasons.push(`${reason}:${failure.id}`);
      }
    }

    // 同步新鲜度：离线过久或落后于签发方已公布水位时，付款前不得放行
    for (const issuerId of involvedIssuers) {
      const peer = this.peers.get(issuerId);
      if (!peer) {
        reasons.push(`ISSUER_UNTRUSTED:${issuerId}`);
        continue;
      }
      if (!peer.lastSyncAtMs || atMs - peer.lastSyncAtMs > this.maxSyncAgeMs) reasons.push(`SYNC_STALE:${issuerId}`);
      if (peer.appliedSeq < peer.announcedSeq) reasons.push(`SYNC_BEHIND:${issuerId}`);
    }

    // 订单一致性：凭证绑定的订单摘要必须与付款指令当前摘要一致
    const order = this.orders.get(orderRef);
    if (order) {
      for (const credential of usable) {
        if (credential.order_digest !== order.digest) reasons.push(`ORDER_CHANGED:${credential.credential_id}`);
      }
    }

    // 限制条件逐条评估，评估上下文缺失视为不满足
    for (const credential of usable) {
      for (const violation of checkRestrictions(credential.restrictions, context)) {
        reasons.push(`RESTRICTION_VIOLATED:${credential.credential_id}:${violation}`);
      }
    }

    const uniqueReasons = [...new Set(reasons)];
    const decision = uniqueReasons.length === 0 ? 'RELEASE' : 'BLOCK';
    const auditId = `aud_${sha256Hex(`${this.id}|${orderRef}|${atMs}|${this.auditRecords.length}`).slice(0, 16)}`;
    this.auditRecords.push({
      audit_id: auditId,
      at: toIsoUtc(atMs),
      order_ref: orderRef,
      credential_ids: records.map((r) => r.credential.credential_id),
      decision,
      reasons: uniqueReasons,
      list_epoch: this.listEpoch,
      sync: Object.fromEntries([...involvedIssuers].map((issuerId) => {
        const peer = this.peers.get(issuerId);
        return [issuerId, { applied: peer?.appliedSeq ?? 0, announced: peer?.announcedSeq ?? 0 }];
      })),
    });
    return { decision, reasons: uniqueReasons, auditId };
  }

  // 审计只按订单伪名检索本笔记录，不暴露其他交易。
  auditTrail(orderRef) {
    return this.auditRecords.filter((record) => record.order_ref === orderRef);
  }

  #peer(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer) throw new Error(`未知互认机构:${peerId}`);
    return peer;
  }

  #emit(type, payload) {
    const seq = this.events.size + 1;
    this.events.set(seq, { seq, type, at: toIsoUtc(this.now()), payload });
  }

  #hasOpenChallenge(credentialId) {
    return [...this.challenges.values()].some((c) => c.credentialId === credentialId && c.status === 'open');
  }

  #apply(event, fromPeer) {
    const payload = event.payload;
    switch (event.type) {
      case 'CREDENTIAL_ISSUED':
        this.receiveCredential(payload.credential);
        break;
      case 'CREDENTIAL_REVOKED': {
        const record = this.credentials.get(payload.credential_id);
        if (record) record.status = 'revoked';
        else this.credentials.set(payload.credential_id, { credential: null, status: 'revoked' });
        break;
      }
      case 'ORDER_SUPERSEDED':
        for (const record of this.credentials.values()) {
          if (record.credential?.order_ref === payload.order_ref && record.status === 'active') record.status = 'superseded';
        }
        break;
      case 'LIST_UPDATED':
        this.listEpoch = Math.max(this.listEpoch, payload.list_epoch);
        break;
      case 'CHALLENGE_OPENED':
        if (!this.challenges.has(payload.challenge_id)) {
          const record = this.credentials.get(payload.credential_id);
          this.challenges.set(payload.challenge_id, {
            challengeId: payload.challenge_id,
            credentialId: payload.credential_id,
            orderRef: record?.credential?.order_ref ?? null,
            reason: payload.reason,
            status: 'open',
          });
        }
        break;
      case 'CHALLENGE_RESOLVED': {
        const challenge = this.challenges.get(payload.challenge_id);
        if (challenge) {
          challenge.status = 'resolved';
          challenge.responseDigest = payload.response_digest;
        }
        break;
      }
      case 'RELATIONSHIP_PAUSED': {
        const peer = this.peers.get(fromPeer);
        if (peer) peer.active = false;
        break;
      }
      case 'RELATIONSHIP_RESUMED': {
        const peer = this.peers.get(fromPeer);
        if (peer) peer.active = true;
        break;
      }
      default:
        break;
    }
  }
}
