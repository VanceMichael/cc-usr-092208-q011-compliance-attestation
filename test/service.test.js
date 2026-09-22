import test from 'node:test';
import assert from 'node:assert/strict';
import { InstitutionService } from '../src/service.js';
import { generateKeyPair } from '../src/crypto.js';
import { IdentifierRotator } from '../src/identifiers.js';

const START = Date.parse('2026-09-22T09:00:00Z');

function makeWorld() {
  let nowMs = START;
  const now = () => nowMs;
  const a = new InstitutionService({ institutionId: 'bank-cn', keyPair: generateKeyPair(), now });
  const b = new InstitutionService({ institutionId: 'bank-sg', keyPair: generateKeyPair(), now });
  a.registerPeer('bank-sg', b.keyPair.publicKeyPem);
  b.registerPeer('bank-cn', a.keyPair.publicKeyPem);
  const rotator = new IdentifierRotator({ pairId: 'bank-cn|bank-sg', secret: 'pair-secret' });
  return { a, b, rotator, advance: (ms) => { nowMs += ms; } };
}

function issueFull(a, { orderRef, orderDigest, subjectRef, scopes, restrictions = [], key = `req-${orderRef}` }) {
  return a.issueCredential({
    audience: 'bank-sg',
    subjectRef,
    orderRef,
    orderDigest,
    scopes: scopes ?? ['aml', 'trade_background', 'cross_border'],
    ruleSetVersion: 'aml-rules@2026-08',
    evidenceDigest: 'sha256:evidence-001',
    notBefore: '2026-09-22T08:00:00Z',
    notAfter: '2026-09-22T20:00:00Z',
    restrictions,
    idempotencyKey: key,
  });
}

function setupOrder(world) {
  const { a, b, rotator } = world;
  const orderRef = rotator.pseudonym('ORDER-LOCAL-1');
  const subjectRef = rotator.pseudonym('CUST-LOCAL-1');
  const orderDigest = 'sha256:order-v1';
  a.registerOrder(orderRef, orderDigest);
  b.registerOrder(orderRef, orderDigest);
  return { orderRef, subjectRef, orderDigest };
}

test('主流程：签发、同步、验签通过，付款门禁放行', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);
  const gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'RELEASE');
  assert.deepEqual(gate.reasons, []);
});

test('重复请求：同一幂等键返回原凭证，载荷不同即冲突', () => {
  const world = makeWorld();
  const { a } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  const first = issueFull(a, { orderRef, orderDigest, subjectRef });
  const second = issueFull(a, { orderRef, orderDigest, subjectRef });
  assert.equal(second.credential_id, first.credential_id);
  assert.equal([...a.events.values()].filter((e) => e.type === 'CREDENTIAL_ISSUED').length, 1);
  assert.throws(
    () => issueFull(a, { orderRef, orderDigest: 'sha256:order-v2', subjectRef }),
    /幂等键冲突/,
  );
});

test('凭证吊销与离线恢复：离线期阻断为同步过期，恢复后阻断为已吊销', () => {
  const world = makeWorld();
  const { a, b, advance } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  const credential = issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);
  assert.equal(b.gateDecision({ orderRef }).decision, 'RELEASE');

  a.revokeCredential(credential.credential_id, '名单命中');
  // 接收方离线，时钟推进超过同步时限：付款前不得凭旧状态放行
  advance(10 * 60 * 1000);
  let gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('SYNC_STALE')));

  // 恢复连线并同步后，双方得出一致的阻断结论
  b.syncFrom(a);
  gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('CREDENTIAL_REVOKED')));
});

test('离线期间收到对方新水位：即使未超时也按落后阻断', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  const credential = issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);
  a.revokeCredential(credential.credential_id, '名单命中');
  // 付款指令携带签发方当前事件水位，接收方发现自己落后
  b.noteAnnouncedHead('bank-cn', a.headSeq());
  const gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('SYNC_BEHIND')));
});

test('名单更新：旧名单纪元凭证失效，重新签发后放行', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);
  assert.equal(b.gateDecision({ orderRef }).decision, 'RELEASE');

  a.bumpListEpoch();
  b.syncFrom(a);
  let gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('LIST_STALE')));

  issueFull(a, { orderRef, orderDigest, subjectRef, key: 'req-rescreen' });
  b.syncFrom(a);
  gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'RELEASE');
});

test('订单变更：付款指令摘要不一致即阻断，签发方作废旧凭证', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);

  // 付款指令与凭证绑定的订单摘要不一致
  b.changeOrder(orderRef, 'sha256:order-v2');
  let gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('ORDER_SUPERSEDED') || r.startsWith('ORDER_CHANGED')));

  // 签发方侧订单变更后作废旧凭证，同步后接收方一致阻断
  const world2 = makeWorld();
  const order2 = setupOrder(world2);
  const cred2 = issueFull(world2.a, { orderRef: order2.orderRef, orderDigest: order2.orderDigest, subjectRef: order2.subjectRef });
  world2.b.syncFrom(world2.a);
  world2.a.changeOrder(order2.orderRef, 'sha256:order-v2');
  world2.b.syncFrom(world2.a);
  gate = world2.b.gateDecision({ orderRef: order2.orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('ORDER_SUPERSEDED')));
  assert.equal(world2.a.verifyCredential(cred2.credential_id).ok, false);
});

test('互认暂停：合规负责人暂停后阻断并停止签发，恢复后放行', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);

  b.pausePeer('bank-cn', 'compliance-officer-7');
  let gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('RELATIONSHIP_PAUSED')));

  // 暂停事件传播后，签发方也不得再向该机构签发
  a.syncFrom(b);
  assert.throws(() => issueFull(a, { orderRef, orderDigest, subjectRef, key: 'req-paused' }), /互认关系已暂停/);

  b.resumePeer('bank-cn', 'compliance-officer-7');
  a.syncFrom(b);
  gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'RELEASE');
});

test('质疑与补充核验：未决质疑阻断，补充核验完成后放行', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  const credential = issueFull(a, { orderRef, orderDigest, subjectRef });
  b.syncFrom(a);

  const challengeId = b.openChallenge(credential.credential_id, '贸易背景存疑');
  assert.equal(b.openChallenge(credential.credential_id, '贸易背景存疑'), challengeId);
  let gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('CHALLENGE_OPEN')));

  // 签发方得知质疑，完成补充核验并应答，接收方同步后重新评估
  a.syncFrom(b);
  a.respondChallenge(challengeId, 'sha256:supplementary-evidence');
  b.syncFrom(a);
  gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'RELEASE');
});

test('限制条件：超限额或缺少评估上下文即阻断', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  issueFull(a, { orderRef, orderDigest, subjectRef, restrictions: ['amount<=50000', 'corridor=CN>SG'] });
  b.syncFrom(a);

  let gate = b.gateDecision({ orderRef, context: { amount: 60000, corridor: 'CN>SG' } });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('RESTRICTION_VIOLATED')));

  gate = b.gateDecision({ orderRef, context: { amount: 50000 } });
  assert.equal(gate.decision, 'BLOCK');

  gate = b.gateDecision({ orderRef, context: { amount: 50000, corridor: 'CN>SG' } });
  assert.equal(gate.decision, 'RELEASE');
});

test('审核范围：覆盖不全即阻断', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  issueFull(a, { orderRef, orderDigest, subjectRef, scopes: ['aml'] });
  b.syncFrom(a);
  const gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.includes('SCOPE_MISSING:trade_background'));
  assert.ok(gate.reasons.includes('SCOPE_MISSING:cross_border'));
});

test('验签：凭证被篡改后门禁阻断', () => {
  const world = makeWorld();
  const { a, b } = world;
  const { orderRef, subjectRef, orderDigest } = setupOrder(world);
  const credential = issueFull(a, { orderRef, orderDigest, subjectRef });
  b.receiveCredential({ ...credential, evidence_digest: 'sha256:tampered' });
  const gate = b.gateDecision({ orderRef });
  assert.equal(gate.decision, 'BLOCK');
  assert.ok(gate.reasons.some((r) => r.startsWith('SIGNATURE_INVALID')));
});
