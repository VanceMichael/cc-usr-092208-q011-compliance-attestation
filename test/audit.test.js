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
  return { a, b, rotator };
}

function issueFull(a, { orderRef, orderDigest, subjectRef, key }) {
  return a.issueCredential({
    audience: 'bank-sg',
    subjectRef,
    orderRef,
    orderDigest,
    scopes: ['aml', 'trade_background', 'cross_border'],
    ruleSetVersion: 'aml-rules@2026-08',
    evidenceDigest: 'sha256:evidence-001',
    notBefore: '2026-09-22T08:00:00Z',
    notAfter: '2026-09-22T20:00:00Z',
    idempotencyKey: key,
  });
}

test('审计留痕：放行与阻断都可还原原因，且按订单隔离', () => {
  const { a, b, rotator } = makeWorld();
  const orderRef1 = rotator.pseudonym('ORDER-LOCAL-1');
  const orderRef2 = rotator.pseudonym('ORDER-LOCAL-2');
  const subjectRef = rotator.pseudonym('CUST-LOCAL-1');
  a.registerOrder(orderRef1, 'sha256:order-1');
  b.registerOrder(orderRef1, 'sha256:order-1');
  a.registerOrder(orderRef2, 'sha256:order-2');
  b.registerOrder(orderRef2, 'sha256:order-2');
  issueFull(a, { orderRef: orderRef1, orderDigest: 'sha256:order-1', subjectRef, key: 'req-1' });
  const cred2 = issueFull(a, { orderRef: orderRef2, orderDigest: 'sha256:order-2', subjectRef, key: 'req-2' });
  b.syncFrom(a);

  assert.equal(b.gateDecision({ orderRef: orderRef1 }).decision, 'RELEASE');
  a.revokeCredential(cred2.credential_id, '名单命中');
  b.syncFrom(a);
  assert.equal(b.gateDecision({ orderRef: orderRef2 }).decision, 'BLOCK');

  const trail1 = b.auditTrail(orderRef1);
  const trail2 = b.auditTrail(orderRef2);
  assert.equal(trail1.length, 1);
  assert.equal(trail1[0].decision, 'RELEASE');
  assert.deepEqual(trail1[0].reasons, []);
  assert.equal(trail2.length, 1);
  assert.equal(trail2[0].decision, 'BLOCK');
  assert.ok(trail2[0].reasons.some((r) => r.startsWith('CREDENTIAL_REVOKED')));
  assert.ok(trail2[0].credential_ids.includes(cred2.credential_id));
  assert.ok(trail1.every((r) => r.order_ref === orderRef1));
  assert.ok(trail2.every((r) => r.order_ref === orderRef2));
});

test('最小披露：跨机构交换与审计记录不含原始身份与订单明文', () => {
  const { a, b, rotator } = makeWorld();
  const orderRef = rotator.pseudonym('ORDER-LOCAL-9');
  const subjectRef = rotator.pseudonym('CUST-LOCAL-9 张三');
  a.registerOrder(orderRef, 'sha256:order-9');
  b.registerOrder(orderRef, 'sha256:order-9');
  issueFull(a, { orderRef, orderDigest: 'sha256:order-9', subjectRef, key: 'req-9' });
  b.syncFrom(a);
  b.gateDecision({ orderRef });

  // 跨机构链路上流动的内容：签发方事件、接收方凭证库与审计记录
  const exchanged = JSON.stringify({
    wire: [...a.events.values()],
    stored: [...b.credentials.values()],
    audit: b.auditRecords,
  });
  assert.ok(!exchanged.includes('CUST-LOCAL-9'));
  assert.ok(!exchanged.includes('张三'));
  assert.ok(!exchanged.includes('ORDER-LOCAL-9'));
  assert.ok(exchanged.includes(subjectRef));
});
