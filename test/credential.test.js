import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { buildCredentialBody, signCredential, verifyCredentialSignature } from '../src/credential.js';
import { generateKeyPair } from '../src/crypto.js';
import { IdentifierRotator } from '../src/identifiers.js';
import { toUtcMillis, toIsoUtc } from '../src/time.js';
import { checkRestrictions } from '../src/restrictions.js';

const BASE_PARAMS = {
  issuer: 'bank-cn',
  audience: 'bank-sg',
  subjectRef: 'ps_000000000000000000000001',
  orderRef: 'ps_000000000000000000000002',
  orderDigest: 'sha256:order-v1',
  scopes: ['aml', 'trade_background', 'cross_border'],
  ruleSetVersion: 'aml-rules@2026-08',
  listEpoch: 1,
  evidenceDigest: 'sha256:evidence-001',
  notBefore: '2026-09-22T08:00:00Z',
  notAfter: '2026-09-22T20:00:00Z',
  idempotencyKey: 'req-001',
  issuerHead: 1,
};

test('签发与验签：签名覆盖全部字段，篡改即失效', () => {
  const keys = generateKeyPair();
  const credential = signCredential(buildCredentialBody(BASE_PARAMS), keys.privateKeyPem);
  assert.equal(verifyCredentialSignature(credential, keys.publicKeyPem), true);
  const tampered = { ...credential, evidence_digest: 'sha256:evil' };
  assert.equal(verifyCredentialSignature(tampered, keys.publicKeyPem), false);
});

test('时区差异：带偏移时间归一化为 UTC，双方算出同一时刻', () => {
  assert.equal(toUtcMillis('2026-09-22T17:00:00+08:00'), toUtcMillis('2026-09-22T09:00:00Z'));
  const body = buildCredentialBody({ ...BASE_PARAMS, notBefore: '2026-09-22T17:00:00+08:00' });
  assert.equal(body.not_before, '2026-09-22T09:00:00.000Z');
  assert.equal(toIsoUtc(toUtcMillis(body.not_after)), body.not_after);
  assert.throws(() => toUtcMillis('2026-09-22 09:00:00'), /时区/);
  assert.throws(() => buildCredentialBody({ ...BASE_PARAMS, notAfter: '2026-09-22T08:00:00Z' }), /有效期/);
});

test('可轮换标识：同纪元稳定，轮换或换机构对即变化', () => {
  const rotator = new IdentifierRotator({ pairId: 'bank-cn|bank-sg', secret: 'pair-secret' });
  const first = rotator.pseudonym('CUST-LOCAL-1');
  assert.equal(rotator.pseudonym('CUST-LOCAL-1'), first);
  rotator.rotate();
  assert.notEqual(rotator.pseudonym('CUST-LOCAL-1'), first);
  const otherPair = new IdentifierRotator({ pairId: 'bank-cn|bank-hk', secret: 'pair-secret' });
  assert.notEqual(otherPair.pseudonym('CUST-LOCAL-1'), first);
});

test('限制条件：数值比较、等值匹配与缺失上下文', () => {
  const restrictions = ['amount<=50000', 'corridor=CN>SG'];
  assert.deepEqual(checkRestrictions(restrictions, { amount: 50000, corridor: 'CN>SG' }), []);
  assert.equal(checkRestrictions(restrictions, { amount: 50001, corridor: 'CN>SG' }).length, 1);
  assert.equal(checkRestrictions(restrictions, { amount: 100, corridor: 'CN>HK' }).length, 1);
  assert.equal(checkRestrictions(restrictions, { amount: 100 }).length, 1);
});

test('凭证符合共享契约的必填字段与格式', async () => {
  const schema = JSON.parse(await readFile(new URL('../contracts/credential.schema.json', import.meta.url), 'utf8'));
  const keys = generateKeyPair();
  const credential = signCredential(buildCredentialBody(BASE_PARAMS), keys.privateKeyPem);
  for (const key of schema.required) assert.ok(key in credential, `缺少字段 ${key}`);
  assert.match(credential.credential_id, new RegExp(schema.properties.credential_id.pattern));
  assert.match(credential.subject_ref, new RegExp(schema.properties.subject_ref.pattern));
});
