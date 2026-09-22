import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCredential, evidenceDigest } from '../src/lib/attestation.js';
import { foldState, evaluatePayment, compareVersions } from '../src/lib/state.js';

const T = 1_758_500_000; // 固定 UTC 纪元秒，与任何本地时区无关

function credential(overrides = {}) {
  return buildCredential({
    jti: 'jti:t1',
    issuer: 'bank-cn',
    audience: 'bank-sg',
    subjectPseudonym: 'pn:1:abc',
    orderFingerprint: 'ofp:order1',
    scopes: ['aml', 'trade', 'crossborder'],
    ruleVersions: { aml: '2.1', trade: '1.4', crossborder: '3.0' },
    evidence: [
      { scope: 'aml', digest: 'ev:a', ruleVersion: '2.1' },
      { scope: 'trade', digest: 'ev:t', ruleVersion: '1.4' },
      { scope: 'crossborder', digest: 'ev:c', ruleVersion: '3.0' },
    ],
    issuedAt: T,
    expiresAt: T + 3600,
    restrictions: [],
    kid: 'k1',
    ...overrides,
  });
}

const baseArgs = (cred, state, overrides = {}) => ({
  credential: cred,
  signatureVerified: true,
  signerIssuer: 'bank-cn',
  selfId: 'bank-sg',
  expectedOrderFp: 'ofp:order1',
  order: { currency: 'USD', amount: '1000.00' },
  now: T + 10,
  state,
  ...overrides,
});

test('完整有效凭证放行', () => {
  const verdict = evaluatePayment(baseArgs(credential(), foldState([])));
  assert.equal(verdict.decision, 'release');
  assert.deepEqual(verdict.reasons, []);
});

test('签名无效直接阻断', () => {
  const verdict = evaluatePayment(baseArgs(credential(), foldState([]), { signatureVerified: false }));
  assert.equal(verdict.decision, 'block');
  assert.ok(verdict.reasons.some((r) => r.code === 'bad_signature'));
});

test('不能凭本机构自签凭证放行', () => {
  const verdict = evaluatePayment(baseArgs(credential(), foldState([]), { selfId: 'bank-cn' }));
  assert.ok(verdict.reasons.some((r) => r.code === 'self_issued'));
});

test('受众不符阻断', () => {
  const verdict = evaluatePayment(baseArgs(credential({ audience: 'bank-eu' }), foldState([])));
  assert.ok(verdict.reasons.some((r) => r.code === 'audience_mismatch'));
});

test('未生效与已过期均阻断（边界：exp 时刻即失效）', () => {
  const early = evaluatePayment(baseArgs(credential(), foldState([]), { now: T - 1 }));
  assert.ok(early.reasons.some((r) => r.code === 'not_yet_valid'));
  const expired = evaluatePayment(baseArgs(credential(), foldState([]), { now: T + 3600 }));
  assert.ok(expired.reasons.some((r) => r.code === 'expired'));
});

test('订单指纹不一致阻断（订单要素变更）', () => {
  const verdict = evaluatePayment(baseArgs(credential(), foldState([]), { expectedOrderFp: 'ofp:changed' }));
  assert.ok(verdict.reasons.some((r) => r.code === 'order_mismatch'));
});

test('凭证吊销阻断', () => {
  const state = foldState([
    { kind: 'credential.revoked', iss: 'bank-cn', ts: T + 5, body: { jti: 'jti:t1', reason: '客户涉诉' } },
  ]);
  const verdict = evaluatePayment(baseArgs(credential(), state));
  assert.ok(verdict.reasons.some((r) => r.code === 'credential_revoked'));
});

test('名单命中阻断，且记录名单版本与条目', () => {
  const state = foldState([
    { kind: 'sanction.list.updated', iss: 'bank-sg', ts: T, body: { list_version: 'L/42', added: [{ pseudonym: 'pn:1:abc', entry_id: 'UN-2001' }] } },
  ]);
  const verdict = evaluatePayment(baseArgs(credential(), state));
  const hit = verdict.reasons.find((r) => r.code === 'sanctions_hit');
  assert.ok(hit);
  assert.match(hit.detail, /L\/42/);
  assert.match(hit.detail, /UN-2001/);
});

test('名单移除后不再命中', () => {
  const state = foldState([
    { kind: 'sanction.list.updated', iss: 'bank-sg', ts: T, body: { list_version: 1, added: [{ pseudonym: 'pn:1:abc', entry_id: 'x' }] } },
    { kind: 'sanction.list.updated', iss: 'bank-sg', ts: T + 1, body: { list_version: 2, removed: [{ pseudonym: 'pn:1:abc' }] } },
  ]);
  assert.equal(evaluatePayment(baseArgs(credential(), state)).decision, 'release');
});

test('互认关系暂停阻断，恢复后放行（任一方宣布均生效）', () => {
  const suspended = foldState([
    { kind: 'relationship.suspended', iss: 'bank-cn', ts: T, body: { peer: 'bank-sg' } },
  ]);
  assert.ok(evaluatePayment(baseArgs(credential(), suspended)).reasons.some((r) => r.code === 'relationship_suspended'));
  const resumed = foldState([
    { kind: 'relationship.suspended', iss: 'bank-cn', ts: T, body: { peer: 'bank-sg' } },
    { kind: 'relationship.resumed', iss: 'bank-cn', ts: T + 2, body: { peer: 'bank-sg' } },
  ]);
  assert.equal(evaluatePayment(baseArgs(credential(), resumed)).decision, 'release');
});

test('缺少审核范围阻断', () => {
  const verdict = evaluatePayment(baseArgs(credential({
    scopes: ['aml'],
    ruleVersions: { aml: '2.1' },
    evidence: [{ scope: 'aml', digest: 'ev:a', ruleVersion: '2.1' }],
  }), foldState([])));
  assert.ok(verdict.reasons.some((r) => r.code === 'scope_missing'));
});

test('规则版本低于跨机构底线阻断；底线取多方最高值', () => {
  const state = foldState([
    { kind: 'rule.floor.updated', iss: 'bank-sg', ts: T, body: { floors: { aml: '2.0' } } },
    { kind: 'rule.floor.updated', iss: 'bank-cn', ts: T, body: { floors: { aml: '2.2' } } },
  ]);
  assert.equal(state.ruleFloors.aml, '2.2');
  const verdict = evaluatePayment(baseArgs(credential(), state));
  assert.ok(verdict.reasons.some((r) => r.code === 'rule_outdated'));
});

test('金额、币种限制与无法识别的限制按最严格处理', () => {
  const over = evaluatePayment(baseArgs(credential({ restrictions: [{ type: 'max_amount', currency: 'USD', amount: '500' }] }), foldState([])));
  assert.ok(over.reasons.some((r) => r.code === 'restriction_violation'));
  const badCurrency = evaluatePayment(baseArgs(credential({ restrictions: [{ type: 'currency_in', currencies: ['EUR'] }] }), foldState([])));
  assert.ok(badCurrency.reasons.some((r) => r.code === 'restriction_violation'));
  const unknown = evaluatePayment(baseArgs(credential({ restrictions: [{ type: 'future_policy' }] }), foldState([])));
  assert.ok(unknown.reasons.some((r) => r.code === 'restriction_unknown'));
});

test('一次性凭证第二次使用阻断', () => {
  const cred = credential({ restrictions: [{ type: 'one_time' }] });
  const consumed = new Set(['jti:t1']);
  assert.ok(evaluatePayment(baseArgs(cred, foldState([]), { consumedOneTimeJtis: consumed }))
    .reasons.some((r) => r.code === 'restriction_violation'));
});

test('本地复核失败即使互认凭证有效也阻断', () => {
  const verdict = evaluatePayment(baseArgs(credential(), foldState([]), {
    localScreening: { passed: false, hits: ['本地补充名单 LOC-7'] },
  }));
  assert.ok(verdict.reasons.some((r) => r.code === 'local_screening_failed'));
});

test('多原因同时存在时全部列出，fail closed', () => {
  const state = foldState([
    { kind: 'credential.revoked', iss: 'bank-cn', ts: T, body: { jti: 'jti:t1' } },
    { kind: 'relationship.suspended', iss: 'bank-cn', ts: T, body: { peer: 'bank-sg' } },
  ]);
  const verdict = evaluatePayment(baseArgs(credential({ audience: 'bank-eu' }), state, { now: T + 10_000 }));
  const codes = verdict.reasons.map((r) => r.code);
  assert.deepEqual(new Set(codes), new Set(['audience_mismatch', 'credential_revoked', 'relationship_suspended', 'expired']));
});

test('版本号比较', () => {
  assert.equal(compareVersions('2.10', '2.9') > 0, true);
  assert.equal(compareVersions('3.0', '3.0'), 0);
});

test('证据摘要不含原始材料且随内容变化', () => {
  const a = evidenceDigest('aml', '2.1', { hits: [], officer: '张' });
  const b = evidenceDigest('aml', '2.1', { hits: ['X'], officer: '张' });
  assert.notEqual(a, b);
  assert.ok(a.startsWith('ev:aml:'));
});
