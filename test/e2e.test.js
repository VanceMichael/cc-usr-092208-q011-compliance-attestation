import test from 'node:test';
import assert from 'node:assert/strict';
import { Institution, orderFingerprint } from '../src/lib/node.js';

// 可注入时钟；测试中全部使用 UTC 纪元秒，时区差异只体现在人类展示层。
function pair() {
  let t = 1_758_500_000;
  const clock = () => t;
  const A = new Institution('bank-cn', { clock });
  const B = new Institution('bank-sg', { clock });
  A.bootstrapWith(B);
  A.setRotationSecret('bank-sg', 1, 'hmac-secret-cn-epoch1');
  A.noteSubject('cust-1', { name: '完整客户档案仅存境内行', docs: ['合同.pdf', '发票.pdf'] });
  return { A, B, advance: (s) => { t += s; } };
}

function issue(A, B, overrides = {}) {
  const subjectId = overrides.subjectId ?? 'cust-1';
  const pn = A.pseudonymFor(subjectId, 'bank-sg');
  const order = {
    order_id: 'PO-2026-0007',
    currency: 'USD',
    amount: '12500.00',
    payer_pseudonym: pn,
    payee_pseudonym: 'pn:payee:overseas-merchant',
    trade_digest: 'sha256:trade-docs-bundle',
    ...overrides.order,
  };
  const issued = A.issueCredential({
    subjectId,
    peerId: 'bank-sg',
    order,
    scopes: ['aml', 'trade', 'crossborder'],
    ruleVersions: { aml: '2.1', trade: '1.4', crossborder: '3.0' },
    findings: { aml: { hits: [] }, trade: { doc_count: 4 }, crossborder: { license: 'LIC-9' } },
    ttlSeconds: 7200,
    ...overrides.credential,
  });
  A.syncTo(B);
  return { ...issued, head: A.provideStreamHead().compact };
}

test('端到端：最小证明跨境放行，凭证中不含真实姓名与原始材料', () => {
  const { A, B } = pair();
  const { compact, order, head } = issue(A, B);
  const decision = B.requestPayment({ credential: compact, order, streamHead: head });
  assert.equal(decision.decision, 'release');
  assert.equal(compact.includes('完整客户档案仅存境内行'), false);
  assert.equal(compact.includes('合同.pdf'), false);
  assert.equal(compact.includes('cust-1'), false);
});

test('可轮换假名：周期切换后新旧假名不同，链路上无法关联', () => {
  const { A } = pair();
  const pn1 = A.pseudonymFor('cust-1', 'bank-sg', 1);
  A.advanceEpoch('bank-sg', 2, 'hmac-secret-cn-epoch2');
  const pn2 = A.pseudonymFor('cust-1', 'bank-sg', 2);
  assert.notEqual(pn1, pn2);
  // 同周期同客户同对端稳定复用
  assert.equal(A.pseudonymFor('cust-1', 'bank-sg', 1), pn1);
  // 不同对端得到不同假名
  assert.notEqual(issuePseudonymOtherPeer(A), pn1);
});

function issuePseudonymOtherPeer(A) {
  A.setRotationSecret('bank-eu', 1, 'hmac-secret-cn-epoch1');
  return A.pseudonymFor('cust-1', 'bank-eu', 1);
}

test('订单任何要素变更都改变指纹并阻断付款', () => {
  const { A, B } = pair();
  const { compact, order, head } = issue(A, B);
  for (const changed of [
    { amount: '12500.01' },
    { currency: 'EUR' },
    { trade_digest: 'sha256:tampered-docs' },
    { order_id: 'PO-2026-0008' },
  ]) {
    const decision = B.requestPayment({
      credential: compact,
      order: { ...order, ...changed },
      streamHead: head,
      idempotencyKey: `k-${JSON.stringify(changed)}`,
    });
    assert.equal(decision.decision, 'block', `应阻断变更 ${JSON.stringify(changed)}`);
    assert.ok(decision.reasons.some((r) => r.code === 'order_mismatch'));
  }
});

test('时区差异：两端本地时钟表述不同但 UTC 判定一致', () => {
  let t = 1_758_500_000;
  const A = new Institution('bank-cn', { clock: () => t }); // 本地 UTC+8
  const B = new Institution('bank-sg', { clock: () => t }); // 本地 UTC+8
  const C = new Institution('bank-eu', { clock: () => t }); // 本地 UTC+1
  A.bootstrapWith(B);
  A.bootstrapWith(C);
  A.setRotationSecret('bank-sg', 1, 's1');
  A.setRotationSecret('bank-eu', 1, 's2');
  A.noteSubject('cust-1', {});
  const pnSg = A.pseudonymFor('cust-1', 'bank-sg');
  const pnEu = A.pseudonymFor('cust-1', 'bank-eu');
  const base = { order_id: 'O1', currency: 'USD', amount: '10', payee_pseudonym: 'x' };
  const issuedSg = A.issueCredential({
    subjectId: 'cust-1', peerId: 'bank-sg', order: { ...base, payer_pseudonym: pnSg },
    scopes: ['aml', 'trade', 'crossborder'],
    ruleVersions: { aml: '2.1', trade: '1.4', crossborder: '3.0' },
    findings: { aml: {}, trade: {}, crossborder: {} },
  });
  const issuedEu = A.issueCredential({
    subjectId: 'cust-1', peerId: 'bank-eu', order: { ...base, payer_pseudonym: pnEu },
    scopes: ['aml', 'trade', 'crossborder'],
    ruleVersions: { aml: '2.1', trade: '1.4', crossborder: '3.0' },
    findings: { aml: {}, trade: {}, crossborder: {} },
  });
  A.syncTo(B);
  A.syncTo(C);
  const head = A.provideStreamHead().compact;
  const dSg = B.requestPayment({ credential: issuedSg.compact, order: issuedSg.order, streamHead: head });
  const dEu = C.requestPayment({ credential: issuedEu.compact, order: issuedEu.order, streamHead: head });
  assert.equal(dSg.decision, 'release');
  assert.equal(dEu.decision, 'release');
});

test('重复请求：相同幂等键始终返回首次结论；一次性凭证不可二次放行', () => {
  const { A, B } = pair();
  const { compact, order, head } = issue(A, B, { credential: { restrictions: [{ type: 'one_time' }] } });
  const first = B.requestPayment({ credential: compact, order, streamHead: head, idempotencyKey: 'idem-1' });
  assert.equal(first.decision, 'release');
  assert.equal(first.duplicate, false);
  const retry = B.requestPayment({ credential: compact, order, streamHead: head, idempotencyKey: 'idem-1' });
  assert.equal(retry.decision, 'release');
  assert.equal(retry.duplicate, true);
  const secondUse = B.requestPayment({ credential: compact, order, streamHead: head, idempotencyKey: 'idem-2' });
  assert.equal(secondUse.decision, 'block');
  assert.ok(secondUse.reasons.some((r) => r.code === 'restriction_violation'));
});

test('凭证吊销：付款前任何时点吊销，恢复同步后必然阻断', () => {
  const { A, B, advance } = pair();
  const { compact, order, credential } = issue(A, B);
  const head0 = A.provideStreamHead().compact;
  assert.equal(B.requestPayment({ credential: compact, order, streamHead: head0, idempotencyKey: 'a' }).decision, 'release');
  advance(60);
  A.revokeCredential(credential.jti, '发现司法关联');
  // B 尚未恢复：仅凭新鲜流头即可发现自己落后并阻断
  const staleHead = A.provideStreamHead().compact;
  const behind = B.requestPayment({ credential: compact, order, streamHead: staleHead, idempotencyKey: 'b' });
  assert.equal(behind.decision, 'block');
  assert.ok(behind.reasons.some((r) => r.code === 'stream_behind'));
  // 离线恢复：按水位只补发缺口
  const sent = A.syncTo(B);
  assert.equal(sent, 1);
  const freshHead = A.provideStreamHead().compact;
  const caughtUp = B.requestPayment({ credential: compact, order, streamHead: freshHead, idempotencyKey: 'c' });
  assert.equal(caughtUp.decision, 'block');
  assert.ok(caughtUp.reasons.some((r) => r.code === 'credential_revoked'));
});

test('名单更新：双方各自发布、乱序分批到达，折叠后判定一致', () => {
  const { A, B, advance } = pair();
  const { compact, order, credential } = issue(A, B);
  const pn = credential.sub;

  // 先在 B 处付款成功
  const head0 = A.provideStreamHead().compact;
  assert.equal(B.requestPayment({ credential: compact, order, streamHead: head0, idempotencyKey: 'a' }).decision, 'release');

  advance(10);
  // B 自己（收款行）把假名加入名单
  B.publishSanctions('LIST/SG/17', { added: [{ pseudonym: pn, entry_id: 'SG-909' }] });
  const headB = A.provideStreamHead().compact;
  const hit = B.requestPayment({ credential: compact, order, streamHead: headB, idempotencyKey: 'b' });
  assert.ok(hit.reasons.some((r) => r.code === 'sanctions_hit'));

  // 第三方机构 C 离线后以交错、重复批次恢复，应得到相同的命中状态
  advance(10);
  const C = new Institution('bank-eu', { clock: A.clock });
  A.bootstrapWith(C);
  B.bootstrapWith(C);
  const envA = A.stream.exportSince(0);
  const envB = B.stream.exportSince(0);
  C.receiveSync([...envB, ...envA, ...envB]);
  const state = C.state();
  assert.ok(state.blockedPseudonyms.has(pn));

  // 移除命中
  advance(10);
  B.publishSanctions('LIST/SG/18', { removed: [{ pseudonym: pn }] });
  B.syncTo(C);
  assert.equal(C.state().blockedPseudonyms.has(pn), false);
});

test('合规负责人暂停互认立即阻断，恢复后可继续', () => {
  const { A, B } = pair();
  const { compact, order } = issue(A, B);
  A.suspendWith('bank-sg', '合规审查');
  A.syncTo(B);
  const head = A.provideStreamHead().compact;
  const blocked = B.requestPayment({ credential: compact, order, streamHead: head, idempotencyKey: 'a' });
  assert.ok(blocked.reasons.some((r) => r.code === 'relationship_suspended'));
  A.resumeWith('bank-sg');
  A.syncTo(B);
  const head2 = A.provideStreamHead().compact;
  assert.equal(B.requestPayment({ credential: compact, order, streamHead: head2, idempotencyKey: 'b' }).decision, 'release');
});

test('验签钥轮换：轮换前的凭证仍可验，轮换后新凭证以新 kid 签发也可验', () => {
  const { A, B, advance } = pair();
  const old = issue(A, B);
  assert.equal(B.verifyCredential(old.compact).kid, 'k1');
  advance(3600);
  A.rotateSigningKey('k2');
  A.syncTo(B);
  // 旧凭证依旧验签通过（旧钥保留 + 初始目录已信任）
  assert.equal(B.verifyCredential(old.compact).kid, 'k1');
  // 新凭证
  const fresh = issue(A, B);
  assert.equal(fresh.credential.kid, 'k2');
  const decision = B.requestPayment({ credential: fresh.compact, order: fresh.order, streamHead: fresh.head, idempotencyKey: 'n' });
  assert.equal(decision.decision, 'release');
});

test('质疑与补充核验：只返回被质疑范围的证据摘要，不倾倒档案', () => {
  const { A, B } = pair();
  const { compact } = issue(A, B);
  const { compact: challengeEnv } = B.challenge('bank-cn', compact, { scopes: ['aml'], items: ['请提供筛查批次号'] });
  const supplementEnv = A.respondToChallenge(challengeEnv, { reveal: { screening_batch: 'BATCH-2026-09-22-11' } });
  const supplement = B.acceptSupplement(supplementEnv);
  assert.deepEqual(supplement.evidence.map((e) => e.scope), ['aml']);
  assert.equal(JSON.stringify(supplement).includes('cust-1'), false);
  // 超出凭证范围的质疑被签发方拒绝
  const bad = B.challenge('bank-cn', compact, { scopes: ['unknown-scope'] });
  assert.throws(() => A.respondToChallenge(bad.compact, { reveal: {} }), /超出凭证审核范围/);
});

test('审计报告：能解释放行/阻断原因，且不泄露无关交易的假名与条目', () => {
  const { A, B, advance } = pair();
  // 客户 1 的交易
  const tx1 = issue(A, B);
  const head0 = A.provideStreamHead().compact;
  const r1 = B.requestPayment({ credential: tx1.compact, order: tx1.order, streamHead: head0, idempotencyKey: 'tx1' });
  assert.equal(r1.decision, 'release');

  // 客户 2 的无关交易也在 B 行处理
  A.noteSubject('cust-2', { name: '另一位客户' });
  const tx2 = issue(A, B, { subjectId: 'cust-2', order: { order_id: 'PO-OTHER' } });
  advance(5);
  // 名单同时命中两个假名
  B.publishSanctions('L/1', { added: [
    { pseudonym: tx1.credential.sub, entry_id: 'E-1' },
    { pseudonym: tx2.credential.sub, entry_id: 'E-2' },
  ] });
  const headBlock = A.provideStreamHead().compact;
  const r2 = B.requestPayment({ credential: tx1.compact, order: tx1.order, streamHead: headBlock, idempotencyKey: 'tx1-blocked' });
  assert.equal(r2.decision, 'block');

  const report = B.auditReport('tx1-blocked');
  const text = JSON.stringify(report.relevant_events);
  assert.ok(text.includes('E-1'));
  assert.ok(!text.includes('E-2'));
  assert.ok(!text.includes(tx2.credential.sub));
  assert.match(report.explanation, /sanctions_hit/);
  assert.ok(!JSON.stringify(report).includes('另一位客户'));

  // 放行交易的报告同样可解释
  const okReport = B.auditReport('tx1');
  assert.match(okReport.explanation, /放行/);
});

test('安全：篡改事件负载或信封均被拒绝；跳号恢复抛错', () => {
  const { A, B, advance } = pair();
  issue(A, B);
  advance(1);
  A.publishSanctions('L/2', { added: [{ pseudonym: 'pn:x', entry_id: 'e' }] });
  const envelopes = A.stream.exportSince(0);
  // 信封被改一个字节
  assert.throws(() => B.receiveSync([tamper(envelopes[envelopes.length - 1])]), /签名|哈希/);
  // 跳号（只给 seq=3 不给 seq=2）
  const C = new Institution('bank-eu', { clock: A.clock });
  A.bootstrapWith(C);
  advance(1);
  A.publishRuleFloor({ aml: '2.2' });
  const all = A.stream.exportSince(0);
  assert.throws(() => C.receiveSync([all[1]]), /跳号/);
});

function tamper(envelope) {
  const parts = envelope.split('.');
  const buf = Buffer.from(parts[2], 'base64url');
  buf[0] ^= 0xff;
  parts[2] = buf.toString('base64url');
  return parts.join('.');
}

test('离线恢复：按水位增量补发，重复投递全部幂等', () => {
  const { A, B, advance } = pair();
  issue(A, B); // 已同步 seq 基线
  advance(1); A.publishRuleFloor({ aml: '2.2' });
  advance(1); A.publishRuleFloor({ trade: '1.5' });
  advance(1); A.publishSanctions('L/3', { added: [] });
  const wmBefore = B.replicated.highWatermark('bank-cn');
  const batch = A.stream.exportSince(wmBefore);
  assert.equal(batch.length, 3);
  const applied = B.receiveSync(batch);
  assert.equal(applied.length, 3);
  const again = B.receiveSync(batch);
  assert.equal(again.length, 0);
  assert.equal(B.state().ruleFloors.aml, '2.2');
  assert.equal(B.state().ruleFloors.trade, '1.5');
});

test('规则底线：签发凭证后全员抬高底线，旧规则凭证在付款前被阻断', () => {
  const { A, B, advance } = pair();
  const tx = issue(A, B);
  advance(1);
  B.publishRuleFloor({ aml: '2.2' }); // 收款行要求更高反洗钱规则（自摄入本地状态）
  const head = A.provideStreamHead().compact;
  const r = B.requestPayment({ credential: tx.compact, order: tx.order, streamHead: head, idempotencyKey: 'x' });
  assert.ok(r.reasons.some((d) => d.code === 'rule_outdated'));
});

test('无带外信任关系时拒绝验签', () => {
  let t = 1_758_500_000;
  const A = new Institution('bank-cn', { clock: () => t });
  const X = new Institution('bank-unknown', { clock: () => t });
  A.setRotationSecret('bank-unknown', 1, 's');
  A.noteSubject('c', {});
  const issued = A.issueCredential({
    subjectId: 'c', peerId: 'bank-unknown',
    order: { order_id: 'o', currency: 'USD', amount: '1', payer_pseudonym: A.pseudonymFor('c', 'bank-unknown'), payee_pseudonym: 'y' },
    scopes: ['aml', 'trade', 'crossborder'],
    ruleVersions: { aml: '2.1', trade: '1.4', crossborder: '3.0' },
    findings: { aml: {}, trade: {}, crossborder: {} },
  });
  assert.throws(() => X.verifyCredential(issued.compact), /可信公钥/);
});

test('订单指纹对各要素敏感', () => {
  const o = { order_id: '1', currency: 'USD', amount: '100', payer_pseudonym: 'p', payee_pseudonym: 'q', trade_digest: 'd' };
  assert.equal(orderFingerprint(o), orderFingerprint({ ...o }));
  assert.notEqual(orderFingerprint(o), orderFingerprint({ ...o, amount: '101' }));
});
