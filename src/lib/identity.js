// 可轮换标识（假名）。
// 真实客户档案永不离开本机构；跨境链路只出现由 HMAC 派生的假名，
// 每个互认关系（peer 机构 + 轮换代号）使用独立假名，代号轮换后旧假名不可与新假名关联。
import { createHmac, createHash, randomBytes } from 'node:crypto';
import { b64url } from './encoding.js';

// rotationSecret：每段轮换周期的机构内秘密，仅签发方持有，永不上链、不出境。
export function issuePseudonym({ institutionId, subjectId, peerInstitutionId, rotationEpoch, rotationSecret }) {
  const tag = createHmac('sha256', rotationSecret)
    .update(`${institutionId}|${subjectId}|${peerInstitutionId}|${rotationEpoch}`)
    .digest();
  return `pn:${rotationEpoch}:${b64url(tag).slice(0, 32)}`;
}

// 订单指纹：订单号、币种金额、收付双方假名、贸易单据摘要的绑定摘要。
// 凭证只对“这一笔订单”有效，订单要素任何改动都会得到不同指纹。
export function orderFingerprint(order) {
  const required = ['order_id', 'currency', 'amount', 'payer_pseudonym', 'payee_pseudonym'];
  for (const key of required) {
    if (order[key] === undefined || order[key] === null || order[key] === '') {
      throw new Error(`订单缺少必要字段 ${key}`);
    }
  }
  return `ofp:${b64url(
    createHash('sha256')
      .update(JSON.stringify([
        order.order_id,
        order.currency,
        String(order.amount),
        order.payer_pseudonym,
        order.payee_pseudonym,
        order.trade_digest ?? '',
      ]))
      .digest(),
  ).slice(0, 43)}`;
}

export function nonce(size = 18) {
  return b64url(randomBytes(size));
}
