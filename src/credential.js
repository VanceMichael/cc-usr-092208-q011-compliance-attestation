import { canonicalize, sha256Hex, signPayload, verifyPayload } from './crypto.js';
import { toIsoUtc, toUtcMillis } from './time.js';

// 汇款前必须覆盖的审核范围：反洗钱、贸易背景、跨境合规。
export const REQUIRED_SCOPES = ['aml', 'trade_background', 'cross_border'];

// 凭证只携带伪名与摘要：审核范围、规则版本、证据摘要、有效期、限制条件，
// 不携带任何原始客户材料。credential_id 由内容摘要派生，天然防篡改。
export function buildCredentialBody({
  issuer,
  audience,
  subjectRef,
  orderRef,
  orderDigest,
  scopes,
  ruleSetVersion,
  listEpoch,
  evidenceDigest,
  notBefore,
  notAfter,
  restrictions = [],
  idempotencyKey,
  issuerHead,
}) {
  const notBeforeMs = toUtcMillis(notBefore);
  const notAfterMs = toUtcMillis(notAfter);
  if (notAfterMs <= notBeforeMs) throw new Error('凭证有效期终点必须晚于起点');
  if (!Array.isArray(scopes) || scopes.length === 0) throw new Error('凭证必须声明审核范围');
  if (!idempotencyKey) throw new Error('凭证必须携带幂等键');
  const body = {
    issuer,
    audience,
    subject_ref: subjectRef,
    order_ref: orderRef,
    order_digest: orderDigest,
    scopes: [...new Set(scopes)].sort(),
    rule_set_version: ruleSetVersion,
    list_epoch: listEpoch,
    evidence_digest: evidenceDigest,
    not_before: toIsoUtc(notBeforeMs),
    not_after: toIsoUtc(notAfterMs),
    restrictions: [...restrictions].sort(),
    idempotency_key: idempotencyKey,
    issuer_head: issuerHead,
  };
  const credentialId = `cred_${sha256Hex(canonicalize(body)).slice(0, 24)}`;
  return { credential_id: credentialId, ...body };
}

export function signCredential(body, privateKeyPem) {
  return { ...body, signature: signPayload(privateKeyPem, canonicalize(body)) };
}

export function verifyCredentialSignature(credential, publicKeyPem) {
  if (!credential || typeof credential.signature !== 'string') return false;
  const { signature, ...body } = credential;
  return verifyPayload(publicKeyPem, canonicalize(body), signature);
}
