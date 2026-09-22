// 合规结论凭证：审核范围、规则版本、证据摘要、有效期与限制条件。
// 凭证内不含任何原始材料，证据以摘要形式出现；原始材料仅保存在签发机构本地。
import { createHash } from 'node:crypto';
import { b64url, canonicalJSON, utf8 } from './encoding.js';

export const CREDENTIAL_TYPE = 'compliance-credential/v1';
export const SCOPES = ['aml', 'trade', 'crossborder'];

export function evidenceDigest(kind, ruleVersion, summary) {
  // summary 由签发机构在本地从完整材料计算后给出（例如筛查命中清单哈希 + 审核人结论）。
  return `ev:${kind}:${b64url(
    createHash('sha256').update(utf8(canonicalJSON({ kind, ruleVersion, summary }))).digest(),
  ).slice(0, 43)}`;
}

// 构造凭证负载（尚未签名）。所有时间为 UTC 纪元秒，签发方与接收方处于不同时区也得到同一判定。
export function buildCredential({
  jti,
  issuer,
  audience,
  subjectPseudonym,
  orderFingerprint: orderFp,
  scopes,
  ruleVersions,
  evidence,
  issuedAt,
  notBefore = issuedAt,
  expiresAt,
  restrictions = [],
  parentJti = null,
  kid,
}) {
  const missing = scopes.filter((s) => !SCOPES.includes(s));
  if (missing.length) throw new Error(`未知审核范围 ${missing.join(',')}`);
  for (const scope of scopes) {
    if (!ruleVersions?.[scope]) throw new Error(`范围 ${scope} 缺少规则版本`);
  }
  if (!(expiresAt > issuedAt)) throw new Error('凭证有效期必须晚于签发时刻');
  if (notBefore > expiresAt) throw new Error('生效时刻不得晚于失效时刻');
  return {
    typ: CREDENTIAL_TYPE,
    jti,
    iss: issuer,
    aud: audience,
    sub: subjectPseudonym,
    order_fp: orderFp,
    scopes: [...scopes].sort(),
    rules: ruleVersions,
    evidence: evidence.map((e) => ({
      scope: e.scope,
      digest: e.digest,
      rule_version: e.ruleVersion,
    })),
    iat: issuedAt,
    nbf: notBefore,
    exp: expiresAt,
    restrictions,
    parent_jti: parentJti,
    kid,
  };
}

// 结构性校验；业务校验（受众、订单绑定、吊销等）在付款门禁中完成。
export function assertWellFormed(payload) {
  if (payload.typ !== CREDENTIAL_TYPE) throw new Error('凭证类型不受支持');
  for (const key of ['jti', 'iss', 'aud', 'sub', 'order_fp', 'scopes', 'rules', 'evidence', 'iat', 'nbf', 'exp', 'kid']) {
    if (payload[key] === undefined) throw new Error(`凭证缺少字段 ${key}`);
  }
  if (!Array.isArray(payload.scopes) || payload.scopes.length === 0) throw new Error('凭证审核范围为空');
  if (!payload.evidence.every((e) => e.digest && e.scope)) throw new Error('证据摘要不完整');
  if (!(payload.nbf <= payload.exp)) throw new Error('凭证有效期不合法');
}
