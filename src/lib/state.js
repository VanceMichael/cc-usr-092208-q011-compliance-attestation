// 把签名事件流确定性地折叠成付款门禁所需状态；门禁本身是纯函数，
// 因此任意机构在同一组事件、同一 UTC 时刻对同一凭证必然得到同一结论。
import { SCOPES } from './attestation.js';

export const REQUIRED_SCOPES = [...SCOPES];

// 输入 ReplicatedLog.orderedRecords() 的记录，输出：
// { blockedPseudonyms, ruleFloors, revokedJtis, suspendedPairs, trustedKeys }
export function foldState(records) {
  const blockedPseudonyms = new Map(); // pseudonym -> { entry_id, list_version, iss, ts }
  const floorsByIssuer = new Map(); // iss -> { scope -> version }
  const revokedJtis = new Map(); // jti -> { iss, ts, reason }
  const suspended = new Map(); // pairKey -> { since, by }

  for (const r of records) {
    switch (r.kind) {
      case 'sanction.list.updated': {
        const v = r.body.list_version;
        for (const e of r.body.added ?? []) {
          blockedPseudonyms.set(e.pseudonym, { entry_id: e.entry_id, list_version: v, iss: r.iss, ts: r.ts });
        }
        for (const e of r.body.removed ?? []) {
          blockedPseudonyms.delete(e.pseudonym);
        }
        break;
      }
      case 'rule.floor.updated': {
        floorsByIssuer.set(r.iss, { ...(floorsByIssuer.get(r.iss) ?? {}), ...r.body.floors });
        break;
      }
      case 'credential.revoked': {
        revokedJtis.set(r.body.jti, { iss: r.iss, ts: r.ts, reason: r.body.reason ?? null });
        break;
      }
      case 'relationship.suspended': {
        suspended.set(pairKey(r.iss, r.body.peer), { since: r.ts, by: r.iss });
        break;
      }
      case 'relationship.resumed': {
        suspended.delete(pairKey(r.iss, r.body.peer));
        break;
      }
    }
  }

  // 任一机构宣布的更高底线对全体生效：取跨机构最高版本。
  const ruleFloors = {};
  for (const scope of SCOPES) {
    let winner = null;
    for (const floors of floorsByIssuer.values()) {
      const v = floors[scope];
      if (v && (winner === null || compareVersions(v, winner) > 0)) winner = v;
    }
    if (winner) ruleFloors[scope] = winner;
  }

  return { blockedPseudonyms, ruleFloors, revokedJtis, suspended, floorsByIssuer };
}

export function pairKey(a, b) {
  return [a, b].sort().join('~');
}

export function compareVersions(a, b) {
  const pa = String(a).split('.');
  const pb = String(b).split('.');
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i += 1) {
    const x = Number(pa[i] ?? 0);
    const y = Number(pb[i] ?? 0);
    if (Number.isNaN(x) || Number.isNaN(y)) {
      const cmp = String(pa[i] ?? '').localeCompare(String(pb[i] ?? ''));
      if (cmp) return cmp;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

// 纯函数门禁。release 当且仅当 reasons 为空；任何不确定一律 fail closed。
export function evaluatePayment({
  credential,
  signatureVerified,
  signerIssuer,
  selfId,
  expectedOrderFp,
  order,
  now,
  state,
  localScreening,
  consumedOneTimeJtis = new Set(),
}) {
  const reasons = [];
  const c = credential;

  if (!signatureVerified) reasons.push({ code: 'bad_signature', detail: `签发方 ${signerIssuer ?? '未知'}` });
  if (signatureVerified && c.iss === selfId) reasons.push({ code: 'self_issued', detail: '不能凭本机构签发的凭证放行' });
  const audience = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (signatureVerified && !audience.includes(selfId)) reasons.push({ code: 'audience_mismatch', detail: `受众 ${audience.join(',')}` });
  if (now < c.nbf) reasons.push({ code: 'not_yet_valid', detail: `生效时刻 ${c.nbf}` });
  if (now >= c.exp) reasons.push({ code: 'expired', detail: `失效时刻 ${c.exp}` });
  if (c.order_fp !== expectedOrderFp) reasons.push({ code: 'order_mismatch', detail: '凭证与当前订单指纹不一致' });

  if (signatureVerified && state.suspended.has(pairKey(selfId, c.iss))) {
    reasons.push({ code: 'relationship_suspended', detail: `与 ${c.iss} 的互认关系已暂停` });
  }
  if (state.revokedJtis.has(c.jti)) {
    const rev = state.revokedJtis.get(c.jti);
    reasons.push({ code: 'credential_revoked', detail: `由 ${rev.iss} 于 ${rev.ts} 吊销：${rev.reason ?? ''}` });
  }
  if (state.blockedPseudonyms.has(c.sub)) {
    const hit = state.blockedPseudonyms.get(c.sub);
    reasons.push({ code: 'sanctions_hit', detail: `名单版本 ${hit.list_version} 条目 ${hit.entry_id}` });
  }

  for (const scope of REQUIRED_SCOPES) {
    if (!array(c.scopes).includes(scope)) reasons.push({ code: 'scope_missing', detail: `缺少审核范围 ${scope}` });
  }
  for (const scope of array(c.scopes)) {
    const floor = state.ruleFloors[scope];
    const used = c.rules?.[scope];
    if (floor && (!used || compareVersions(used, floor) < 0)) {
      reasons.push({ code: 'rule_outdated', detail: `${scope} 使用 ${used ?? '无'}，底线 ${floor}` });
    }
  }

  for (const r of array(c.restrictions)) {
    const violation = checkRestriction(r, order, c.jti, consumedOneTimeJtis);
    if (violation) reasons.push(violation);
  }

  if (localScreening && !localScreening.passed) {
    reasons.push({ code: 'local_screening_failed', detail: (localScreening.hits ?? []).join(',') || '本地复核未通过' });
  }

  return {
    decision: reasons.length ? 'block' : 'release',
    reasons,
    evaluated_at: now,
    rule_versions: c.rules ?? {},
    scopes: array(c.scopes),
  };
}

function array(v) {
  return Array.isArray(v) ? v : [];
}

function checkRestriction(r, order, jti, consumed) {
  switch (r.type) {
    case 'max_amount': {
      if (r.currency && order.currency !== r.currency) {
        return { code: 'restriction_violation', detail: `币种 ${order.currency} 不满足 ${r.currency}` };
      }
      if (Number(order.amount) > Number(r.amount)) {
        return { code: 'restriction_violation', detail: `金额 ${order.amount} 超过上限 ${r.amount}` };
      }
      return null;
    }
    case 'currency_in': {
      if (!r.currencies.includes(order.currency)) {
        return { code: 'restriction_violation', detail: `币种 ${order.currency} 不在允许列表` };
      }
      return null;
    }
    case 'one_time': {
      return consumed.has(jti)
        ? { code: 'restriction_violation', detail: '一次性凭证已被使用' }
        : null;
    }
    default:
      // 无法识别的限制条件按最严格处理：不放行。
      return { code: 'restriction_unknown', detail: `限制类型 ${r.type} 无法解释` };
  }
}
