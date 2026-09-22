// 限制条件形如 amount<=50000、currency=USD、corridor=CN>SG。
// 评估所需上下文缺失时一律视为不满足：付款前宁可阻断。
const PATTERN = /^([a-z_]+)(<=|>=|=)(.+)$/;

export function checkRestrictions(restrictions, context) {
  const violations = [];
  for (const restriction of restrictions) {
    const match = PATTERN.exec(restriction);
    if (!match) {
      violations.push(`限制条件无法解析:${restriction}`);
      continue;
    }
    const [, key, op, expected] = match;
    const actual = context[key];
    if (actual === undefined || actual === null) {
      violations.push(`限制条件缺少评估上下文:${key}`);
      continue;
    }
    if (op === '=') {
      if (String(actual) !== expected) violations.push(`限制条件不满足:${restriction}`);
      continue;
    }
    const actualNum = Number(actual);
    const expectedNum = Number(expected);
    if (Number.isNaN(actualNum) || Number.isNaN(expectedNum)) {
      violations.push(`限制条件需要数值上下文:${restriction}`);
      continue;
    }
    if (op === '<=' && !(actualNum <= expectedNum)) violations.push(`限制条件不满足:${restriction}`);
    if (op === '>=' && !(actualNum >= expectedNum)) violations.push(`限制条件不满足:${restriction}`);
  }
  return violations;
}
