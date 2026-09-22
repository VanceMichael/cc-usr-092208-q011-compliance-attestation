// 跨机构时间一律换算为 UTC 毫秒比较，消除时区差异带来的歧义。
// 输入必须携带时区标记（Z 或 ±hh:mm），不带时区的本地时间直接拒绝。
const ZONE_SUFFIX = /(Z|[+-]\d{2}:?\d{2})$/;

export function toUtcMillis(isoString) {
  if (typeof isoString !== 'string') throw new Error('时间必须是字符串');
  const text = isoString.trim();
  if (!ZONE_SUFFIX.test(text)) throw new Error(`时间缺少时区标记: ${isoString}`);
  const ms = Date.parse(text);
  if (Number.isNaN(ms)) throw new Error(`无法解析时间: ${isoString}`);
  return ms;
}

export function toIsoUtc(ms) {
  return new Date(ms).toISOString();
}
