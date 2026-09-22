// 统一的字节 / base64url / 规范 JSON 编码，跨境链路只交换这些最小文本。
import { createHash } from 'node:crypto';

export function utf8(text) {
  return Buffer.from(text, 'utf8');
}

export function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

export function b64urlDecode(text) {
  return Buffer.from(text, 'base64url');
}

// 确定性 JSON：键按字典序排列，保证两端对同一负载算出的摘要完全一致。
export function canonicalJSON(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sortDeep(value[key])]),
    );
  }
  return value;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest();
}
