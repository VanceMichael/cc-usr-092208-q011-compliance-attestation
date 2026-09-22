// 数字信封：`<版本>.<规范JSON负载(base64url)>.<签名(base64url)>`。
// 签名算法 Ed25519，签名内容是“版本.负载”，不规范编码（null），由负载内 kid 指定验签公钥。
import { sign as edSign, verify as edVerify, createPublicKey } from 'node:crypto';
import { b64url, b64urlDecode, canonicalJSON } from './encoding.js';

const ENVELOPE_VERSION = 'v1';

export function signPayload(payload, privateKey) {
  const body = `${ENVELOPE_VERSION}.${b64url(canonicalJSON(payload))}`;
  const signature = edSign(null, Buffer.from(body), privateKey);
  return `${body}.${b64url(signature)}`;
}

// 返回 { payload, compact }；验签失败、格式错误一律抛异常，绝不返回“半可信”对象。
export function openEnvelope(compact, resolvePublicKey) {
  const parts = compact.split('.');
  if (parts.length !== 3 || parts[0] !== ENVELOPE_VERSION) {
    throw new Error('凭证信封格式不受支持');
  }
  const payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  const publicKey = resolvePublicKey(payload);
  const ok = edVerify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`),
    normalizeKey(publicKey),
    b64urlDecode(parts[2]),
  );
  if (!ok) throw new Error('凭证签名验证失败');
  return { payload, compact };
}

function normalizeKey(key) {
  return typeof key === 'string' || Buffer.isBuffer(key) ? createPublicKey(key) : key;
}
