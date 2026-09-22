import { createHash, createHmac, generateKeyPairSync, sign, verify } from 'node:crypto';

// 规范化序列化：键序稳定，签名与内容摘要才具备跨机构可比对性。
export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256Hex(input) {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export function hmacHex(secret, input) {
  return createHmac('sha256', secret).update(input, 'utf8').digest('hex');
}

export function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

export function signPayload(privateKeyPem, payload) {
  return sign(null, Buffer.from(payload, 'utf8'), privateKeyPem).toString('hex');
}

export function verifyPayload(publicKeyPem, payload, signatureHex) {
  try {
    return verify(null, Buffer.from(payload, 'utf8'), publicKeyPem, Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}
