// 机构内 Ed25519 密钥环：kid 标识、轮换、序列化（仅保存在本机构，永不出境）。
import { createPrivateKey, createPublicKey, generateKeyPairSync, createHash } from 'node:crypto';
import { b64url } from './encoding.js';

export class KeyRing {
  constructor(institutionId, keys = [], currentKid = null) {
    this.institutionId = institutionId;
    // kid -> { kid, privateKey, publicKey, created_at }
    this.keys = new Map(keys);
    this.currentKid = currentKid;
  }

  static initialize(institutionId, kid = 'k1', createdAt) {
    const ring = new KeyRing(institutionId);
    ring.generate(kid, createdAt);
    return ring;
  }

  generate(kid, createdAt) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    this.keys.set(kid, { kid, privateKey, publicKey, created_at: createdAt });
    this.currentKid = kid;
    return kid;
  }

  // 轮换：生成新 kid，旧钥保留用于对历史凭证验签与对轮换公告背书。
  rotate(kid, createdAt) {
    if (this.keys.has(kid)) throw new Error(`kid ${kid} 已存在`);
    const predecessor = this.currentKid;
    this.generate(kid, createdAt);
    return { kid, predecessor };
  }

  get current() {
    const key = this.keys.get(this.currentKid);
    if (!key) throw new Error('密钥环没有当前密钥');
    return key;
  }

  getPrivate(kid) {
    const key = this.keys.get(kid ?? this.currentKid);
    if (!key) throw new Error(`未知 kid ${kid}`);
    return key.privateKey;
  }

  getPublic(kid) {
    const key = this.keys.get(kid ?? this.currentKid);
    if (!key) throw new Error(`未知 kid ${kid}`);
    return key.publicKey;
  }

  publicJwk(kid) {
    const jwk = this.getPublic(kid).export({ format: 'jwk' });
    delete jwk.d;
    return jwk;
  }

  // 持久化私钥仅以 JWK 写入本机构存储；示例项目中快照只存在内存/临时文件。
  toJSON() {
    return {
      institution_id: this.institutionId,
      current_kid: this.currentKid,
      keys: [...this.keys.values()].map((k) => ({
        kid: k.kid,
        created_at: k.created_at,
        private_jwk: k.privateKey.export({ format: 'jwk' }),
      })),
    };
  }

  static fromJSON(data) {
    const ring = new KeyRing(data.institution_id);
    for (const row of data.keys) {
      const privateKey = createPrivateKey({ key: row.private_jwk, format: 'jwk' });
      ring.keys.set(row.kid, {
        kid: row.kid,
        privateKey,
        publicKey: createPublicKey(privateKey),
        created_at: row.created_at,
      });
    }
    ring.currentKid = data.current_kid;
    return ring;
  }
}

export function publicKeyFromJwk(jwk) {
  return createPublicKey({ key: jwk, format: 'jwk' });
}

export function keyFingerprint(publicKey) {
  return `kf:${b64url(createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest()).slice(0, 21)}`;
}
