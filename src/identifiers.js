import { hmacHex } from './crypto.js';

// 可轮换的成对伪名标识：同一客户或订单在不同机构对、不同轮换纪元下
// 呈现不同标识；原始身份映射只保留在本机构内部，跨机构链路上不出现。
// 轮换纪元递增后旧伪名不再用于新凭证，已签发凭证保持签发时的伪名。
export class IdentifierRotator {
  constructor({ pairId, secret, epoch = 1 }) {
    if (!pairId || !secret) throw new Error('伪名轮换器需要机构对标识与密钥');
    this.pairId = pairId;
    this.secret = secret;
    this.epoch = epoch;
  }

  pseudonym(localId) {
    const tag = hmacHex(this.secret, `${this.pairId}|${this.epoch}|${localId}`).slice(0, 24);
    return `ps_${tag}`;
  }

  rotate() {
    this.epoch += 1;
  }
}
