// elgamal.h : ElGamal 加密、解密、签名、验证及格式转换。
#ifndef ELGAMAL_H
#define ELGAMAL_H

#include "bigint.h"
#include <string>

namespace Crypto {

struct ElGamalKey {
    NTL::ZZ p;   // 大素数
    NTL::ZZ g;   // 生成元
    NTL::ZZ y;   // 公钥 y = g^x mod p
    NTL::ZZ x;   // 私钥
    bool isPrivate() const { return x != NTL::ZZ(0); }
};

// 密钥生成：p 为 bits 比特安全素数（p=2q+1, q 为素数），g 为生成元
void ElGamalKeyGen(ElGamalKey& key, long bits = 1024, long k = 20);

// 加密 / 解密（m 应 < p）。密文为 (c1, c2)
void ElGamalEncrypt(const ElGamalKey& pub, const NTL::ZZ& m, NTL::ZZ& c1, NTL::ZZ& c2);
NTL::ZZ ElGamalDecrypt(const ElGamalKey& priv, const NTL::ZZ& c1, const NTL::ZZ& c2);

// 签名 / 验证（hm 为消息摘要对应的整数）
void ElGamalSign(const ElGamalKey& priv, const NTL::ZZ& hm, NTL::ZZ& r, NTL::ZZ& s);
bool ElGamalVerify(const ElGamalKey& pub, const NTL::ZZ& hm, const NTL::ZZ& r, const NTL::ZZ& s);

// 消息 <-> 整数
NTL::ZZ ElGamalEncodeMessage(const std::string& msg);
std::string ElGamalDecodeMessage(const NTL::ZZ& m);

// 公钥 / 私钥 <-> 字符串
std::string ElGamalPubKeyToString(const ElGamalKey& pub);
ElGamalKey ElGamalPubKeyFromString(const std::string& s);
std::string ElGamalFullKeyToString(const ElGamalKey& key);
ElGamalKey ElGamalFullKeyFromString(const std::string& s);

} // namespace Crypto

#endif
