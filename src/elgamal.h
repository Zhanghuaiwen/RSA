// =====================================================================
// elgamal.h : ElGamal 公钥密码体制（基于有限域上的离散对数难题）：
//
//   ElGamal 原理：
//     选取随机素数 p（默认 2048 比特），并取素数 q，使 q | (p-1)，
//     生成元 g 的阶恰为 q（128/256/512 比特），私钥 x 随机选取，
//     公钥 y = g^x mod p。
//   加密：随机取 k，c1 = g^k mod p，c2 = m * y^k mod p，密文为 (c1, c2)
//   解密：m = c2 * inv(c1^x) mod p
//   签名：随机取与 p-1 互素的 k，r = g^k mod p，
//         s = k^{-1} * (H(m) - x*r) mod (p-1)，签名 (r, s)
//   验证：y^r * r^s == g^{H(m)} (mod p)
//   安全性依赖于求解离散对数 x 的困难性。
#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <NTL/ZZ.h>
#include <string>

namespace Crypto {

// ElGamal 密钥对：公钥(p,g,y)，私钥 x
struct ElGamalKey {
    NTL::ZZ p;   // 大素数（公开）
    NTL::ZZ g;   // 生成元（公开）
    NTL::ZZ y;   // 公钥 y = g^x mod p（公开）
    NTL::ZZ x;   // 私钥（保密）
    bool isPrivate() const { return x != NTL::ZZ(0); }
};

// 密钥生成：p 为 bits 比特素数，且存在素数 q | (p-1)，g 为阶为 q 的生成元
void ElGamalKeyGen(ElGamalKey& key, long bits = 1024, long k = 20);

// 加密 / 解密（要求 0 <= m < p）。密文为 (c1, c2)
void ElGamalEncrypt(const ElGamalKey& pub, const NTL::ZZ& m, NTL::ZZ& c1, NTL::ZZ& c2);
NTL::ZZ ElGamalDecrypt(const ElGamalKey& priv, const NTL::ZZ& c1, const NTL::ZZ& c2);

// 签名 / 验证（hm 为消息摘要对应的整数）。(r, s) 为签名
void ElGamalSign(const ElGamalKey& priv, const NTL::ZZ& hm, NTL::ZZ& r, NTL::ZZ& s);
bool ElGamalVerify(const ElGamalKey& pub, const NTL::ZZ& hm, const NTL::ZZ& r, const NTL::ZZ& s);

// 消息 <-> 整数
NTL::ZZ ElGamalEncodeMessage(const std::string& msg);
std::string ElGamalDecodeMessage(const NTL::ZZ& m);

// 公钥 / 私钥 <-> 字符串（用于证书的 ver 字段与密钥文本存储）
std::string ElGamalPubKeyToString(const ElGamalKey& pub);
ElGamalKey ElGamalPubKeyFromString(const std::string& s);
std::string ElGamalFullKeyToString(const ElGamalKey& key);
ElGamalKey ElGamalFullKeyFromString(const std::string& s);

} // namespace Crypto

#endif