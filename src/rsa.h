// =====================================================================
// rsa.h : RSA 公钥密码体制（基于 NTL::ZZ 大整数）。
//
//   RSA 原理：
//     选取两个大素数 p、q，令 n = p*q，phi = (p-1)(q-1)。
//     选择公钥指数 e（本设计取 65537，且要求 gcd(e, phi)=1），
//     计算私钥指数 d = e^{-1} mod phi。
//   公钥 (n, e)，私钥 (p, q, d)：
//     加密：c = m^e  mod n
//     解密：m = c^d  mod n
//     签名：s = H(m)^d mod n   （H 为 SHA-256，签名对象是消息摘要）
//     验证：s^e mod n == H(m)
//   本设计把明文按字节串编码为大整数 m 后运算。
// =====================================================================
#ifndef RSA_H
#define RSA_H

#include <NTL/ZZ.h>
#include <string>

namespace Crypto {

// RSA 密钥对：公钥(n,b)，私钥(p,q,a)。b 即公钥指数 e，a 即私钥指数 d
struct RSAKey {
    NTL::ZZ n;   // 模数 n = p*q（公开）
    NTL::ZZ b;   // 公钥指数 e（公开）通常取 65537
    NTL::ZZ p;   // 素数 p（保密）
    NTL::ZZ q;   // 素数 q（保密）
    NTL::ZZ a;   // 私钥指数 d（保密）
    bool isPrivate() const { return p != NTL::ZZ(0); }  // 是否含私钥分量
};

// 密钥生成：p、q 为 bits 比特随机素数（任务书要求取 1024 比特）
void RSAKeyGen(RSAKey& key, long bits = 1024, long k = 20);

// 加密 / 解密（要求 0 <= m, c < n）
NTL::ZZ RSAEncrypt(const RSAKey& pub, const NTL::ZZ& m);
NTL::ZZ RSADecrypt(const RSAKey& priv, const NTL::ZZ& c);

// 签名 / 验证（hm 为消息摘要对应的整数，应 < n）
NTL::ZZ RSASign(const RSAKey& priv, const NTL::ZZ& hm);
bool RSAVerify(const RSAKey& pub, const NTL::ZZ& hm, const NTL::ZZ& s);

// 消息 <-> 整数（字节串 <-> ZZ）
NTL::ZZ RSAEncodeMessage(const std::string& msg);
std::string RSADecodeMessage(const NTL::ZZ& m);

// 公钥 / 私钥 <-> 字符串（用于证书的 ver 字段与密钥文本存储）
std::string RSAPubKeyToString(const RSAKey& pub);          // "RSA n=... b=..."
RSAKey RSAPubKeyFromString(const std::string& s);
std::string RSAFullKeyToString(const RSAKey& key);         // 含私钥分量 p,q,a
RSAKey RSAFullKeyFromString(const std::string& s);

} // namespace Crypto

#endif