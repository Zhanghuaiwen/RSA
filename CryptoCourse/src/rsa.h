// rsa.h : RSA 加密、解密、签名、验证及格式转换（基于 NTL::ZZ）。
#ifndef RSA_H
#define RSA_H

#include "bigint.h"
#include <string>

namespace Crypto {

struct RSAKey {
    NTL::ZZ n;   // 模数
    NTL::ZZ b;   // 公钥指数 e
    NTL::ZZ p;   // 私钥素数 p
    NTL::ZZ q;   // 私钥素数 q
    NTL::ZZ a;   // 私钥指数 d
    bool isPrivate() const { return p != NTL::ZZ(0); }
};

// 密钥生成：p,q 为 bits 比特随机素数（默认 1024）
void RSAKeyGen(RSAKey& key, long bits = 1024, long k = 20);

// 加密 / 解密（m, c 均为小于 n 的整数）
NTL::ZZ RSAEncrypt(const RSAKey& pub, const NTL::ZZ& m);
NTL::ZZ RSADecrypt(const RSAKey& priv, const NTL::ZZ& c);

// 签名 / 验证（hm 为消息摘要对应的整数，应 < n）
NTL::ZZ RSASign(const RSAKey& priv, const NTL::ZZ& hm);
bool RSAVerify(const RSAKey& pub, const NTL::ZZ& hm, const NTL::ZZ& s);

// 消息 <-> 整数（字节串 <-> ZZ）
NTL::ZZ RSAEncodeMessage(const std::string& msg);
std::string RSADecodeMessage(const NTL::ZZ& m);

// 公钥 / 私钥 <-> 字符串（用于证书与文件）
std::string RSAPubKeyToString(const RSAKey& pub);          // "RSA n=... b=..."
RSAKey RSAPubKeyFromString(const std::string& s);
std::string RSAFullKeyToString(const RSAKey& key);         // 含私钥
RSAKey RSAFullKeyFromString(const std::string& s);

} // namespace Crypto

#endif
