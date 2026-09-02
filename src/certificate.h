// certificate.h : 简单证书方案（课本 9.3.1），含 TA 的 ID、签名算法标志 flag1、用途标志 flag2。
#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <NTL/ZZ.h>
#include "rsa.h"
#include "elgamal.h"
#include <string>
#include <vector>

namespace Crypto {

enum SigScheme { SCHEME_RSA = 0, SCHEME_ELGAMAL = 1 };
enum KeyUsage  { USE_ENCRYPT = 0, USE_SIGN = 1 };

// 统一公钥 / 私钥封装，支持 RSA 与 ElGamal
struct PubKey {
    int scheme = SCHEME_RSA;
    RSAKey rsa;
    ElGamalKey elg;
};
struct PrivKey {
    int scheme = SCHEME_RSA;
    RSAKey rsa;
    ElGamalKey elg;
};

PubKey parsePubKey(const std::string& ver);          // 由 "RSA ..." / "ELG ..." 解析
std::string pubKeyToString(const PubKey& pk);

// 用私钥对摘要 hm 签名，返回签名字符串（RSA 为整数；ElGamal 为 "r=... s=..."）
std::string signHash(const PrivKey& priv, const NTL::ZZ& hm);
// 用公钥验证签名
bool verifyHash(const PubKey& pub, const NTL::ZZ& hm, const std::string& sigStr);

// 证书（txt 格式）
struct Cert {
    std::string id;     // ID(subject)
    std::string ver;    // ver_subject：主体公钥字符串
    std::string sig;    // s = sig_TA(ID || ver)
    std::string idTA;   // ID(TA)
    int flag1 = 0;      // 0=RSA, 1=ElGamal（签名算法）
    int flag2 = 0;      // 0=加密, 1=签名（公钥用途）

    std::string dataForSign() const { return id + "|" + ver; }   // TA 签名的内容
    std::string toTxt() const;          // 序列化为 txt
    static Cert fromTxt(const std::string& txt);
    bool valid() const { return !id.empty() && !ver.empty(); }
};

// 证书颁发：TA 用自己的私钥为 subject 的公钥 ver 签名，生成证书
Cert issueCertificate(const std::string& subjectID, const PubKey& subjectPub,
                      const PrivKey& taPriv, const std::string& taID,
                      int flag1, int flag2);

// 证书验证：使用颁发者(TA)的公钥验证证书可信
bool verifyCertificate(const Cert& cert, const PubKey& issuerPub);

// 验证整条证书链（root -> ... -> subject），全部可信才返回 true
bool verifyCertPath(const std::vector<Cert>& path);

// 方案无关的消息加解密（密文编码为字符串）
std::string encryptMessage(const PubKey& pub, const NTL::ZZ& m);
NTL::ZZ decryptMessage(const PrivKey& priv, const std::string& ct);

// 方案无关的消息签名 / 验证（对消息做 SHA-256 摘要后签名）
std::string signMessage(const PrivKey& priv, const std::string& msg);
bool verifyMessage(const PubKey& pub, const std::string& msg, const std::string& sigStr);

} // namespace Crypto

#endif
