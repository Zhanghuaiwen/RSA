// entity.h : 系统中的实体（用户 Alice / Bob / Eve），每个实体拥有加密密钥与签名密钥。
#ifndef ENTITY_H
#define ENTITY_H

#include "certificate.h"
#include "pki.h"
#include <string>

namespace Crypto {

struct Entity {
    std::string id;       // 实体名称，如 "Alice"
    PrivKey encPriv;      // 加密私钥
    PubKey  encPub;       // 加密公钥
    PrivKey sigPriv;      // 签名私钥
    PubKey  sigPub;       // 签名公钥

    // 生成密钥：encScheme/sigScheme 可为 SCHEME_RSA 或 SCHEME_ELGAMAL
    void generateKeys(int encScheme, int sigScheme, long bits = 1024, long k = 20);

    std::string encCertID() const { return id + "_ENC"; }
    std::string sigCertID() const { return id + "_SIG"; }

    // 向指定 CA 申请加密用途与签名用途两张证书
    void requestCerts(CA& ca);

    // 对消息签名（返回签名串）
    std::string sign(const std::string& msg) const { return signMessage(sigPriv, msg); }
    // 用加密私钥解密
    NTL::ZZ decrypt(const std::string& ct) const { return decryptMessage(encPriv, ct); }
};

} // namespace Crypto

#endif
