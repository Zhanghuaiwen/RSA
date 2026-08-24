// pki.cpp
#include "pki.h"
#include "utils.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace Crypto {

CertRepo& CertRepo::instance() {
    static CertRepo repo;
    return repo;
}

void CertRepo::addCert(const Cert& cert) {
    if (!cert.id.empty()) certs_[cert.id] = cert;
}

bool CertRepo::hasCert(const std::string& id) const {
    return certs_.find(id) != certs_.end();
}

Cert CertRepo::getCert(const std::string& id) const {
    auto it = certs_.find(id);
    if (it == certs_.end()) return Cert();
    return it->second;
}

std::vector<Cert> CertRepo::getCertPath(const std::string& subjectID) const {
    std::vector<Cert> path;
    Cert cur = getCert(subjectID);
    if (cur.id.empty()) return path;   // 无此证书
    path.push_back(cur);
    int guard = 0;
    while (cur.idTA != cur.id) {       // 非自签名则向上追溯颁发者
        Cert issuer = getCert(cur.idTA);
        if (issuer.id.empty()) break;   // 颁发者证书缺失
        path.insert(path.begin(), issuer);
        cur = issuer;
        if (++guard > 64) break;        // 防御环路
    }
    return path;
}

void CertRepo::clear() {
    certs_.clear();
}

void CertRepo::saveAll(const std::string& dir) const {
#ifdef _WIN32
    CreateDirectoryA(dir.c_str(), NULL);
#else
    mkdir(dir.c_str(), 0755);
#endif
    std::string sep = dir;
    if (!sep.empty() && sep.back() != '/' && sep.back() != '\\') sep += "/";
    for (const auto& kv : certs_)
        Crypto::writeFile(sep + kv.first + ".txt", kv.second.toTxt());
}

// ---------------- CA ----------------
void CA::initRoot(const std::string& id, int scheme, long bits, long k) {
    this->id = id;
    if (scheme == SCHEME_RSA) {
        RSAKey key; RSAKeyGen(key, bits, k);
        priv.scheme = SCHEME_RSA; priv.rsa = key;
        pub.scheme = SCHEME_RSA; pub.rsa = key;
    } else {
        ElGamalKey key; ElGamalKeyGen(key, bits, k);
        priv.scheme = SCHEME_ELGAMAL; priv.elg = key;
        pub.scheme = SCHEME_ELGAMAL; pub.elg = key;
    }
    // 根 CA 自签名（flag1 = 自身签名算法；flag2 设为签名用途 1）
    myCert = issueCertificate(id, pub, priv, id, scheme, USE_SIGN);
    CertRepo::instance().addCert(myCert);
}

void CA::initSub(const std::string& id, const CA& parent, int scheme, long bits, long k) {
    this->id = id;
    if (scheme == SCHEME_RSA) {
        RSAKey key; RSAKeyGen(key, bits, k);
        priv.scheme = SCHEME_RSA; priv.rsa = key;
        pub.scheme = SCHEME_RSA; pub.rsa = key;
    } else {
        ElGamalKey key; ElGamalKeyGen(key, bits, k);
        priv.scheme = SCHEME_ELGAMAL; priv.elg = key;
        pub.scheme = SCHEME_ELGAMAL; pub.elg = key;
    }
    // 由父 CA 用其私钥为本 CA 签发证书
    myCert = parent.issueCert(id, pub, scheme, USE_SIGN);
}

Cert CA::issueCert(const std::string& subjectID, const PubKey& subjectPub, int flag1, int flag2) const {
    Cert c = issueCertificate(subjectID, subjectPub, priv, id, flag1, flag2);
    CertRepo::instance().addCert(c);
    return c;
}

// ---------------- PKI ----------------
void PKI::build(int scheme1, int scheme2, long bits, long k) {
    CertRepo::instance().clear();
    root.initRoot("CA_root", SCHEME_RSA, bits, k);   // 根 CA 自签名
    ca1.initSub("CA1", root, scheme1, bits, k);     // 由根 CA 签发
    ca2.initSub("CA2", root, scheme2, bits, k);     // 由根 CA 签发
    CertRepo::instance().saveAll("certs");  // 任务书要求：证书以 txt 文本形式保存
}

} // namespace Crypto
