// pki.h : 简易 PKI 系统——证书库(CertRepo)与各级 CA（根 CA、下级 CA）。
#ifndef PKI_H
#define PKI_H

#include "certificate.h"
#include <vector>
#include <map>
#include <string>

namespace Crypto {

// 证书库：存储本 PKI 系统中所有证书，并支持按所有者 ID 查询证书链
class CertRepo {
public:
    static CertRepo& instance();

    // 仅存储 CA 发来的证书（任何证书均可登记，查询时按 ID 索引）
    void addCert(const Cert& cert);
    bool hasCert(const std::string& id) const;
    Cert getCert(const std::string& id) const;

    // 返回从根 CA 到 subject 的证书链：<root, ..., subject>
    // 找不到则返回空链
    std::vector<Cert> getCertPath(const std::string& subjectID) const;

    void clear();
    size_t size() const { return certs_.size(); }
    // 将证书库全部证书以 txt 形式保存到目录（任务书要求证书以 txt 文本保存）
    void saveAll(const std::string& dir) const;

private:
    CertRepo() {}
    CertRepo(const CertRepo&) = delete;
    void operator=(const CertRepo&) = delete;
    std::map<std::string, Cert> certs_;
};

// 证书颁发机构 CA（根 CA 或下级 CA）
struct CA {
    std::string id;
    PrivKey priv;
    PubKey pub;
    Cert myCert;   // 自己的证书（根 CA 自签名，下级 CA 由上级签发）

    // 根 CA：生成密钥并自签名，存入证书库
    void initRoot(const std::string& id, int scheme, long bits = 1024, long k = 20);
    // 下级 CA：生成密钥，并请求由 parent CA 签发证书，存入证书库
    void initSub(const std::string& id, const CA& parent, int scheme, long bits = 1024, long k = 20);
    // 为某个主体（用户或其他 CA）签发证书并存入证书库
    Cert issueCert(const std::string& subjectID, const PubKey& subjectPub, int flag1, int flag2) const;
};

// 顶层 PKI 构建：根 CA + 两个下级 CA
struct PKI {
    CA root;
    CA ca1;
    CA ca2;
    void build(int scheme1 = SCHEME_RSA, int scheme2 = SCHEME_RSA, long bits = 1024, long k = 20);
};

} // namespace Crypto

#endif
