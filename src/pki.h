// =====================================================================
// pki.h : 简易 PKI（公钥基础设施）——证书库(CertRepo)与各级 CA。
//
//   结构（证书信任模型）：
//       CA_root（根 CA，自签名）
//         ├── CA1（下级 CA，由根 CA 签发）
//         │     └── 用户证书（如 Alice_ENC / Alice_SIG）
//         └── CA2（下级 CA，由根 CA 签发）
//               └── 用户证书（如 Bob_ENC / Bob_SIG）
//   任何用户只要信任根 CA 的公钥，就能沿证书链验证其他用户的证书。
// =====================================================================
#ifndef PKI_H
#define PKI_H

#include "certificate.h"
#include <vector>
#include <map>
#include <string>

namespace Crypto {

// ---------- 证书库 ----------
// 单例：存储本 PKI 系统中的全部证书，支持按持有者 ID 查询、
// 获取到根的证书链，并把证书以 txt 文本落盘（任务书要求）。
class CertRepo {
public:
    // 取得全局唯一的证书库实例（含根 CA 与各级证书）
    static CertRepo& instance();

    // 登记一张证书（按 ID 覆盖旧条目）
    void addCert(const Cert& cert);
    bool hasCert(const std::string& id) const;   // 该 ID 是否有证书
    Cert getCert(const std::string& id) const;   // 按 ID 取证书（无则返回空）

    // 返回从根 CA 到 subject 的证书链 <root, ..., subject>
    // 沿 cert.idTA 向上回溯；找不到或无证书链返回空链
    std::vector<Cert> getCertPath(const std::string& subjectID) const;

    void clear();                               // 清空证书库（重建 PKI 时用）
    unsigned size() const { return (unsigned)certs_.size(); }  // 证书总数
    // 把证书库中全部证书以 txt 文本保存到目录 dir（每张证书一个文件）
    void saveAll(const std::string& dir) const;

private:
    CertRepo() {}                               // 禁止外部直接构造（单例）
    CertRepo(const CertRepo&);                  // 禁止复制（不实现）
    CertRepo& operator=(const CertRepo&);       // 禁止赋值（不实现）
    std::map<std::string, Cert> certs_;         // ID -> 证书
};

// ---------- 证书颁发机构 CA ----------
// 根 CA 与下级 CA 使用同一结构：根 CA 自己签发（自签名），
// 下级 CA 的证书由父 CA 签发。
struct CA {
    std::string id;        // CA 标识，如 "CA_root" / "CA1" / "CA2"
    PrivKey priv;          // CA 私钥（签名用，保密）
    PubKey pub;            // CA 公钥（公开）
    Cert myCert;           // CA 自己的证书（根 CA 自签名；下级 CA 由上级签发）

    // 初始化根 CA：生成密钥并自签名，把自己的证书存入证书库
    void initRoot(const std::string& id, int scheme, long bits = 1024, long k = 20);
    // 初始化下级 CA：生成密钥，并请求父 CA 为其签发证书，存入证书库
    void initSub(const std::string& id, const CA& parent, int scheme, long bits = 1024, long k = 20);
    // 为某个主体（用户或其他 CA）签发证书并存入证书库，
    // flag1 为签名算法（0=RSA,1=ElGamal），flag2 为用途（0=加密,1=签名）
    Cert issueCert(const std::string& subjectID, const PubKey& subjectPub, int flag1, int flag2) const;
};

// ---------- 顶层 PKI 构建 ----------
// scheme1/scheme2 分别为 CA1、CA2 的签名算法，bits 为素数比特数
struct PKI {
    CA root;               // 根 CA
    CA ca1;                // 下级 CA1
    CA ca2;                // 下级 CA2
    void build(int scheme1 = SCHEME_RSA, int scheme2 = SCHEME_RSA, long bits = 1024, long k = 20);
};

} // namespace Crypto

#endif