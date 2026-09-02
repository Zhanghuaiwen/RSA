// =====================================================================
// pki.cpp : 证书库、CA 与 PKI 构建的实现。
// =====================================================================

#include "pki.h"
#include "utils.h"
#ifdef _WIN32
#include <windows.h>   // CreateDirectoryA：创建证书输出目录
#else
#include <sys/stat.h>  // mkdir
#endif

// 与官方 NTL 的 NTL_CLIENT 宏一致：展开为下面两行
using namespace std;
using namespace NTL;

namespace Crypto
{

    // ---------------- 证书库 ----------------

    // 全局唯一实例（函数内静态变量实现单例）
    CertRepo &CertRepo::instance()
    {
        static CertRepo repo;
        return repo;
    }

    // 登记证书：ID 非空才入库
    void CertRepo::addCert(const Cert &cert)
    {
        if (!cert.id.empty())
            certs_[cert.id] = cert;
    }

    // 判断某个 ID 是否已有证书
    bool CertRepo::hasCert(const string &id) const
    {
        return certs_.find(id) != certs_.end();
    }

    // 按 ID 取证书；找不到返回空证书（id 为空）
    Cert CertRepo::getCert(const string &id) const
    {
        map<string, Cert>::const_iterator it = certs_.find(id);
        if (it == certs_.end())
            return Cert();
        return it->second;
    }

    // 证书链查询：<root, ..., subject>
    // 从 subject 出发，不断沿 idTA 找到颁发者证书并插入链头，直到自签名根
    vector<Cert> CertRepo::getCertPath(const string &subjectID) const
    {
        vector<Cert> path;
        Cert cur = getCert(subjectID);
        if (cur.id.empty())
            return path;                  // 该 ID 没有证书
        path.push_back(cur);
        int guard = 0;                    // 防御环路
        while (cur.idTA != cur.id)        // 非自签名，继续向上追溯
        {
            Cert issuer = getCert(cur.idTA);
            if (issuer.id.empty())
                break;                    // 颁发者证书缺失（链断裂）
            path.insert(path.begin(), issuer);   // 颁发者插入最前面
            cur = issuer;
            if (++guard > 64)
                break;                    // 安全阀：防止异常死循环
        }
        return path;
    }

    // 清空证书库
    void CertRepo::clear()
    {
        certs_.clear();
    }

    // 把全部证书以 txt 文本写入目录 dir（每张证书为 <ID>.txt）
    void CertRepo::saveAll(const string &dir) const
    {
#ifdef _WIN32
        CreateDirectoryA(dir.c_str(), NULL);   // 目录不存在则创建
#else
        mkdir(dir.c_str(), 0755);
#endif
        // 规范化目录分隔符
        string sep = dir;
        if (!sep.empty() && sep[sep.length() - 1] != '/' && sep[sep.length() - 1] != '\\')
            sep += "/";
        map<string, Cert>::const_iterator it;
        for (it = certs_.begin(); it != certs_.end(); ++it)
            Crypto::writeFile(sep + it->first + ".txt", it->second.toTxt());
    }

    // ---------------- CA ----------------

    // 根 CA：生成密钥，自签名自己的证书，并登记入库
    void CA::initRoot(const string &id, int scheme, long bits, long k)
    {
        this->id = id;
        // (1) 依据选择的签名算法生成密钥对
        if (scheme == SCHEME_RSA)
        {
            RSAKey key;
            RSAKeyGen(key, bits, k);
            priv.scheme = SCHEME_RSA;
            priv.rsa = key;
            pub.scheme = SCHEME_RSA;
            pub.rsa = key;
        }
        else
        {
            ElGamalKey key;
            ElGamalKeyGen(key, bits, k);
            priv.scheme = SCHEME_ELGAMAL;
            priv.elg = key;
            pub.scheme = SCHEME_ELGAMAL;
            pub.elg = key;
        }
        // (2) 自签名：颁发者即自身（flag1 = 自身签名算法，flag2 = 1 签名用途）
        myCert = issueCertificate(id, pub, priv, id, scheme, USE_SIGN);
        CertRepo::instance().addCert(myCert);
    }

    // 下级 CA：生成密钥，由父 CA 签发证书并登记入库
    void CA::initSub(const string &id, const CA &parent, int scheme, long bits, long k)
    {
        this->id = id;
        if (scheme == SCHEME_RSA)
        {
            RSAKey key;
            RSAKeyGen(key, bits, k);
            priv.scheme = SCHEME_RSA;
            priv.rsa = key;
            pub.scheme = SCHEME_RSA;
            pub.rsa = key;
        }
        else
        {
            ElGamalKey key;
            ElGamalKeyGen(key, bits, k);
            priv.scheme = SCHEME_ELGAMAL;
            priv.elg = key;
            pub.scheme = SCHEME_ELGAMAL;
            pub.elg = key;
        }
        // 由父 CA 用其私钥为本 CA 签发证书
        myCert = parent.issueCert(id, pub, scheme, USE_SIGN);
    }

    // 为某个主体签发证书：调用通用颁发函数并登记入库
    Cert CA::issueCert(const string &subjectID, const PubKey &subjectPub, int flag1, int flag2) const
    {
        Cert c = issueCertificate(subjectID, subjectPub, priv, id, flag1, flag2);
        CertRepo::instance().addCert(c);
        return c;
    }

    // ---------------- PKI 顶层构建 ----------------
    // 重新初始化证书库：根 CA 自签名，CA1/CA2 由根 CA 签发，最后把证书落盘
    void PKI::build(int scheme1, int scheme2, long bits, long k)
    {
        CertRepo::instance().clear();                       // 先清空旧证书库
        root.initRoot("CA_root", SCHEME_RSA, bits, k);      // 根 CA（RSA 自签名）
        ca1.initSub("CA1", root, scheme1, bits, k);         // 下级 CA1（由根签发）
        ca2.initSub("CA2", root, scheme2, bits, k);         // 下级 CA2（由根签发）
        CertRepo::instance().saveAll("certs");              // 证书以 txt 落盘
    }

} // namespace Crypto