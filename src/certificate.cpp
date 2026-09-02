// =====================================================================
// certificate.cpp : 简单证书方案（教材 9.3）与方案无关的加解密/签名封装。
//
//   证书格式（txt）：
//     ID    = 证书持有者标识（如 "Alice_ENC"）
//     VER   = 持有者公钥字符串（"RSA n=... b=..." 或 "ELG p=... g=... y=..."）
//     SIG   = 颁发者(TA)用其私钥对 (ID|VER) 的 SHA-256 摘要的签名
//     ID_TA = 颁发者标识（根 CA 自签时等于自身 ID）
//     FLAG1 = 签名算法：0=RSA，1=ElGamal
//     FLAG2 = 用途：0=加密，1=签名
//   证书验证：用颁发者公钥验证 (ID|VER) 的摘要与 SIG 是否匹配。
// =====================================================================

#include "certificate.h"
#include "utils.h"
#include <sstream>
#include <cstdlib>

// 与官方 NTL 的 NTL_CLIENT 宏一致：展开为下面两行
using namespace std;
using namespace NTL;
namespace Crypto
{

    // 由公钥字符串解析出统一公钥结构（识别 "RSA" / "ELG" 前缀）
    PubKey parsePubKey(const string &ver)
    {
        PubKey pk;
        string s = trim(ver);
        if (s.compare(0, 3, "RSA") == 0)
        {
            pk.scheme = SCHEME_RSA; // flag1：签名算法为 RSA
            pk.rsa = RSAPubKeyFromString(s);
        }
        else if (s.compare(0, 3, "ELG") == 0)
        {
            pk.scheme = SCHEME_ELGAMAL; // flag1：签名算法为 ElGamal
            pk.elg = ElGamalPubKeyFromString(s);
        }
        else
        {
            throw std::runtime_error("parsePubKey: unknown scheme");
        }
        return pk;
    }

    // 统一公钥转字符串（供 VER 字段存储）
    string pubKeyToString(const PubKey &pk)
    {
        if (pk.scheme == SCHEME_RSA)
            return RSAPubKeyToString(pk.rsa);
        return ElGamalPubKeyToString(pk.elg);
    }

    // 用私钥对摘要 hm 签名，返回签名字符串
    // （RSA 返回一个大整数；ElGamal 返回 "r=... s=..."，两个算法可互换）
    string signHash(const PrivKey &priv, const ZZ &hm)
    {
        if (priv.scheme == SCHEME_RSA)
        {
            return ztostr(RSASign(priv.rsa, hm));
        }
        else
        {
            ZZ r, s;
            ElGamalSign(priv.elg, hm, r, s);
            return "r=" + ztostr(r) + " s=" + ztostr(s);
        }
    }

    // 用公钥验证签名字符串是否匹配摘要 hm
    bool verifyHash(const PubKey &pub, const ZZ &hm, const string &sigStr)
    {
        if (pub.scheme == SCHEME_RSA)
        {
            ZZ sig = strtoz(sigStr);
            return RSAVerify(pub.rsa, hm, sig);
        }
        else
        {
            // 解析 ElGamal 签名串 "r=... s=..."
            string body = trim(sigStr);
            long pos = (long)body.find("r=");
            long pos2 = (long)body.find("s=", pos + 1);
            if (pos < 0 || pos2 < 0)
                return false;
            string rs = trim(body.substr(pos + 2, (unsigned)(pos2 - pos - 2)));
            string ss = trim(body.substr(pos2 + 2));
            ZZ r = strtoz(rs), s = strtoz(ss);
            return ElGamalVerify(pub.elg, hm, r, s);
        }
    }

    // 证书序列化为 txt 文本（每行一个字段，任务书要求证书以 txt 保存）
    string Cert::toTxt() const
    {
        ostringstream os;
        os << "ID=" << id << "\n";
        os << "VER=" << ver << "\n";
        os << "SIG=" << sig << "\n";
        os << "ID_TA=" << idTA << "\n";
        os << "FLAG1=" << flag1 << "\n";
        os << "FLAG2=" << flag2 << "\n";
        return os.str();
    }

    // 由 txt 文本还原证书
    Cert Cert::fromTxt(const string &txt)
    {
        Cert c;
        istringstream is(txt);
        string line;
        while (getline(is, line))
        {
            line = trim(line);
            if (line.empty())
                continue;
            long eq = (long)line.find('=');
            if (eq < 0)
                continue;
            string key = trim(line.substr(0, (unsigned)eq));
            string val = trim(line.substr((unsigned)eq + 1));
            if (key == "ID")
                c.id = val;
            else if (key == "VER")
                c.ver = val;
            else if (key == "SIG")
                c.sig = val;
            else if (key == "ID_TA")
                c.idTA = val;
            else if (key == "FLAG1")
                c.flag1 = atoi(val.c_str());
            else if (key == "FLAG2")
                c.flag2 = atoi(val.c_str());
        }
        return c;
    }

    // 证书颁发：TA 用自己的私钥为 subjectID 的公钥 ver 签名，生成证书
    // 签名内容为 dataForSign() = "ID|VER" 的 SHA-256 摘要
    Cert issueCertificate(const string &subjectID, const PubKey &subjectPub,
                          const PrivKey &taPriv, const string &taID,
                          int flag1, int flag2)
    {
        Cert c;
        c.id = subjectID;
        c.ver = pubKeyToString(subjectPub); // 主体公钥字符串
        c.idTA = taID;                      // 颁发者标识
        c.flag1 = flag1;                    // 签名算法标志
        c.flag2 = flag2;                    // 用途标志
        ZZ hm = sha256ZZ(c.dataForSign());  // 对 (ID|VER) 计算摘要
        c.sig = signHash(taPriv, hm);       // 颁发者用私钥签名
        return c;
    }

    // 证书验证：用颁发者公钥重新计算 (ID|VER) 的摘要并校验签名
    bool verifyCertificate(const Cert &cert, const PubKey &issuerPub)
    {
        ZZ hm = sha256ZZ(cert.dataForSign());
        return verifyHash(issuerPub, hm, cert.sig);
    }

    // 证书链验证：path = [root, ..., subject]
    // 由根向下逐张验证，每张证书都必须由上一张证书的持有者正确签发
    bool verifyCertPath(const vector<Cert> &path)
    {
        if (path.empty())
            return false;
        for (int i = 0; i < (int)path.size(); i++)
        {
            PubKey issuer;
            if (i == 0)
                issuer = parsePubKey(path[0].ver); // 根 CA 证书自签名验证
            else
                issuer = parsePubKey(path[i - 1].ver); // 用上一级 CA 的公钥
            if (!verifyCertificate(path[i], issuer))
                return false;
        }
        return true;
    }

    // 把任意长度的明文整数 m 分块加密（每块 < 模数），密文以 '|' 分隔
    // 返回串首带方案前缀 "RSA " 或 "ELG "，解密时据此选择算法
    string encryptMessage(const PubKey &pub, const ZZ &m)
    {
        string bytes = zztobytes(m);
        if (pub.scheme == SCHEME_RSA)
        {
            long nbytes = NumBytes(pub.rsa.n); // 每个密文块对应一个 RSA 加密
            long block = nbytes - 1;           // 块长取模数字节数减 1
            if (block < 1)
                block = 1;
            string out;
            for (unsigned off = 0; off < bytes.length(); off += (unsigned)block)
            {
                string chunk = bytes.substr(off, (unsigned)block);
                ZZ z = zzfrombytes(chunk);
                ZZ c = RSAEncrypt(pub.rsa, z);
                if (!out.empty())
                    out.push_back('|');
                out += ztostr(c);
            }
            return "RSA " + out;
        }
        else // ElGamal：每块密文为 "c1=... c2=..."
        {
            long nbytes = NumBytes(pub.elg.p);
            long block = nbytes - 1;
            if (block < 1)
                block = 1;
            string out;
            for (unsigned off = 0; off < bytes.length(); off += (unsigned)block)
            {
                string chunk = bytes.substr(off, (unsigned)block);
                ZZ z = zzfrombytes(chunk);
                ZZ c1, c2;
                ElGamalEncrypt(pub.elg, z, c1, c2);
                if (!out.empty())
                    out.push_back('|');
                out += "c1=" + ztostr(c1) + " c2=" + ztostr(c2);
            }
            return "ELG " + out;
        }
    }

    // 与 encryptMessage 对应的解密：按前缀识别算法、按 '|' 分割逐块解密，
    // 再把各块明文字节拼接后转成整数返回
    ZZ decryptMessage(const PrivKey &priv, const string &ct)
    {
        string s = trim(ct);
        if (s.compare(0, 3, "RSA") == 0)
        {
            string body = trim(s.substr(3));
            vector<string> blocks = split(body, '|');
            string bytes;
            for (unsigned i = 0; i < blocks.size(); i++)
            {
                ZZ c = strtoz(trim(blocks[i]));
                ZZ m = RSADecrypt(priv.rsa, c);
                bytes += zztobytes(m);
            }
            return zzfrombytes(bytes);
        }
        else if (s.compare(0, 3, "ELG") == 0)
        {
            string body = trim(s.substr(3));
            vector<string> blocks = split(body, '|');
            string bytes;
            for (unsigned i = 0; i < blocks.size(); i++)
            {
                vector<string> parts = split(trim(blocks[i]), ' ');
                ZZ c1, c2;
                for (unsigned j = 0; j < parts.size(); j++)
                {
                    vector<string> kv = split(parts[j], '=');
                    if (kv.size() == 2)
                    {
                        if (kv[0] == "c1")
                            c1 = strtoz(kv[1]);
                        else if (kv[0] == "c2")
                            c2 = strtoz(kv[1]);
                    }
                }
                ZZ m = ElGamalDecrypt(priv.elg, c1, c2);
                bytes += zztobytes(m);
            }
            return zzfrombytes(bytes);
        }
        throw std::runtime_error("decryptMessage: unknown scheme");
    }

    // 对消息做 SHA-256 摘要后签名（签名对象是摘要，而非整个明文）
    string signMessage(const PrivKey &priv, const string &msg)
    {
        return signHash(priv, sha256ZZ(msg));
    }

    // 验证消息签名：计算消息摘要并验证签名串
    bool verifyMessage(const PubKey &pub, const string &msg, const string &sigStr)
    {
        return verifyHash(pub, sha256ZZ(msg), sigStr);
    }

} // namespace Crypto