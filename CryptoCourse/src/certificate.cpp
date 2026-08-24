// certificate.cpp
#include "certificate.h"
#include "utils.h"
#include <sstream>

namespace Crypto {

PubKey parsePubKey(const std::string& ver) {
    PubKey pk;
    std::string s = trim(ver);
    if (s.compare(0, 3, "RSA") == 0) {
        pk.scheme = SCHEME_RSA;
        pk.rsa = RSAPubKeyFromString(s);
    } else if (s.compare(0, 3, "ELG") == 0) {
        pk.scheme = SCHEME_ELGAMAL;
        pk.elg = ElGamalPubKeyFromString(s);
    } else {
        throw std::runtime_error("parsePubKey: unknown scheme");
    }
    return pk;
}

std::string pubKeyToString(const PubKey& pk) {
    if (pk.scheme == SCHEME_RSA) return RSAPubKeyToString(pk.rsa);
    return ElGamalPubKeyToString(pk.elg);
}

std::string signHash(const PrivKey& priv, const NTL::ZZ& hm) {
    if (priv.scheme == SCHEME_RSA) {
        return RSASign(priv.rsa, hm).to_string();
    } else {
        NTL::ZZ r, s;
        ElGamalSign(priv.elg, hm, r, s);
        return "r=" + r.to_string() + " s=" + s.to_string();
    }
}

bool verifyHash(const PubKey& pub, const NTL::ZZ& hm, const std::string& sigStr) {
    if (pub.scheme == SCHEME_RSA) {
        NTL::ZZ sig(sigStr);
        return RSAVerify(pub.rsa, hm, sig);
    } else {
        // 解析 "r=... s=..."
        std::string body = trim(sigStr);
        size_t pos = body.find("r=");
        size_t pos2 = body.find("s=", pos + 1);
        if (pos == std::string::npos || pos2 == std::string::npos) return false;
        std::string rs = trim(body.substr(pos + 2, pos2 - pos - 2));
        std::string ss = trim(body.substr(pos2 + 2));
        NTL::ZZ r(rs), s(ss);
        return ElGamalVerify(pub.elg, hm, r, s);
    }
}

std::string Cert::toTxt() const {
    std::ostringstream os;
    os << "ID=" << id << "\n";
    os << "VER=" << ver << "\n";
    os << "SIG=" << sig << "\n";
    os << "ID_TA=" << idTA << "\n";
    os << "FLAG1=" << flag1 << "\n";
    os << "FLAG2=" << flag2 << "\n";
    return os.str();
}

Cert Cert::fromTxt(const std::string& txt) {
    Cert c;
    std::istringstream is(txt);
    std::string line;
    while (std::getline(is, line)) {
        line = trim(line);
        if (line.empty()) continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (key == "ID") c.id = val;
        else if (key == "VER") c.ver = val;
        else if (key == "SIG") c.sig = val;
        else if (key == "ID_TA") c.idTA = val;
        else if (key == "FLAG1") c.flag1 = std::stoi(val);
        else if (key == "FLAG2") c.flag2 = std::stoi(val);
    }
    return c;
}

Cert issueCertificate(const std::string& subjectID, const PubKey& subjectPub,
                      const PrivKey& taPriv, const std::string& taID,
                      int flag1, int flag2) {
    Cert c;
    c.id = subjectID;
    c.ver = pubKeyToString(subjectPub);
    c.idTA = taID;
    c.flag1 = flag1;
    c.flag2 = flag2;
    NTL::ZZ hm = sha256ZZ(c.dataForSign());
    c.sig = signHash(taPriv, hm);
    return c;
}

bool verifyCertificate(const Cert& cert, const PubKey& issuerPub) {
    NTL::ZZ hm = sha256ZZ(cert.dataForSign());
    return verifyHash(issuerPub, hm, cert.sig);
}

bool verifyCertPath(const std::vector<Cert>& path) {
    if (path.empty()) return false;
    for (size_t i = 0; i < path.size(); i++) {
        PubKey issuer;
        if (i == 0) issuer = parsePubKey(path[0].ver);   // 根 CA 自签名
        else issuer = parsePubKey(path[i - 1].ver);
        if (!verifyCertificate(path[i], issuer)) return false;
    }
    return true;
}

// 将任意长度的明文分块加密（每块小于模数），密文各块以 '|' 分隔
std::string encryptMessage(const PubKey& pub, const NTL::ZZ& m) {
    std::string bytes = m.toBytes();
    if (pub.scheme == SCHEME_RSA) {
        long nbytes = pub.rsa.n.NumBytes();
        long block = nbytes - 1; if (block < 1) block = 1;
        std::string out;
        for (size_t off = 0; off < bytes.size(); off += (size_t)block) {
            std::string chunk = bytes.substr(off, (size_t)block);
            NTL::ZZ z = NTL::ZZ::fromBytes(chunk);
            NTL::ZZ c = RSAEncrypt(pub.rsa, z);
            if (!out.empty()) out.push_back('|');
            out += c.to_string();
        }
        return "RSA " + out;
    } else {
        long nbytes = pub.elg.p.NumBytes();
        long block = nbytes - 1; if (block < 1) block = 1;
        std::string out;
        for (size_t off = 0; off < bytes.size(); off += (size_t)block) {
            std::string chunk = bytes.substr(off, (size_t)block);
            NTL::ZZ z = NTL::ZZ::fromBytes(chunk);
            NTL::ZZ c1, c2;
            ElGamalEncrypt(pub.elg, z, c1, c2);
            if (!out.empty()) out.push_back('|');
            out += "c1=" + c1.to_string() + " c2=" + c2.to_string();
        }
        return "ELG " + out;
    }
}

NTL::ZZ decryptMessage(const PrivKey& priv, const std::string& ct) {
    std::string s = trim(ct);
    if (s.compare(0, 3, "RSA") == 0) {
        std::string body = trim(s.substr(3));
        std::vector<std::string> blocks = split(body, '|');
        std::string bytes;
        for (auto& blk : blocks) {
            NTL::ZZ c(trim(blk));
            NTL::ZZ m = RSADecrypt(priv.rsa, c);
            bytes += m.toBytes();
        }
        return NTL::ZZ::fromBytes(bytes);
    } else if (s.compare(0, 3, "ELG") == 0) {
        std::string body = trim(s.substr(3));
        std::vector<std::string> blocks = split(body, '|');
        std::string bytes;
        for (auto& blk : blocks) {
            std::vector<std::string> parts = split(trim(blk), ' ');
            NTL::ZZ c1, c2;
            for (auto& p : parts) {
                std::vector<std::string> kv = split(p, '=');
                if (kv.size() == 2) {
                    if (kv[0] == "c1") c1 = NTL::ZZ(kv[1]);
                    else if (kv[0] == "c2") c2 = NTL::ZZ(kv[1]);
                }
            }
            NTL::ZZ m = ElGamalDecrypt(priv.elg, c1, c2);
            bytes += m.toBytes();
        }
        return NTL::ZZ::fromBytes(bytes);
    }
    throw std::runtime_error("decryptMessage: unknown scheme");
}

std::string signMessage(const PrivKey& priv, const std::string& msg) {
    return signHash(priv, sha256ZZ(msg));
}

bool verifyMessage(const PubKey& pub, const std::string& msg, const std::string& sigStr) {
    return verifyHash(pub, sha256ZZ(msg), sigStr);
}

} // namespace Crypto
