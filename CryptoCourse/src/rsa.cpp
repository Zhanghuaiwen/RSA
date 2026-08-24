// rsa.cpp
#include "rsa.h"
#include "utils.h"
#include <stdexcept>

namespace Crypto {

void RSAKeyGen(RSAKey& key, long bits, long k) {
    if (bits < 32) bits = 32;
    // 生成两个互异的 bits 比特素数
    NTL::ZZ p, q;
    for (;;) {
        NTL::GenPrime(p, bits, k);
        NTL::GenPrime(q, bits, k);
        if (p != q) break;
    }
    key.p = p; key.q = q;
    key.n = p * q;
    NTL::ZZ phi = (p - NTL::ZZ(1)) * (q - NTL::ZZ(1));
    // 选取公钥指数 b（常用 65537），保证与 phi 互素
    key.b = NTL::ZZ(65537);
    if (NTL::GCD(key.b, phi) != NTL::ZZ(1)) {
        // 退而求其次，从小到大找一个互素的奇数
        key.b = NTL::ZZ(3);
        while (NTL::GCD(key.b, phi) != NTL::ZZ(1)) key.b = key.b + NTL::ZZ(2);
    }
    key.a = NTL::InvMod(key.b, phi);   // 私钥指数 d
}

NTL::ZZ RSAEncrypt(const RSAKey& pub, const NTL::ZZ& m) {
    if (m >= pub.n) throw std::runtime_error("RSAEncrypt: message >= n");
    return NTL::PowerMod(m, pub.b, pub.n);
}

NTL::ZZ RSADecrypt(const RSAKey& priv, const NTL::ZZ& c) {
    return NTL::PowerMod(c, priv.a, priv.n);
}

NTL::ZZ RSASign(const RSAKey& priv, const NTL::ZZ& hm) {
    if (hm >= priv.n) throw std::runtime_error("RSASign: hash >= n");
    return NTL::PowerMod(hm, priv.a, priv.n);
}

bool RSAVerify(const RSAKey& pub, const NTL::ZZ& hm, const NTL::ZZ& s) {
    NTL::ZZ t = NTL::PowerMod(s, pub.b, pub.n);
    return t == hm;
}

NTL::ZZ RSAEncodeMessage(const std::string& msg) { return NTL::ZZ::fromBytes(msg); }
std::string RSADecodeMessage(const NTL::ZZ& m) { return m.toBytes(); }

std::string RSAPubKeyToString(const RSAKey& pub) {
    return "RSA n=" + pub.n.to_string() + " b=" + pub.b.to_string();
}
RSAKey RSAPubKeyFromString(const std::string& s) {
    RSAKey k;
    std::vector<std::string> parts = split(trim(s), ' ');
    for (auto& part : parts) {
        std::vector<std::string> kv = split(part, '=');
        if (kv.size() == 2) {
            if (kv[0] == "n") k.n = NTL::ZZ(kv[1]);
            else if (kv[0] == "b") k.b = NTL::ZZ(kv[1]);
        }
    }
    return k;
}
std::string RSAFullKeyToString(const RSAKey& key) {
    return "RSA n=" + key.n.to_string() + " b=" + key.b.to_string() +
           " p=" + key.p.to_string() + " q=" + key.q.to_string() +
           " a=" + key.a.to_string();
}
RSAKey RSAFullKeyFromString(const std::string& s) {
    RSAKey k;
    std::vector<std::string> parts = split(trim(s), ' ');
    for (auto& part : parts) {
        std::vector<std::string> kv = split(part, '=');
        if (kv.size() == 2) {
            if (kv[0] == "n") k.n = NTL::ZZ(kv[1]);
            else if (kv[0] == "b") k.b = NTL::ZZ(kv[1]);
            else if (kv[0] == "p") k.p = NTL::ZZ(kv[1]);
            else if (kv[0] == "q") k.q = NTL::ZZ(kv[1]);
            else if (kv[0] == "a") k.a = NTL::ZZ(kv[1]);
        }
    }
    return k;
}

} // namespace Crypto
