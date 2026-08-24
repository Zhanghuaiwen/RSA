// elgamal.cpp
#include "elgamal.h"
#include "utils.h"
#include <stdexcept>

namespace Crypto {

static void genSafePrime(NTL::ZZ& p, long bits, long k) {
    // p = 2q + 1, p、q 均为素数
    for (;;) {
        NTL::ZZ q;
        NTL::GenPrime(q, bits - 1, k);
        p = q * NTL::ZZ(2) + NTL::ZZ(1);
        if (NTL::ProbPrime(p, k)) return;
    }
}

void ElGamalKeyGen(ElGamalKey& key, long bits, long k) {
    if (bits < 32) bits = 32;
    genSafePrime(key.p, bits, k);
    // 找生成元：p 为安全素数时，满足 g^q != 1 (mod p) 的 g 即阶为 p-1
    NTL::ZZ q = (key.p - NTL::ZZ(1)) / NTL::ZZ(2);
    long cand[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
    for (long c : cand) {
        NTL::ZZ g(c);
        if (NTL::PowerMod(g, q, key.p) != NTL::ZZ(1) && NTL::PowerMod(g, NTL::ZZ(2), key.p) != NTL::ZZ(1)) {
            key.g = g;
            key.x = NTL::RandomPrime(bits - 2 < 2 ? 2 : bits - 2, k); // 私钥 x
            if (key.x >= key.p - NTL::ZZ(1)) key.x = key.x - (key.p - NTL::ZZ(1));
            key.y = NTL::PowerMod(g, key.x, key.p);
            return;
        }
    }
    throw std::runtime_error("ElGamalKeyGen: no generator found");
}

void ElGamalEncrypt(const ElGamalKey& pub, const NTL::ZZ& m, NTL::ZZ& c1, NTL::ZZ& c2) {
    if (m >= pub.p) throw std::runtime_error("ElGamalEncrypt: message >= p");
    NTL::ZZ k = NTL::RandomLen_ZZ(pub.p.NumBits());
    k = k % (pub.p - NTL::ZZ(1));
    if (k == NTL::ZZ(0)) k = NTL::ZZ(1);
    c1 = NTL::PowerMod(pub.g, k, pub.p);
    NTL::ZZ yk = NTL::PowerMod(pub.y, k, pub.p);
    c2 = NTL::MulMod(m, yk, pub.p);
}

NTL::ZZ ElGamalDecrypt(const ElGamalKey& priv, const NTL::ZZ& c1, const NTL::ZZ& c2) {
    NTL::ZZ inv = NTL::PowerMod(c1, priv.p - NTL::ZZ(1) - priv.x, priv.p);
    return NTL::MulMod(c2, inv, priv.p);
}

void ElGamalSign(const ElGamalKey& priv, const NTL::ZZ& hm, NTL::ZZ& r, NTL::ZZ& s) {
    NTL::ZZ pm1 = priv.p - NTL::ZZ(1);
    for (;;) {
        NTL::ZZ k = NTL::RandomLen_ZZ(pm1.NumBits());
        k = k % pm1;
        if (k == NTL::ZZ(0)) continue;
        if (NTL::GCD(k, pm1) != NTL::ZZ(1)) continue;
        r = NTL::PowerMod(priv.g, k, priv.p);
        NTL::ZZ kinv = NTL::InvMod(k, pm1);
        NTL::ZZ t = (hm - NTL::MulMod(priv.x, r, pm1)) % pm1;
        if (t < NTL::ZZ(0)) t = t + pm1;
        s = NTL::MulMod(kinv, t, pm1);
        return;
    }
}

bool ElGamalVerify(const ElGamalKey& pub, const NTL::ZZ& hm, const NTL::ZZ& r, const NTL::ZZ& s) {
    if (r <= NTL::ZZ(0) || r >= pub.p) return false;
    NTL::ZZ left = NTL::PowerMod(pub.g, hm, pub.p);
    NTL::ZZ t1 = NTL::PowerMod(pub.y, r, pub.p);
    NTL::ZZ t2 = NTL::PowerMod(r, s, pub.p);
    NTL::ZZ right = NTL::MulMod(t1, t2, pub.p);
    return left == right;
}

NTL::ZZ ElGamalEncodeMessage(const std::string& msg) { return NTL::ZZ::fromBytes(msg); }
std::string ElGamalDecodeMessage(const NTL::ZZ& m) { return m.toBytes(); }

std::string ElGamalPubKeyToString(const ElGamalKey& pub) {
    return "ELG p=" + pub.p.to_string() + " g=" + pub.g.to_string() + " y=" + pub.y.to_string();
}
ElGamalKey ElGamalPubKeyFromString(const std::string& s) {
    ElGamalKey k;
    std::vector<std::string> parts = split(trim(s), ' ');
    for (auto& part : parts) {
        std::vector<std::string> kv = split(part, '=');
        if (kv.size() == 2) {
            if (kv[0] == "p") k.p = NTL::ZZ(kv[1]);
            else if (kv[0] == "g") k.g = NTL::ZZ(kv[1]);
            else if (kv[0] == "y") k.y = NTL::ZZ(kv[1]);
        }
    }
    return k;
}
std::string ElGamalFullKeyToString(const ElGamalKey& key) {
    return "ELG p=" + key.p.to_string() + " g=" + key.g.to_string() +
           " y=" + key.y.to_string() + " x=" + key.x.to_string();
}
ElGamalKey ElGamalFullKeyFromString(const std::string& s) {
    ElGamalKey k;
    std::vector<std::string> parts = split(trim(s), ' ');
    for (auto& part : parts) {
        std::vector<std::string> kv = split(part, '=');
        if (kv.size() == 2) {
            if (kv[0] == "p") k.p = NTL::ZZ(kv[1]);
            else if (kv[0] == "g") k.g = NTL::ZZ(kv[1]);
            else if (kv[0] == "y") k.y = NTL::ZZ(kv[1]);
            else if (kv[0] == "x") k.x = NTL::ZZ(kv[1]);
        }
    }
    return k;
}

} // namespace Crypto
