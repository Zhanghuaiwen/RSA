// =====================================================================
// elgamal.cpp : ElGamal 加密/解密/签名/验证 以及密钥、消息的格式转换。
// =====================================================================
#include "elgamal.h"
#include "utils.h"
#include <stdexcept>
using namespace std;
using namespace NTL;
namespace Crypto
{

    // ---------------- 安全素数生成 ----------------
    // 生成安全素数 p = 2q + 1（p、q 均为素数）。安全素数在 ElGamal 中
    // 用于简化生成元的选择：此时任意满足 g^q != 1 的 g 都是本原元。
    // ---------------- 子群（Schnorr）方式生成 p、q ----------------
    // 生成素数 p（pbits 比特）与素数 q（qbits 比特），且满足 q 整除 (p-1)（即 p = 1 mod q）。
    // 为什么不用"安全素数 p = 2q + 1"（教材常见写法）：
    //   安全素数要求相邻两个数同时为素数，2048 比特时约 100 万个候选才出一个，
    //   且每个候选 q 都要完整生成一次大素数，非常耗时。
    //   子群方式只需 p 本身是素数（平均约 1400 个候选），快大约三个数量级；
    //   同时生成元 g 的阶是 q 比特大素数（128/256/512 比特），离散对数依然困难。
    static void genSubgroupPrime(ZZ &p, ZZ &q, long pbits, long qbits, long trials)
    {
        GenPrime(q, qbits); // 先生成小素数 q（错误概率 2^-80）
        for (;;)
        {
            ZZ r = RandomLen_ZZ(pbits - qbits - 1); // 随机商 r，保证 p = 1 (mod q)
            p = ZZ(2) * r * q + ZZ(1);              // 构造 p = 2rq + 1
            if (NumBits(p) != pbits)
                continue;        // 位宽不对就换下一个 r
            if (ProbPrime(p, 1)) // 快速过筛：先跑 1 轮过滤绝大多数合数
            {
                if (ProbPrime(p, trials))
                    return; // 再过足够多轮，误判概率 < 2^-96
            }
        }
    }

    // ---------------- 密钥生成 ----------------
    // 步骤：生成 p、q（q | p-1）-> 找阶为 q 的生成元 g -> 随机私钥 x -> 公钥 y = g^x mod p。
    // 任务书记号：公钥 (p, alpha, beta) = (p, g, y)，私钥 a = x。
    void ElGamalKeyGen(ElGamalKey &key, long bits, long k)
    {
        if (bits < 256)
            bits = 256;
        long qbits = bits / 4; // 子群阶的比特数（bits/4）
        if (qbits < 128)
            qbits = 128;                 // 至少 128 比特，保证离散对数安全
        long trials = (k < 40) ? 40 : k; // 素性检测轮数（保证"测足够的次数"）
        ZZ q;
        genSubgroupPrime(key.p, q, bits, qbits, trials);

        // 找阶为 q 的生成元 g：随机取 h，g = h^{(p-1)/q} mod p。
        // 因 q 是素数，g 的阶必整除 q，只可能是 1 或 q；故 g > 1 即阶恰为 q。
        ZZ pm1 = key.p - ZZ(1);
        for (;;)
        {
            ZZ h = RandomLen_ZZ(bits) % pm1;
            if (h <= ZZ(1))
                continue;
            key.g = PowerMod(h, pm1 / q, key.p);
            if (key.g > ZZ(1))
                break;
        }

        // 随机私钥 x 属于 [1, q-1]，取两倍位宽后取模，保证均匀
        key.x = RandomLen_ZZ(2 * qbits) % (q - ZZ(1)) + ZZ(1);
        key.y = PowerMod(key.g, key.x, key.p); // 公钥 y = g^x mod p
    }

    // ---------------- 加密 / 解密 ----------------

    // 加密：随机取 k，c1 = g^k，c2 = m * y^k (mod p)
    void ElGamalEncrypt(const ElGamalKey &pub, const ZZ &m, ZZ &c1, ZZ &c2)
    {
        if (m >= pub.p)
            throw std::runtime_error("ElGamalEncrypt: message >= p");
        ZZ k = RandomLen_ZZ(NumBits(pub.p)); // 每次加密取新的随机数（含随机化）
        k = k % (pub.p - ZZ(1));
        if (k == ZZ(0))
            k = ZZ(1);
        c1 = PowerMod(pub.g, k, pub.p);    // c1 = g^k
        ZZ yk = PowerMod(pub.y, k, pub.p); // y^k
        c2 = MulMod(m, yk, pub.p);         // c2 = m * y^k
    }

    // 解密：c1^x = g^{kx}，故 m = c2 * (c1^x)^{-1} (mod p)
    ZZ ElGamalDecrypt(const ElGamalKey &priv, const ZZ &c1, const ZZ &c2)
    {
        // 用费马小定理 c1^{-x} = c1^(p-1-x) 计算，避免求逆
        ZZ inv = PowerMod(c1, priv.p - ZZ(1) - priv.x, priv.p);
        return MulMod(c2, inv, priv.p);
    }

    // ---------------- 签名 / 验证 ----------------

    // 签名：(r, s) = (g^k, k^{-1}(H(m) - x*r) mod (p-1))
    void ElGamalSign(const ElGamalKey &priv, const ZZ &hm, ZZ &r, ZZ &s)
    {
        ZZ pm1 = priv.p - ZZ(1);
        for (;;)
        {
            // 取与 p-1 互素的随机 k
            ZZ k = RandomLen_ZZ(NumBits(pm1));
            k = k % pm1;
            if (k == ZZ(0))
                continue;
            if (GCD(k, pm1) != ZZ(1))
                continue;
            r = PowerMod(priv.g, k, priv.p);            // r = g^k
            ZZ kinv = InvMod(k, pm1);                   // k^{-1} mod (p-1)
            ZZ t = (hm - MulMod(priv.x, r, pm1)) % pm1; // H(m) - x*r mod (p-1)
            if (t < ZZ(0))
                t = t + pm1;          // 保证非负
            s = MulMod(kinv, t, pm1); // s = k^{-1} * t
            return;
        }
    }

    // 验证：由签名方程 g^{H(m)} = y^r * r^s (mod p) 判真伪
    bool ElGamalVerify(const ElGamalKey &pub, const ZZ &hm, const ZZ &r, const ZZ &s)
    {
        if (r <= ZZ(0) || r >= pub.p)
            return false;                     // 越界签名不可能有效
        ZZ left = PowerMod(pub.g, hm, pub.p); // g^{H(m)}
        ZZ t1 = PowerMod(pub.y, r, pub.p);    // y^r
        ZZ t2 = PowerMod(r, s, pub.p);        // r^s
        ZZ right = MulMod(t1, t2, pub.p);     // y^r * r^s
        return left == right;
    }

    // ---------------- 消息 <-> 整数 ----------------
    ZZ ElGamalEncodeMessage(const string &msg) { return zzfrombytes(msg); }
    string ElGamalDecodeMessage(const ZZ &m) { return zztobytes(m); }

    // ---------------- 密钥 <-> 字符串 ----------------
    // 格式形如 "ELG p=... g=... y=..."，供证书的 VER 字段与密钥文件使用
    string ElGamalPubKeyToString(const ElGamalKey &pub)
    {
        return "ELG p=" + ztostr(pub.p) + " g=" + ztostr(pub.g) + " y=" + ztostr(pub.y);
    }
    ElGamalKey ElGamalPubKeyFromString(const string &s)
    {
        ElGamalKey k;
        vector<string> parts = split(trim(s), ' ');
        for (unsigned i = 0; i < parts.size(); i++)
        {
            vector<string> kv = split(parts[i], '=');
            if (kv.size() == 2)
            {
                if (kv[0] == "p")
                    k.p = strtoz(kv[1]);
                else if (kv[0] == "g")
                    k.g = strtoz(kv[1]);
                else if (kv[0] == "y")
                    k.y = strtoz(kv[1]);
            }
        }
        return k;
    }

    // 私钥全部分量输出（含 x），用于本地保存
    string ElGamalFullKeyToString(const ElGamalKey &key)
    {
        return "ELG p=" + ztostr(key.p) + " g=" + ztostr(key.g) +
               " y=" + ztostr(key.y) + " x=" + ztostr(key.x);
    }

    ElGamalKey ElGamalFullKeyFromString(const string &s)
    {
        ElGamalKey k;
        vector<string> parts = split(trim(s), ' ');
        for (unsigned i = 0; i < parts.size(); i++)
        {
            vector<string> kv = split(parts[i], '=');
            if (kv.size() == 2)
            {
                if (kv[0] == "p")
                    k.p = strtoz(kv[1]);
                else if (kv[0] == "g")
                    k.g = strtoz(kv[1]);
                else if (kv[0] == "y")
                    k.y = strtoz(kv[1]);
                else if (kv[0] == "x")
                    k.x = strtoz(kv[1]);
            }
        }
        return k;
    }
}