// =====================================================================
// rsa.cpp : RSA 加密/解密/签名/验证 以及密钥、消息的格式转换。
// =====================================================================

#include "rsa.h"
#include "utils.h"
#include <stdexcept>

// 与官方 NTL 的 NTL_CLIENT 宏一致：展开为下面两行。
// 之后即可直接书写 string / vector / ZZ / PowerMod 等名字。
using namespace std;
using namespace NTL;

namespace Crypto {

// ---------------- 密钥生成 ----------------
// 步骤：生成两个互异的 bits 比特素数 p,q -> n=p*q -> phi=(p-1)(q-1)
//      -> 取公钥指数 e=65537（保证与 phi 互素）-> d=e^{-1} mod phi
void RSAKeyGen(RSAKey& key, long bits, long k) {
    if (bits < 32) bits = 32;
    if (k < 3) k = 20;                                    // k 为 Miller-Rabin 轮数下限
    // (1) 生成两个互异的 bits 比特大素数
    //     （官方 NTL 的 GenPrime(x, n, err) 第 3 参是错误概率比特数，err=80 即 2^-80，
    //       已远超我们此前自定义实现按“轮数”取的强度）
    ZZ p, q;
    for (;;) {
        GenPrime(p, bits);
        GenPrime(q, bits);
        if (p != q) break;
    }
    // (2) 计算模数与欧拉函数
    key.p = p; key.q = q;
    key.n = p * q;
    ZZ phi = (p - ZZ(1)) * (q - ZZ(1));
    // (3) 选取公钥指数 b（常用 65537），若与 phi 不互素则从小到大找奇数
    key.b = ZZ(65537);
    if (GCD(key.b, phi) != ZZ(1)) {
        key.b = ZZ(3);
        while (GCD(key.b, phi) != ZZ(1)) key.b = key.b + ZZ(2);
    }
    // (4) 私钥指数 a = b^{-1} mod phi
    key.a = InvMod(key.b, phi);
}

// ---------------- 加密 / 解密 ----------------

// 加密：c = m^b mod n
ZZ RSAEncrypt(const RSAKey& pub, const ZZ& m) {
    if (m >= pub.n) throw std::runtime_error("RSAEncrypt: message >= n");
    return PowerMod(m, pub.b, pub.n);
}

// 解密：m = c^a mod n（由 m^{e*d} = m^{1+k*phi} mod n 保证）
ZZ RSADecrypt(const RSAKey& priv, const ZZ& c) {
    return PowerMod(c, priv.a, priv.n);
}

// ---------------- 签名 / 验证 ----------------
// 数字签名的含义：用私钥对“消息摘要”做一次解密运算，只有私钥持有者能生成，
// 而任何人都能用公钥验证，从而实现身份认证 + 完整性。

// 签名：s = hm^a mod n
ZZ RSASign(const RSAKey& priv, const ZZ& hm) {
    if (hm >= priv.n) throw std::runtime_error("RSASign: hash >= n");
    return PowerMod(hm, priv.a, priv.n);
}

// 验证：计算 s^b mod n，若等于摘要 hm 则签名有效
bool RSAVerify(const RSAKey& pub, const ZZ& hm, const ZZ& s) {
    ZZ t = PowerMod(s, pub.b, pub.n);
    return t == hm;
}

// ---------------- 消息 <-> 整数 ----------------
// 明文（字节串）被当作 256 进制数转成整数 m；解密后反向还原
ZZ RSAEncodeMessage(const string& msg) { return zzfrombytes(msg); }
string RSADecodeMessage(const ZZ& m) { return zztobytes(m); }

// ---------------- 密钥 <-> 字符串 ----------------
// 格式形如 "RSA n=... b=..."，供证书的 VER 字段与密钥文件使用
string RSAPubKeyToString(const RSAKey& pub) {
    return "RSA n=" + ztostr(pub.n) + " b=" + ztostr(pub.b);
}

// 从 "key=value" 的字段串解析出 n、b
RSAKey RSAPubKeyFromString(const string& s) {
    RSAKey k;
    vector<string> parts = split(trim(s), ' ');
    for (unsigned i = 0; i < parts.size(); i++) {
        vector<string> kv = split(parts[i], '=');
        if (kv.size() == 2) {
            if (kv[0] == "n") k.n = strtoz(kv[1]);
            else if (kv[0] == "b") k.b = strtoz(kv[1]);
        }
    }
    return k;
}

// 私钥全部分量输出（含 p,q,a），用于本地保存
string RSAFullKeyToString(const RSAKey& key) {
    return "RSA n=" + ztostr(key.n) + " b=" + ztostr(key.b) +
           " p=" + ztostr(key.p) + " q=" + ztostr(key.q) +
           " a=" + ztostr(key.a);
}

RSAKey RSAFullKeyFromString(const string& s) {
    RSAKey k;
    vector<string> parts = split(trim(s), ' ');
    for (unsigned i = 0; i < parts.size(); i++) {
        vector<string> kv = split(parts[i], '=');
        if (kv.size() == 2) {
            if (kv[0] == "n") k.n = strtoz(kv[1]);
            else if (kv[0] == "b") k.b = strtoz(kv[1]);
            else if (kv[0] == "p") k.p = strtoz(kv[1]);
            else if (kv[0] == "q") k.q = strtoz(kv[1]);
            else if (kv[0] == "a") k.a = strtoz(kv[1]);
        }
    }
    return k;
}

} // namespace Crypto