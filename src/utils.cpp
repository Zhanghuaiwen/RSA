// =====================================================================
// utils.cpp
//   公共工具函数的实现：SHA-256 哈希、字符串工具、文件读写。
// =====================================================================

#include "utils.h"
#include <cstdint>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <ctime>

// 与官方 NTL 的 NTL_CLIENT 宏一致：展开为下面两行
using namespace std;
using namespace NTL;

namespace Crypto {

// ---------------- SHA-256 ----------------
// 以下 6 个函数是 SHA-256 的六个基本运算元（轮流、选择、多数、三个折叠函数）。

// 循环右移 n 位
static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

// Ch(x, y, z) = (x & y) ^ (~x & z)：按 x 选择 y 或 z
static uint32_t shaCh(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
// Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)：三个位取多数
static uint32_t shaMaj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
// 大折叠函数（用于压缩主循环中 a、e 的更新）
static uint32_t shaSigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t shaSigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
// 小折叠函数（用于调度 16..63 号消息字）
static uint32_t shaSig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t shaSig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// SHA-256 的 64 个轮常数 K（前 64 个素数的立方根小数部分）
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// SHA-256 主函数：返回 32 字节原始摘要
string sha256(const string& msg) {
    // 初始哈希值 H0..H7（前 8 个素数的平方根小数部分）
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    // 预处理 1：把消息复制为字节序列
    vector<uint8_t> m((uint8_t*)msg.data(), (uint8_t*)msg.data() + msg.size());
    uint64_t ml = (uint64_t)msg.size() * 8;    // 消息总比特数（后面补 64 位）

    // 预处理 2：先补一个 1（0x80），再补 0，直到长度 mod 64 == 56
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0x00);
    // 预处理 3：最后补上 8 字节的消息长度（大端）
    for (int i = 7; i >= 0; i--) m.push_back((uint8_t)(ml >> (i * 8)));

    // 按 64 字节一块处理
    for (unsigned off = 0; off < m.size(); off += 64) {
        // 消息调度数组 W[0..63]
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {          // W[0..15] 直接来自本块（大端）
            w[i] = ((uint32_t)m[off+4*i] << 24) | ((uint32_t)m[off+4*i+1] << 16) |
                   ((uint32_t)m[off+4*i+2] << 8) | (uint32_t)m[off+4*i+3];
        }
        for (int i = 16; i < 64; i++) {         // W[16..63] 由前 16 个字递推
            w[i] = shaSig1(w[i-2]) + w[i-7] + shaSig0(w[i-15]) + w[i-16];
        }
        // 工作变量 a..h 装入当前哈希值
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        // 64 轮压缩
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + shaSigma1(e) + shaCh(e, f, g) + K256[i] + w[i];
            uint32_t t2 = shaSigma0(a) + shaMaj(a, b, c);
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        // 把本块结果累加进 H
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    // 输出：8 个字按大端拼成 32 字节
    string out;
    out.reserve(32);
    for (int i = 0; i < 8; i++) {
        out.push_back((char)(h[i] >> 24));
        out.push_back((char)(h[i] >> 16));
        out.push_back((char)(h[i] >> 8));
        out.push_back((char)(h[i]));
    }
    return out;
}

// 摘要 -> 大整数（签名对象）
NTL::ZZ sha256ZZ(const string& msg) { return Crypto::zzfrombytes(sha256(msg)); }

// 摘要 -> 十六进制字符串（显示用）
string sha256Hex(const string& msg) {
    string d = sha256(msg);
    string s;
    const char* hex = "0123456789abcdef";
    for (unsigned i = 0; i < d.length(); i++) {
        unsigned char c = (unsigned char)d[i];
        s.push_back(hex[c >> 4]);
        s.push_back(hex[c & 0xf]);
    }
    return s;
}

// ---------------- 字符串工具 ----------------

// 去掉 strings 两端的空白字符
string trim(const string& s) {
    unsigned a = 0, b = (unsigned)s.length();
    while (a < b && isspace((unsigned char)s[a])) a++;
    while (b > a && isspace((unsigned char)s[b-1])) b--;
    return s.substr(a, b - a);
}

// 按分隔符切分字符串（返回值不含分隔符）
vector<string> split(const string& s, char delim) {
    vector<string> r;
    string cur;
    for (unsigned i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == delim) { r.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    r.push_back(cur);          // 最后一个子串（即使为空）
    return r;
}

string toLower(string s) {
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// ---------------- 文件读写 ----------------

// 以二进制方式读入整个文件
bool readFile(const string& path, string& out) {
    ifstream f(path.c_str(), ios::binary);
    if (!f) return false;
    stringstream ss; ss << f.rdbuf();
    out = ss.str();
    return true;
}

// 把内容写入文件（覆盖）
bool writeFile(const string& path, const string& content) {
    ofstream f(path.c_str(), ios::binary);
    if (!f) return false;
    f << content;
    return true;
}

} // namespace Crypto