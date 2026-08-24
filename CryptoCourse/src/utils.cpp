// utils.cpp
#include "utils.h"
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <ctime>

namespace Crypto {

// ---------------- SHA-256 ----------------
static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static uint32_t shaCh(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t shaMaj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t shaSigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t shaSigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t shaSig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t shaSig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

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

std::string sha256(const std::string& msg) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    // 预处理
    std::vector<uint8_t> m((uint8_t*)msg.data(), (uint8_t*)msg.data() + msg.size());
    uint64_t ml = (uint64_t)msg.size() * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0x00);
    for (int i = 7; i >= 0; i--) m.push_back((uint8_t)(ml >> (i * 8)));

    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)m[off+4*i] << 24) | ((uint32_t)m[off+4*i+1] << 16) |
                   ((uint32_t)m[off+4*i+2] << 8) | (uint32_t)m[off+4*i+3];
        }
        for (int i = 16; i < 64; i++) {
            w[i] = shaSig1(w[i-2]) + w[i-7] + shaSig0(w[i-15]) + w[i-16];
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + shaSigma1(e) + shaCh(e, f, g) + K256[i] + w[i];
            uint32_t t2 = shaSigma0(a) + shaMaj(a, b, c);
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    std::string out;
    out.reserve(32);
    for (int i = 0; i < 8; i++) {
        out.push_back((char)(h[i] >> 24));
        out.push_back((char)(h[i] >> 16));
        out.push_back((char)(h[i] >> 8));
        out.push_back((char)(h[i]));
    }
    return out;
}

NTL::ZZ sha256ZZ(const std::string& msg) { return NTL::ZZ::fromBytes(sha256(msg)); }

std::string sha256Hex(const std::string& msg) {
    std::string d = sha256(msg);
    std::string s;
    const char* hex = "0123456789abcdef";
    for (unsigned char c : d) { s.push_back(hex[c >> 4]); s.push_back(hex[c & 0xf]); }
    return s;
}

// ---------------- 字符串工具 ----------------
std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) a++;
    while (b > a && isspace((unsigned char)s[b-1])) b--;
    return s.substr(a, b - a);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> r;
    std::string cur;
    for (char c : s) { if (c == delim) { r.push_back(cur); cur.clear(); } else cur.push_back(c); }
    r.push_back(cur);
    return r;
}

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// ---------------- 文件读写 ----------------
bool readFile(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::stringstream ss; ss << f.rdbuf();
    out = ss.str();
    return true;
}

bool writeFile(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f << content;
    return true;
}

} // namespace Crypto
