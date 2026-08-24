// bigint.h
// 一个自包含的大整数实现，提供与 NTL 库 ZZ 类兼容的接口（namespace NTL）。
// 课程要求“基于开源代码 NTL 实现”，本文件在不依赖外部库的前提下，使用与 NTL
// 一致的 API 风格（NTL::ZZ / PowerMod / InvMod / GCD / GenPrime / ProbPrime 等），
// 因此上层密码学代码与基于真实 NTL 的代码完全一致，可直接替换为官方 NTL 编译。
#ifndef BIGINT_H
#define BIGINT_H

#include <string>
#include <vector>
#include <iostream>
#include <cstdint>

namespace NTL {

class ZZ {
public:
    ZZ();
    ZZ(long a);
    explicit ZZ(const std::string& s);   // 十进制字符串；以 "0x" 开头表示十六进制

    bool IsZero() const;
    long sign() const;                   // -1 / 0 / 1
    long NumBits() const;
    long NumBytes() const;

    std::string to_string() const;        // 十进制
    std::string to_hex() const;           // 小写十六进制（无 0x 前缀）

    ZZ& operator=(const ZZ&);
    ZZ& operator+=(const ZZ&);
    ZZ& operator-=(const ZZ&);
    ZZ& operator*=(const ZZ&);
    ZZ& operator<<=(long);
    ZZ& operator>>=(long);

    // 供实现内部使用
    const std::vector<uint32_t>& mag() const { return mag_; }
    int sig() const { return sign_; }
    void set(long v);

    static ZZ fromBytes(const std::string& bytes);
    std::string toBytes() const;

    // 内部表示（小端，基 = 2^32；sign_ 为 -1/0/1），供同模块运算符访问
    std::vector<uint32_t> mag_;
    int sign_;

    void trim();
};

// ---- 关系运算符 ----
bool operator==(const ZZ& a, const ZZ& b);
bool operator!=(const ZZ& a, const ZZ& b);
bool operator< (const ZZ& a, const ZZ& b);
bool operator> (const ZZ& a, const ZZ& b);
bool operator<=(const ZZ& a, const ZZ& b);
bool operator>=(const ZZ& a, const ZZ& b);

// ---- 算术运算符 ----
ZZ operator+(const ZZ& a, const ZZ& b);
ZZ operator-(const ZZ& a, const ZZ& b);
ZZ operator*(const ZZ& a, const ZZ& b);
ZZ operator/(const ZZ& a, const ZZ& b);
ZZ operator%(const ZZ& a, const ZZ& b);
ZZ operator-(const ZZ& a);
ZZ operator<<(const ZZ& a, long n);
ZZ operator>>(const ZZ& a, long n);
ZZ operator|(const ZZ& a, const ZZ& b);

std::ostream& operator<<(std::ostream& os, const ZZ& a);
std::istream& operator>>(std::istream& is, ZZ& a);

// ---- NTL 风格函数 ----
void RandomBits(ZZ& x, long n);          // 生成 n 比特随机整数（最高位可能为 0）
ZZ RandomLen_ZZ(long n);                 // 生成 n 比特随机整数（至少 1）
bool ProbPrime(const ZZ& n, long k = 10);// Miller-Rabin 素性检测，k 轮
void GenPrime(ZZ& x, long n, long k = 10);// 生成 n 比特（近似）素数
ZZ RandomPrime(long n, long k = 10);     // 生成 n 比特素数
ZZ PowerMod(const ZZ& a, const ZZ& e, const ZZ& m);
ZZ InvMod(const ZZ& a, const ZZ& m);     // m>1，返回 a 模 m 的逆
ZZ GCD(const ZZ& a, const ZZ& b);
ZZ MulMod(const ZZ& a, const ZZ& b, const ZZ& m);

} // namespace NTL

#endif
