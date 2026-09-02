// utils.h : 公共工具函数——SHA-256 哈希、字符串处理与文件读写。
//   SHA-256 用于：对消息/证书内容做摘要后再签名（签名对象是摘要而不是明文）；
//   字符串与文件工具用于证书的 txt 序列化、密钥的文本存储与读取。
#ifndef UTILS_H
#define UTILS_H

#include <NTL/ZZ.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace Crypto {

// ---------- SHA-256 哈希 ----------
// 计算消息摘要（32 字节原始二进制数据）
std::string sha256(const std::string& msg);
// 摘要转为大整数（RSA/ElGamal 直接对该整数签名、验签）
NTL::ZZ sha256ZZ(const std::string& msg);
// 摘要的十六进制字符串（屏幕显示与人工核对用）
std::string sha256Hex(const std::string& msg);

// ---------- 字符串工具 ----------
std::string trim(const std::string& s);            // 去掉两端空白
std::vector<std::string> split(const std::string& s, char delim);  // 按分隔符切分
std::string toLower(std::string s);                // 转小写

// ---------- 文件读写 ----------
// 任务书要求证书以 txt 文本形式保存，这里提供通用文本文件读写
bool readFile(const std::string& path, std::string& out);
bool writeFile(const std::string& path, const std::string& content);

// ---------- NTL::ZZ 与字符串/字节串互转 ----------
// 直接使用官方 NTL 的流与 BytesFromZZ / ZZFromBytes（本工程自实现部分被移除）
// ZZ -> 十进制字符串（密钥 / 证书内容存储）
inline std::string ztostr(const NTL::ZZ& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

// 十进制字符串 -> ZZ（用 NTL 的流式 operator>> 解析，与 ztostr 互逆）
inline NTL::ZZ strtoz(const std::string& s) {
    NTL::ZZ v;
    std::istringstream is(s);
    is >> v;
    return v;
}

// 字节串 -> ZZ（256 进制、大端存储，与 zztobytes 互逆）
inline NTL::ZZ zzfrombytes(const std::string& s) {
    if (s.empty()) return NTL::ZZ(0);
    return NTL::ZZFromBytes((const unsigned char*)s.data(), (long)s.size());
}

// ZZ -> 字节串（按模数实际字节数输出，与 zzfrombytes 互逆）
inline std::string zztobytes(const NTL::ZZ& v) {
    long n = NTL::NumBytes(v);
    if (n <= 0) return std::string();
    std::string r((unsigned)n, '\0');
    NTL::BytesFromZZ((unsigned char*)&r[0], v, n);
    return r;
}

} // namespace Crypto

#endif