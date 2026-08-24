// utils.h : 公共工具——哈希函数(SHA-256)、十六进制、文件读写等。
#ifndef UTILS_H
#define UTILS_H

#include "bigint.h"
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace Crypto {

// ---------- SHA-256 ----------
std::string sha256(const std::string& msg);          // 返回 32 字节原始摘要
NTL::ZZ sha256ZZ(const std::string& msg);            // 摘要转大整数（用于签名）
std::string sha256Hex(const std::string& msg);       // 十六进制字符串

// ---------- 字符串工具 ----------
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
std::string toLower(std::string s);

// ---------- 文件读写 ----------
bool readFile(const std::string& path, std::string& out);
bool writeFile(const std::string& path, const std::string& content);

// ZZ <-> 十进制串（用于密钥/证书存储）
inline std::string ztostr(const NTL::ZZ& v) { return v.to_string(); }
inline NTL::ZZ strtoz(const std::string& s) { return NTL::ZZ(s); }

} // namespace Crypto

#endif
