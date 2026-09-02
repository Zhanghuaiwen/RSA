// securemail.h : 简易安全邮件系统（发送端签名+加密，接收端解密+验证）。
#ifndef SECUREMAIL_H
#define SECUREMAIL_H

#include "entity.h"
#include <string>
#include <vector>

namespace Crypto {

// 发送端：查询接收端加密证书链并验证；对 m 的摘要签名得到 s；
// 用接收端加密公钥加密 m||s，得到密文 cipher。返回证书链是否验证通过。
bool sendMail(const Entity& sender, const Entity& receiver,
              const std::string& msg, std::string& cipher, std::string& log);

// 接收端：用加密私钥解密得到 m||s；查询发送端签名证书链并验证；
// 取出发送端签名公钥验证签名。返回验证是否通过，msgOut 为恢复出的明文。
bool receiveMail(const Entity& receiver, const Entity& sender,
                 const std::string& cipher, std::string& msgOut, std::string& log);

} // namespace Crypto

#endif
