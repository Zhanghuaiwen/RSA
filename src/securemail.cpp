// =====================================================================
// securemail.cpp : 简易安全邮件系统的实现。
//
//   发送过程 sendMail(sender, receiver, msg)：
//     (1) 查询并验证接收方的加密证书链（证明接收方公钥可信）；
//     (2) 发送方用自己签名私钥对 msg 的 SHA-256 摘要签名得 sigStr；
//     (3) 组合 payload = msg + 分隔符 + sigStr，转成大整数；        // 签名+消息
//     (4) 用接收方的加密公钥分块加密 payload，输出密文字符串。       // 机密性
//   接收过程 receiveMail(receiver, sender, cipher)：
//     (1) 用接收方的加密私钥解密得到 payload，按分隔符拆出 msg 与 sigStr；
//     (2) 查询并验证发送方的签名证书链（证明发送方身份可信）；
//     (3) 用发送方签名公钥验证签名，通过则 msg 可信且完整。
//   这样同时实现了机密性、完整性、身份认证与抗抵赖，但不保证传输层安全。
// =====================================================================

#include "securemail.h"
#include "utils.h"
#include <sstream>

// 与官方 NTL 的 NTL_CLIENT 宏一致：展开为下面两行
using namespace std;
using namespace NTL;

namespace Crypto {

// 消息与签名之间的分隔符
static const string DELIM = "\n@@SIG@@\n";

// ---------------- 发送端 ----------------
bool sendMail(const Entity& sender, const Entity& receiver,
              const string& msg, string& cipher, string& log) {
    log.clear();
    CertRepo& repo = CertRepo::instance();

    // (1) 查询接收方“加密证书”的证书链并验证     —— 信任锚定
    vector<Cert> path = repo.getCertPath(receiver.encCertID());
    bool pathOK = verifyCertPath(path);
    log += "[发送端] 接收端加密证书链:\n";
    for (unsigned i = 0; i < path.size(); i++)
        log += "  " + path[i].id + (i + 1 < path.size() ? " <- " : "\n");
    log += string("  证书链验证: ") + (pathOK ? "通过" : "失败") + "\n";

    // (2) 发送方用自己的签名私钥对消息摘要签名    —— 认证与抗抵赖
    string s = sender.sign(msg);

    // (3) 从证书中取出接收方的加密公钥
    PubKey encPub;
    if (!path.empty())
        encPub = parsePubKey(path.back().ver);

    // (4) 组合 m||s 并加密                       —— 机密性
    string payload = msg + DELIM + s;
    ZZ z = zzfrombytes(payload);
    cipher = encryptMessage(encPub, z);
    {
        // 用最基础的流方式把密文字节数转成字符串（不用 std::to_string）
        ostringstream os;
        os << cipher.length();
        log += "[发送端] 已用接收端加密公钥加密 m||s，密文长度 " + os.str() + " 字节。\n";
    }
    return pathOK;
}

// ---------------- 接收端 ----------------
bool receiveMail(const Entity& receiver, const Entity& sender,
                 const string& cipher, string& msgOut, string& log) {
    log.clear();

    // (1) 用自己的加密私钥解密得到 m||s
    ZZ z = receiver.decrypt(cipher);
    string payload = zztobytes(z);
    long pos = (long)payload.find(DELIM);
    if (pos < 0) { log += "[接收端] 无法解析 m||s。\n"; return false; }
    string msg = payload.substr(0, (unsigned)pos);                // 明文
    string s = payload.substr((unsigned)pos + DELIM.length());    // 签名串

    // (2) 查询发送方“签名证书”的证书链并验证     —— 身份认证
    CertRepo& repo = CertRepo::instance();
    vector<Cert> path = repo.getCertPath(sender.sigCertID());
    bool pathOK = verifyCertPath(path);
    log += "[接收端] 发送端签名证书链:\n";
    for (unsigned i = 0; i < path.size(); i++)
        log += "  " + path[i].id + (i + 1 < path.size() ? " <- " : "\n");
    log += string("  证书链验证: ") + (pathOK ? "通过" : "失败") + "\n";
    if (!pathOK)
        return false;

    // (3) 取出发送方签名公钥并验证签名            —— 完整性与认证
    PubKey sigPub = parsePubKey(path.back().ver);
    bool ok = verifyMessage(sigPub, msg, s);
    log += string("[接收端] 签名验证: ") + (ok ? "通过" : "失败") + "\n";
    if (ok)
        msgOut = msg;               // 通过验证才返回明文
    return ok;
}

} // namespace Crypto