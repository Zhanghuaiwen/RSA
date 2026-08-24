// securemail.cpp
#include "securemail.h"
#include "utils.h"

namespace Crypto {

static const std::string DELIM = "\n@@SIG@@\n";

bool sendMail(const Entity& sender, const Entity& receiver,
              const std::string& msg, std::string& cipher, std::string& log) {
    log.clear();
    CertRepo& repo = CertRepo::instance();
    // 1. 查询接收端加密证书链并验证
    std::vector<Cert> path = repo.getCertPath(receiver.encCertID());
    bool pathOK = verifyCertPath(path);
    log += "[发送端] 接收端加密证书链:\n";
    for (size_t i = 0; i < path.size(); i++)
        log += "  " + path[i].id + (i + 1 < path.size() ? " <- " : "\n");
    log += std::string("  证书链验证: ") + (pathOK ? "通过" : "失败") + "\n";

    // 2. 用发送端签名私钥对 m 的摘要签名
    std::string s = sender.sign(msg);

    // 3. 从证书中取出接收端加密公钥
    PubKey encPub;
    if (!path.empty()) encPub = parsePubKey(path.back().ver);

    // 4. 加密 m||s
    std::string payload = msg + DELIM + s;
    NTL::ZZ z = NTL::ZZ::fromBytes(payload);
    cipher = encryptMessage(encPub, z);
    log += "[发送端] 已用接收端加密公钥加密 m||s，密文长度 " +
           std::to_string(cipher.size()) + " 字节。\n";
    return pathOK;
}

bool receiveMail(const Entity& receiver, const Entity& sender,
                 const std::string& cipher, std::string& msgOut, std::string& log) {
    log.clear();
    // 1. 用接收端加密私钥解密
    NTL::ZZ z = receiver.decrypt(cipher);
    std::string payload = z.toBytes();
    size_t pos = payload.find(DELIM);
    if (pos == std::string::npos) { log += "[接收端] 无法解析 m||s。\n"; return false; }
    std::string msg = payload.substr(0, pos);
    std::string s = payload.substr(pos + DELIM.size());

    // 2. 查询发送端签名证书链并验证
    CertRepo& repo = CertRepo::instance();
    std::vector<Cert> path = repo.getCertPath(sender.sigCertID());
    bool pathOK = verifyCertPath(path);
    log += "[接收端] 发送端签名证书链:\n";
    for (size_t i = 0; i < path.size(); i++)
        log += "  " + path[i].id + (i + 1 < path.size() ? " <- " : "\n");
    log += std::string("  证书链验证: ") + (pathOK ? "通过" : "失败") + "\n";
    if (!pathOK) return false;

    // 3. 取出发送端签名公钥
    PubKey sigPub = parsePubKey(path.back().ver);
    // 4. 验证签名
    bool ok = verifyMessage(sigPub, msg, s);
    log += std::string("[接收端] 签名验证: ") + (ok ? "通过" : "失败") + "\n";
    if (ok) msgOut = msg;
    return ok;
}

} // namespace Crypto
