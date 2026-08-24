// test.cpp : 各密码方案的独立测试函数（控制台输出，便于演示与截图）。
#include "test.h"
#include "rsa.h"
#include "elgamal.h"
#include "certificate.h"
#include "pki.h"
#include "entity.h"
#include "securemail.h"
#include "utils.h"
#include <iostream>
#include <iomanip>

using namespace NTL;

namespace Crypto {

static void line(const std::string& s = "") { std::cout << s << "\n"; }

void testRSA(long bits) {
    std::cout << "\n===== RSA 加密 / 解密 / 签名 / 验证 (p,q 为 " << bits << " 比特) =====\n";
    RSAKey key; RSAKeyGen(key, bits, 12);
    std::cout << "公钥 n(前20位)=" << key.n.to_string().substr(0, 20) << "...  b=" << key.b << "\n";
    std::cout << "私钥 p(前20位)=" << key.p.to_string().substr(0, 20) << "...  q(前20位)=" << key.q.to_string().substr(0, 20) << "...\n";

    std::string msg = "Hello RSA! 这是一条测试消息。";
    ZZ m = RSAEncodeMessage(msg);
    ZZ c = RSAEncrypt(key, m);
    ZZ d = RSADecrypt(key, c);
    std::string out = RSADecodeMessage(d);
    line("明文: " + msg);
    line("密文(前40位): " + c.to_string().substr(0, 40) + "...");
    line("解密: " + out);
    line("加解密一致: " + std::string(out == msg ? "通过" : "失败"));

    // 签名
    ZZ h = sha256ZZ(msg);
    ZZ s = RSASign(key, h);
    bool ok = RSAVerify(key, h, s);
    line("签名: " + s.to_string().substr(0, 30) + "...");
    line("验证: " + std::string(ok ? "通过" : "失败"));

    // 格式转换（密钥 <-> 字符串）
    std::string ks = RSAFullKeyToString(key);
    RSAKey key2 = RSAFullKeyFromString(ks);
    line("密钥字符串往返一致: " + std::string(key2.n == key.n && key2.a == key.a ? "通过" : "失败"));
}

void testElGamal(long bits) {
    std::cout << "\n===== ElGamal 加密 / 解密 / 签名 / 验证 (p 为 " << bits << " 比特) =====\n";
    ElGamalKey key; ElGamalKeyGen(key, bits, 12);
    std::cout << "p(前20位)=" << key.p.to_string().substr(0, 20) << "...  g=" << key.g << "\n";

    std::string msg = "Hello ElGamal!";
    ZZ m = ElGamalEncodeMessage(msg);
    ZZ c1, c2; ElGamalEncrypt(key, m, c1, c2);
    ZZ d = ElGamalDecrypt(key, c1, c2);
    std::string out = ElGamalDecodeMessage(d);
    line("明文: " + msg);
    line("密文 c1(前20位)=" + c1.to_string().substr(0, 20) + "  c2(前20位)=" + c2.to_string().substr(0, 20));
    line("解密: " + out);
    line("加解密一致: " + std::string(out == msg ? "通过" : "失败"));

    ZZ h = sha256ZZ(msg);
    ZZ r, s; ElGamalSign(key, h, r, s);
    bool ok = ElGamalVerify(key, h, r, s);
    line("签名 r=" + r.to_string().substr(0, 16) + "  s=" + s.to_string().substr(0, 16));
    line("验证: " + std::string(ok ? "通过" : "失败"));

    std::string ks = ElGamalFullKeyToString(key);
    ElGamalKey key2 = ElGamalFullKeyFromString(ks);
    line("密钥字符串往返一致: " + std::string(key2.p == key.p && key2.x == key.x ? "通过" : "失败"));
}

void testCertificate(long bits) {
    std::cout << "\n===== 简单证书方案 (flag1 签名算法 / flag2 用途) =====\n";
    // TA 用自己的 RSA 私钥
    PrivKey taPriv; RSAKey rk; RSAKeyGen(rk, bits, 12);
    taPriv.scheme = SCHEME_RSA; taPriv.rsa = rk;
    PubKey taPub; taPub.scheme = SCHEME_RSA; taPub.rsa = rk;

    // Alice 的公钥（这里用 RSA，可换成 ElGamal）
    PubKey alicePub; RSAKey ak; RSAKeyGen(ak, bits, 12);
    alicePub.scheme = SCHEME_RSA; alicePub.rsa = ak;

    Cert cert = issueCertificate("Alice", alicePub, taPriv, "TA",
                                 SCHEME_RSA,   // flag1 = 0 (RSA 签名)
                                 USE_ENCRYPT); // flag2 = 0 (加密用途)
    std::cout << "颁发的证书(txt):\n" << cert.toTxt() << "\n";
    bool ok = verifyCertificate(cert, taPub);
    line("证书验证: " + std::string(ok ? "通过" : "失败"));

    // 篡改检测：修改 ver 后应验证失败
    Cert fake = cert; fake.ver = fake.ver + "1";
    line("篡改后验证(应失败): " + std::string(verifyCertificate(fake, taPub) ? "通过" : "失败"));
}

void testPKI(long bits) {
    std::cout << "\n===== 简易 PKI 系统：根 CA + 2 个下级 CA + 用户证书 =====\n";
    PKI pki; pki.build(SCHEME_RSA, SCHEME_RSA, bits, 12);
    std::cout << "证书库当前证书数: " << CertRepo::instance().size() << "\n";

    Entity alice; alice.id = "Alice"; alice.generateKeys(SCHEME_RSA, SCHEME_RSA, bits, 12);
    pki.ca1.issueCert(alice.encCertID(), alice.encPub, SCHEME_RSA, USE_ENCRYPT);
    pki.ca1.issueCert(alice.sigCertID(), alice.sigPub, SCHEME_RSA, USE_SIGN);

    std::vector<Cert> path = CertRepo::instance().getCertPath(alice.encCertID());
    std::cout << "Alice 加密证书链查询:\n";
    for (size_t i = 0; i < path.size(); i++)
        std::cout << "  " << (i + 1) << ". " << path[i].id
                  << "  (颁发者=" << path[i].idTA << ", flag1=" << path[i].flag1
                  << ", flag2=" << path[i].flag2 << ")\n";
    bool ok = verifyCertPath(path);
    std::cout << "证书链验证: " << (ok ? "通过" : "失败") << "\n";
}

void testSecureMail(long bits) {
    std::cout << "\n===== 简易安全邮件系统演示 =====\n";
    PKI pki; pki.build(SCHEME_RSA, SCHEME_RSA, bits, 12);
    Entity alice; alice.id = "Alice"; alice.generateKeys(SCHEME_RSA, SCHEME_RSA, bits, 12);
    alice.requestCerts(pki.ca1);
    Entity bob; bob.id = "Bob"; bob.generateKeys(SCHEME_RSA, SCHEME_RSA, bits, 12);
    bob.requestCerts(pki.ca2);

    std::string msg = "Bob, 这是一条机密邮件，来自 Alice。";
    std::string cipher, logSend;
    bool sendOK = sendMail(alice, bob, msg, cipher, logSend);
    std::cout << logSend;

    std::string out, logRecv;
    bool recvOK = receiveMail(bob, alice, cipher, out, logRecv);
    std::cout << logRecv;
    std::cout << "恢复明文: " << out << "\n";
    std::cout << "邮件收发成功: " << ((sendOK && recvOK && out == msg) ? "是" : "否") << "\n";
}

void runAllTests(long bits) {
    std::cout << "========== 运行全部测试 (密钥强度 " << bits << " 比特素数) ==========\n";
    testRSA(bits);
    testElGamal(bits);
    testCertificate(bits);
    testPKI(bits);
    testSecureMail(bits);
    std::cout << "\n========== 全部测试结束 ==========\n";
}

} // namespace Crypto
