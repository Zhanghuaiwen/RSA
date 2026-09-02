// test.cpp : 各加密方案的独立测试函数与控制台演示（RSA 1024 比特 / ElGamal 2048 比特）
#include "test.h"
#include "rsa.h"
#include "elgamal.h"
#include "certificate.h"
#include "pki.h"
#include "entity.h"
#include "securemail.h"
#include "utils.h"
#include <iostream>

using namespace std;
using namespace NTL;

namespace Crypto {

// 密钥长度（任务书要求）：RSA p,q = 1024 比特；ElGamal p = 2048 比特
static const long RSA_BITS = 1024;
static const long ELG_BITS = 2048;

static void line(const string &s = "") { cout << s << "\n"; }

// ---------------- RSA ----------------
void testRSA()
{
    cout << "\n===== RSA 加密/解密/签名/验证 (p,q 为 1024 比特) =====\n";
    RSAKey key;
    RSAKeyGen(key, RSA_BITS, 12);
    cout << "公钥 n(前20位)=" << ztostr(key.n).substr(0, 20) << "...  b=" << key.b << "\n";

    string msg = "Hello RSA! 这是一条测试消息。";
    ZZ m = RSAEncodeMessage(msg);
    ZZ c = RSAEncrypt(key, m);
    string out = RSADecodeMessage(RSADecrypt(key, c));
    line("原文: " + msg);
    line("密文(前40位): " + ztostr(c).substr(0, 40) + "...");
    line("解密: " + out);
    line("加解密一致: " + string(out == msg ? "通过" : "失败"));

    ZZ h = sha256ZZ(msg);
    ZZ s = RSASign(key, h);
    line("验证: " + string(RSAVerify(key, h, s) ? "通过" : "失败"));

    string ks = RSAFullKeyToString(key);
    RSAKey key2 = RSAFullKeyFromString(ks);
    line("密钥字符串往返一致: " + string(key2.n == key.n && key2.a == key.a ? "通过" : "失败"));
}

// ---------------- ElGamal ----------------
void testElGamal()
{
    cout << "\n===== ElGamal 加密/解密/签名/验证 (p 为 2048 比特) =====\n";
    ElGamalKey key;
    ElGamalKeyGen(key, ELG_BITS, 12);
    cout << "p(前20位)=" << ztostr(key.p).substr(0, 20) << "...\n";

    string msg = "Hello ElGamal!";
    ZZ m = ElGamalEncodeMessage(msg);
    ZZ c1, c2;
    ElGamalEncrypt(key, m, c1, c2);
    string out = ElGamalDecodeMessage(ElGamalDecrypt(key, c1, c2));
    line("原文: " + msg);
    line("密文 c1(前20位)=" + ztostr(c1).substr(0, 20) + "  c2(前20位)=" + ztostr(c2).substr(0, 20));
    line("解密: " + out);
    line("加解密一致: " + string(out == msg ? "通过" : "失败"));

    ZZ h = sha256ZZ(msg);
    ZZ r, s;
    ElGamalSign(key, h, r, s);
    line("验证: " + string(ElGamalVerify(key, h, r, s) ? "通过" : "失败"));

    string ks = ElGamalFullKeyToString(key);
    ElGamalKey key2 = ElGamalFullKeyFromString(ks);
    line("密钥字符串往返一致: " + string(key2.p == key.p && key2.x == key.x ? "通过" : "失败"));
}

// ---------------- 证书方案 ----------------
void testCertificate()
{
    cout << "\n===== 证书方案 (flag1 签名算法 / flag2 用途) =====\n";
    PrivKey taPriv;
    RSAKey rk;
    RSAKeyGen(rk, RSA_BITS, 12);
    taPriv.scheme = SCHEME_RSA;
    taPriv.rsa = rk;
    PubKey taPub;
    taPub.scheme = SCHEME_RSA;
    taPub.rsa = rk;

    PubKey alicePub;
    RSAKey ak;
    RSAKeyGen(ak, RSA_BITS, 12);
    alicePub.scheme = SCHEME_RSA;
    alicePub.rsa = ak;

    Cert cert = issueCertificate("Alice", alicePub, taPriv, "TA", SCHEME_RSA, USE_ENCRYPT);
    cout << "颁发证书(txt):\n" << cert.toTxt() << "\n";
    line("证书验证: " + string(verifyCertificate(cert, taPub) ? "通过" : "失败"));

    Cert fake = cert;
    fake.ver = fake.ver + "1";
    line("篡改后验证(应失败): " + string(verifyCertificate(fake, taPub) ? "通过" : "失败"));
}

// ---------------- 简化 PKI ----------------
void testPKI()
{
    cout << "\n===== 构建 PKI 系统（根 CA + 2 下级 CA + 用户证书查询）=====\n";
    PKI pki;
    pki.build(SCHEME_RSA, SCHEME_RSA, RSA_BITS, 12);

    Entity alice;
    alice.id = "Alice";
    alice.generateKeys(SCHEME_RSA, SCHEME_RSA, RSA_BITS, 12);
    pki.ca1.issueCert(alice.encCertID(), alice.encPub, SCHEME_RSA, USE_ENCRYPT);
    pki.ca1.issueCert(alice.sigCertID(), alice.sigPub, SCHEME_RSA, USE_SIGN);

    vector<Cert> path = CertRepo::instance().getCertPath(alice.encCertID());
    cout << "Alice 加密证书链查询:\n";
    for (unsigned i = 0; i < path.size(); i++)
        cout << "  " << (i + 1) << ". " << path[i].id
             << "  (颁发者=" << path[i].idTA << ", flag1=" << path[i].flag1
             << ", flag2=" << path[i].flag2 << ")\n";
    cout << "证书链验证: " << (verifyCertPath(path) ? "通过" : "失败") << "\n";
}

// ---------------- 数字安全邮件 ----------------
void testSecureMail()
{
    cout << "\n===== 数字安全邮件系统演示 =====\n";
    PKI pki;
    pki.build(SCHEME_RSA, SCHEME_RSA, RSA_BITS, 12);

    Entity alice;
    alice.id = "Alice";
    alice.generateKeys(SCHEME_RSA, SCHEME_RSA, RSA_BITS, 12);
    alice.requestCerts(pki.ca1);
    Entity bob;
    bob.id = "Bob";
    bob.generateKeys(SCHEME_RSA, SCHEME_RSA, RSA_BITS, 12);
    bob.requestCerts(pki.ca2);

    string msg = "Bob, 这是一封测试邮件，来自 Alice。";
    string cipher, logSend;
    bool sendOK = sendMail(alice, bob, msg, cipher, logSend);
    cout << logSend;

    string out, logRecv;
    bool recvOK = receiveMail(bob, alice, cipher, out, logRecv);
    cout << logRecv;
    cout << "恢复原文: " << out << "\n";
    cout << "邮件收发成功: " << ((sendOK && recvOK && out == msg) ? "是" : "否") << "\n";
}

// ---------------- 运行全部测试 ----------------
void runAllTests()
{
    cout << "========== 运行全部测试 (RSA 1024 比特 / ElGamal 2048 比特) ==========\n";
    testRSA();
    testElGamal();
    testCertificate();
    testPKI();
    testSecureMail();
    cout << "\n========== 全部测试结束 ==========\n";
}

} // namespace Crypto