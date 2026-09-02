// main.cpp : 课程设计主程序（菜单式运行）
// 密钥长度（任务书要求）：RSA p,q = 1024 比特；ElGamal p = 2048 比特（均固定）
#include "test.h"
#include "rsa.h"
#include "elgamal.h"
#include "certificate.h"
#include "pki.h"
#include "entity.h"
#include "securemail.h"
#include "utils.h"
#include <iostream>
#include <string>
#include <ctime>

using namespace std;
using namespace NTL;
using namespace Crypto;

int main()
{
    // 以当前时间为随机种子，保证每次生成的密钥/证书都不同
    srand((unsigned int)time(0));
    SetSeed(to_ZZ((long)time(0)) | to_ZZ(1));

    const long RSA_BITS = 1024;    // RSA 的 p、q 各 1024 比特
    const long ELG_BITS = 2048;    // ElGamal 的随机素数 p 为 2048 比特
    int choice = 0;

    while (true)
    {
        cout << "\n================ 现代密码学课程设计 ================\n";
        cout << "密钥长度：RSA p,q = " << RSA_BITS << " 比特 | ElGamal p = " << ELG_BITS << " 比特\n";
        cout << "1. RSA 加解密测试\n";
        cout << "2. RSA 签名/验证测试\n";
        cout << "3. ElGamal 加解密测试\n";
        cout << "4. ElGamal 签名/验证测试\n";
        cout << "5. 证书颁发方案\n";
        cout << "6. 构建 PKI 系统 + 证书颁发查询\n";
        cout << "7. 数字安全邮件系统演示\n";
        cout << "8. 运行全部测试\n";
        cout << "0. 退出\n";
        cout << "请选择: ";
        cin >> choice;

        if (choice == 0)
            break;

        try
        {
            switch (choice)
            {
            case 1:
                testRSA();
                break;
            case 2:
            {
                RSAKey key;
                RSAKeyGen(key, RSA_BITS, 12);
                string msg;
                cout << "请输入签名的信息: ";
                cin.ignore();
                getline(cin, msg);
                if (msg.empty())
                    msg = "Demo sign message.";
                ZZ h = sha256ZZ(msg);
                ZZ s = RSASign(key, h);
                cout << "消息摘要(SHA-256 十六进制): " << sha256Hex(msg) << "\n";
                cout << "签名: " << s << "\n";
                cout << "验证: " << (RSAVerify(key, h, s) ? "通过" : "失败") << "\n";
                break;
            }
            case 3:
                testElGamal();
                break;
            case 4:
            {
                ElGamalKey key;
                ElGamalKeyGen(key, ELG_BITS, 12);
                string msg;
                cout << "请输入签名的信息: ";
                cin.ignore();
                getline(cin, msg);
                if (msg.empty())
                    msg = "Demo sign message.";
                ZZ h = sha256ZZ(msg);
                ZZ r, s;
                ElGamalSign(key, h, r, s);
                cout << "签名 r=" << r << " s=" << s << "\n";
                cout << "验证: " << (ElGamalVerify(key, h, r, s) ? "通过" : "失败") << "\n";
                break;
            }
            case 5:
                testCertificate();
                break;
            case 6:
                testPKI();
                break;
            case 7:
                testSecureMail();
                break;
            case 8:
                runAllTests();
                break;
            default:
                cout << "无效选择\n";
            }
        }
        catch (const exception &e)
        {
            cout << "错误: " << e.what() << "\n";
        }

        cout << "\n按回车继续...";
        cin.ignore();
        cin.get();
    }
    return 0;
}