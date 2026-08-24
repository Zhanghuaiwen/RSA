// main.cpp : 课程设计主程序，提供菜单运行各模块测试与演示。
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

using namespace Crypto;
using namespace NTL;

int main() {
    std::srand((unsigned int)std::time(0));
    int bits = 512;   // 默认素数长度；常量改为 1024 即完全符合任务书（n 为 2048 比特），仅更慢
    int choice = 0;
    while (true) {
        std::cout << "\n================ 现代密码学课程设计 ================\n";
        std::cout << "当前素数长度: " << bits << " 比特 (改为 1024 即符合任务书要求)\n";
        std::cout << "1. RSA 加解密测试\n";
        std::cout << "2. RSA 签名/验证测试\n";
        std::cout << "3. ElGamal 加解密测试\n";
        std::cout << "4. ElGamal 签名/验证测试\n";
        std::cout << "5. 简单证书方案测试 (flag1/flag2)\n";
        std::cout << "6. 简易 PKI 系统 + 证书链查询\n";
        std::cout << "7. 简易安全邮件系统演示\n";
        std::cout << "8. 运行全部测试\n";
        std::cout << "9. 切换密钥强度 (512 / 1024)\n";
        std::cout << "0. 退出\n";
        std::cout << "请选择: ";
        std::cin >> choice;
        if (choice == 0) break;
        if (choice == 9) {
            std::cout << "输入素数长度(512 或 1024): ";
            std::cin >> bits;
            if (bits != 512 && bits != 1024) bits = 512;
            continue;
        }
        try {
            switch (choice) {
                case 1: testRSA(bits); break;
                case 2: { // RSA 签名单独演示
                    RSAKey key; RSAKeyGen(key, bits, 12);
                    std::string msg; std::cout << "输入待签名消息: "; std::cin.ignore();
                    std::getline(std::cin, msg);
                    if (msg.empty()) msg = "Demo sign message.";
                    ZZ h = sha256ZZ(msg); ZZ s = RSASign(key, h);
                    std::cout << "消息摘要(SHA-256 十六进制): " << sha256Hex(msg) << "\n";
                    std::cout << "签名: " << s << "\n";
                    std::cout << "验证: " << (RSAVerify(key, h, s) ? "通过" : "失败") << "\n";
                    break;
                }
                case 3: testElGamal(bits); break;
                case 4: { // ElGamal 签名单独演示
                    ElGamalKey key; ElGamalKeyGen(key, bits, 12);
                    std::string msg; std::cout << "输入待签名消息: "; std::cin.ignore();
                    std::getline(std::cin, msg);
                    if (msg.empty()) msg = "Demo sign message.";
                    ZZ h = sha256ZZ(msg); ZZ r, s; ElGamalSign(key, h, r, s);
                    std::cout << "签名 r=" << r << " s=" << s << "\n";
                    std::cout << "验证: " << (ElGamalVerify(key, h, r, s) ? "通过" : "失败") << "\n";
                    break;
                }
                case 5: testCertificate(bits); break;
                case 6: testPKI(bits); break;
                case 7: testSecureMail(bits); break;
                case 8: runAllTests(bits); break;
                default: std::cout << "无效选择\n";
            }
        } catch (const std::exception& e) {
            std::cout << "错误: " << e.what() << "\n";
        }
        std::cout << "\n按回车继续...";
        std::cin.ignore(); std::cin.get();
    }
    return 0;
}
