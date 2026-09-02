// test.h : 各加密方案的独立测试函数
#ifndef TEST_H
#define TEST_H

namespace Crypto {

void testRSA();
void testElGamal();
void testCertificate();
void testPKI();
void testSecureMail();
void runAllTests();

} // namespace Crypto

#endif