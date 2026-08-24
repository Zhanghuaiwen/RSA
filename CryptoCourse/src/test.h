// test.h : 各密码方案的独立测试函数。
#ifndef TEST_H
#define TEST_H

namespace Crypto {

void testRSA(long bits = 512);
void testElGamal(long bits = 512);
void testCertificate(long bits = 512);
void testPKI(long bits = 512);
void testSecureMail(long bits = 512);
void runAllTests(long bits = 512);

} // namespace Crypto

#endif
