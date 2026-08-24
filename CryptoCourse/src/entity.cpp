// entity.cpp
#include "entity.h"

namespace Crypto {

void Entity::generateKeys(int encScheme, int sigScheme, long bits, long k) {
    if (encScheme == SCHEME_RSA) {
        RSAKey key; RSAKeyGen(key, bits, k);
        encPriv.scheme = SCHEME_RSA; encPriv.rsa = key;
        encPub.scheme = SCHEME_RSA; encPub.rsa = key;
    } else {
        ElGamalKey key; ElGamalKeyGen(key, bits, k);
        encPriv.scheme = SCHEME_ELGAMAL; encPriv.elg = key;
        encPub.scheme = SCHEME_ELGAMAL; encPub.elg = key;
    }
    if (sigScheme == SCHEME_RSA) {
        RSAKey key; RSAKeyGen(key, bits, k);
        sigPriv.scheme = SCHEME_RSA; sigPriv.rsa = key;
        sigPub.scheme = SCHEME_RSA; sigPub.rsa = key;
    } else {
        ElGamalKey key; ElGamalKeyGen(key, bits, k);
        sigPriv.scheme = SCHEME_ELGAMAL; sigPriv.elg = key;
        sigPub.scheme = SCHEME_ELGAMAL; sigPub.elg = key;
    }
}

void Entity::requestCerts(CA& ca) {
    // 加密用途证书：flag1 = 加密算法, flag2 = 0（加密）
    ca.issueCert(encCertID(), encPub, encPub.scheme, USE_ENCRYPT);
    // 签名用途证书：flag1 = 签名算法, flag2 = 1（签名）
    ca.issueCert(sigCertID(), sigPub, sigPub.scheme, USE_SIGN);
}

} // namespace Crypto
