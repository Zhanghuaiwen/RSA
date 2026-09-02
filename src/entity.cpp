// =====================================================================
// entity.cpp : 实体（用户）的实现。
//   每个实体拥有两套密钥：
//     encPriv/encPub —— 加密用途公钥（证人中 FLAG2=0）
//     sigPriv/sigPub —— 签名用途公钥（FLAG2=1）
//   并向 CA 申请两张证书（例如 Alice_ENC / Alice_SIG）。
// =====================================================================

#include "entity.h"

// 与官方 NTL 的 NTL_CLIENT 宏一致：展开为下面两行
using namespace std;
using namespace NTL;

namespace Crypto
{
    // 为实体生成加密与签名两套密钥。encScheme / sigScheme 可取：
    //   SCHEME_RSA=0 或 SCHEME_ELGAMAL=1
    void Entity::generateKeys(int encScheme, int sigScheme, long bits, long k)
    {
        // (1) 加密用途密钥
        if (encScheme == SCHEME_RSA)
        {
            RSAKey key;
            RSAKeyGen(key, bits, k);
            encPriv.scheme = SCHEME_RSA;
            encPriv.rsa = key;
            encPub.scheme = SCHEME_RSA;
            encPub.rsa = key;
        }
        else
        {
            ElGamalKey key;
            ElGamalKeyGen(key, bits, k);
            encPriv.scheme = SCHEME_ELGAMAL;
            encPriv.elg = key;
            encPub.scheme = SCHEME_ELGAMAL;
            encPub.elg = key;
        }
        // (2) 签名用途密钥
        if (sigScheme == SCHEME_RSA)
        {
            RSAKey key;
            RSAKeyGen(key, bits, k);
            sigPriv.scheme = SCHEME_RSA;
            sigPriv.rsa = key;
            sigPub.scheme = SCHEME_RSA;
            sigPub.rsa = key;
        }
        else
        {
            ElGamalKey key;
            ElGamalKeyGen(key, bits, k);
            sigPriv.scheme = SCHEME_ELGAMAL;
            sigPriv.elg = key;
            sigPub.scheme = SCHEME_ELGAMAL;
            sigPub.elg = key;
        }
    }

    // 向指定 CA 申请两张证书：
    //   - 加密证书：ID = 实体ID+"_ENC"，FLAG2=0（加密用途）
    //   - 签名证书：ID = 实体ID+"_SIG"，FLAG2=1（签名用途）
    void Entity::requestCerts(CA &ca)
    {
        ca.issueCert(encCertID(), encPub, encPub.scheme, USE_ENCRYPT);
        ca.issueCert(sigCertID(), sigPub, sigPub.scheme, USE_SIGN);
    }

} // namespace Crypto