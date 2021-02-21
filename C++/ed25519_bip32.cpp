/* The MIT License (MIT)
 * 
 * Copyright (c) 2018 Sideris Coin Developers
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to 
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <memory.h>
#include "ed25519_bip32.h"
#include "ed25519_bip32_utils.h"
#include "custom/random.h"
#include "include/ed25519_signature.h"
#include "source/curve25519_mehdi.h"
#include "openssl/sha.h"

#ifdef BIP32_ENABLE_BLINDING
 #ifdef BIP32_ENABLE_STATIC_BLINDING
 // Static blinding are only created at compiled time and they remain unchanged during execution.
 extern EDP_BLINDING_CTX edp_genkey_blinding;
 extern EDP_BLINDING_CTX edp_signature_blinding;
 #endif
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Derive extended private and public key using pseudo-random generated byte-sequence
//
CED25519Priv_BIP32::CED25519Priv_BIP32()
{
    SetNull();
    unsigned char secret[SecretSize];
    GetRandomBytes(secret, SecretSize);
#ifdef BIP32_ENABLE_BLINDING
 #ifndef BIP32_ENABLE_STATIC_BLINDING
    setGenkeyBlindingCTX();
    if (isGenkeyBlindingSet())
        ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, m_genkey_blinding, secret);
    else
        ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, NULL, secret);
 #else
    ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, &edp_genkey_blinding, secret);
 #endif
#else
    ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, NULL, secret);
#endif
    deriveRootChainCode();
    memset(secret, 0, SecretSize);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Derive extended private and public key using the provided 32 bytes long Master Secret
//
CED25519Priv_BIP32::CED25519Priv_BIP32(const unsigned char *secret)
{
    SetNull();
#ifdef BIP32_ENABLE_BLINDING
 #ifndef BIP32_ENABLE_STATIC_BLINDING
    setGenkeyBlindingCTX();
    if (isGenkeyBlindingSet())
        ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, m_genkey_blinding, secret);
    else
        ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, NULL, secret);
 #else
    ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, &edp_genkey_blinding, secret);
 #endif
#else
    ed25519_CreateExtendedKeyPair(m_PublicKey, m_PrivKey, m_ExtPrivKey, NULL, secret);
#endif
    deriveRootChainCode();
}

CED25519Priv_BIP32::CED25519Priv_BIP32(const unsigned char *extPrivateKey, const unsigned char *chainCode)
{
    SetNull();
    memcpy(m_ExtPrivKey, extPrivateKey, PrivateKeySize);
    memcpy(m_ChainCode, chainCode, ChainCodeSize);
#ifdef BIP32_ENABLE_BLINDING
 #ifndef BIP32_ENABLE_STATIC_BLINDING
    setGenkeyBlindingCTX();
    if (isGenkeyBlindingSet())
        ed25519_DerivePublicKeyfromPrivate(m_PublicKey, m_ExtPrivKey, m_genkey_blinding);
    else
        ed25519_DerivePublicKeyfromPrivate(m_PublicKey, m_ExtPrivKey, NULL);
 #else
    ed25519_DerivePublicKeyfromPrivate(m_PublicKey, m_ExtPrivKey, &edp_genkey_blinding);
 #endif
#else
    ed25519_DerivePublicKeyfromPrivate(m_PublicKey, m_ExtPrivKey, NULL);
#endif
}

CED25519Priv_BIP32::~CED25519Priv_BIP32()
{
    SetNull();
    freeGenkeyBlindingCTX();
}

void CED25519Priv_BIP32::SetNull()
{
    memset(m_PublicKey,  0, PublicKeySize);
    memset(m_PrivKey,    0, SecretSize);
    memset(m_ExtPrivKey, 0, PrivateKeySize);
    memset(m_ChainCode,  0, ChainCodeSize);
}

void CED25519Priv_BIP32::getPublicKeyBytes(unsigned char *pubKey)
{
    if (pubKey) {
        memcpy(pubKey, m_PublicKey, PublicKeySize);
    }
}

void CED25519Priv_BIP32::deriveRootChainCode()
{
    unsigned char buf[PublicKeySize + 1];
    buf[0] = 0x01;
    memcpy(buf + 1, m_PublicKey, PublicKeySize);
    SHA256(buf, sizeof(buf), m_ChainCode);
    memset(buf, 0, sizeof(buf));
}

void CED25519Priv_BIP32::getChainCodeBytes(unsigned char *chainCode)
{
    if (chainCode)
    {
        memcpy(chainCode, m_ChainCode, ChainCodeSize);
    }
}

void CED25519Priv_BIP32::derivePrivateChildKey(CHILDPriKey& privChild, const unsigned int idx)
{
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned char buf[PrivateKeySize + 5];
    unsigned char pchIndex[4];
    const bool IsHardened = (idx & 0x80000000) != 0;
    int len, ret;

    privChild.index = idx;
    for (int i = 0; i < sizeof(pchIndex); i++)
        pchIndex[i] = (idx >> (i * 8)) & 0xff;

    if (IsHardened) {
        buf[0] = 0x00;
        memcpy(buf + 1, m_ExtPrivKey, PrivateKeySize);
        len = PrivateKeySize + 1;
    }
    else {
        buf[0] = 0x02;
        memcpy(buf + 1, m_PublicKey, PublicKeySize);
        len = PublicKeySize + 1;
    }
    memcpy(buf + len, pchIndex, sizeof(pchIndex));
    len += 4;
    HMAC512(buf, len, (unsigned char*)m_ChainCode, hmac);

    BIGNUM* modl = BN_new();
    BIGNUM* zl = BN_new();

    // Calculate Zleft = 8 * (( hmac[0..27] + ( extPrivKey[0..31] / 8 )) mod l ),
    // where l = 2^252 + 27742317777372353535851937790883648493.
    unsigned char secret[32];
    memcpy(&secret, &m_ExtPrivKey, 32);
    div_scalar_by_eight(secret);

    ret = aplusbmodl(zl, hmac, 28, secret, 32);
    BN_bn2lebinpad(zl, privChild.childprivkey, 32);

    // Check if Zleft is divisible by the base order n. If so, the child key is invalid.
    ret += amodl(modl, zl);
    privChild.valid = (ret == 0 && BN_is_zero(modl) == 0) ? 1 : 0;

    BN_free(zl);
    BN_free(modl);

    BIGNUM *zr = BN_new();
    // Calculate Zright = ( hmac[32..63] + extPrivKey[32..63] ) mod l,
    // where l = 2^252 + 27742317777372353535851937790883648493.
    aplusbmodl(zr, (hmac + 32), 32, (m_ExtPrivKey + 32), 32);
    BN_bn2lebinpad(zr, (privChild.childprivkey + 32), 32);
    BN_free(zr);

    // Derive the Child Chaincode
    if (IsHardened) {
        buf[0] = 0x01;
        memcpy(buf + 1, m_ExtPrivKey, PrivateKeySize);
        len = PrivateKeySize + 1;
    }
    else {
        buf[0] = 0x03;
        memcpy(buf + 1, m_PublicKey, PublicKeySize);
        len = PublicKeySize + 1;
    }
    memcpy(buf + len, pchIndex, sizeof(pchIndex));
    len += 4;
    HMAC512(buf, len, (unsigned char*)m_ChainCode, hmac);
    memcpy(privChild.childchaincode, (hmac + 32), 32);

    ed25519_DerivePublicKeyfromPrivate(privChild.childpubkey, privChild.childprivkey, NULL);
}

void CED25519Priv_BIP32::SignMessage(const unsigned char *msg, unsigned int msg_size, unsigned char *signature)
{
    unsigned char keyPair[64];
    memcpy(keyPair, m_PrivKey, 32);
    memcpy(keyPair + 32, m_PublicKey, 32);
#ifdef BIP32_ENABLE_BLINDING
 #ifndef BIP32_ENABLE_STATIC_BLINDING
    setSigningBlindingCTX();
    if (isSigningBlindingSet())
        ed25519_SignMessage(signature, keyPair, m_signing_blinding, msg, msg_size);
    else
        ed25519_SignMessage(signature, keyPair, NULL, msg, msg_size);
    freeSigningBlindingCTX();
#else
    ed25519_SignMessage(signature, keyPair, &edp_signature_blinding, msg, msg_size);
 #endif
#else
    ed25519_SignMessage(signature, keyPair, NULL, msg, msg_size);
#endif
}

void CED25519Priv_BIP32::SignMessage_BIP32(const unsigned char *msg, unsigned int msg_size, unsigned char *signature)
{
#ifdef BIP32_ENABLE_BLINDING
 #ifndef BIP32_ENABLE_STATIC_BLINDING
    setSigningBlindingCTX();
    if (isSigningBlindingSet())
        ed25519_SignMessage_BIP32(signature, m_PublicKey, m_ExtPrivKey, m_signing_blinding, msg, msg_size);
    else
        ed25519_SignMessage_BIP32(signature, m_PublicKey, m_ExtPrivKey, NULL, msg, msg_size);
    freeSigningBlindingCTX();
#else
    ed25519_SignMessage_BIP32(signature, m_PublicKey, m_ExtPrivKey, &edp_signature_blinding, msg, msg_size);
 #endif
#else
    ed25519_SignMessage_BIP32(signature, m_PublicKey, m_ExtPrivKey, NULL, msg, msg_size);
#endif
}

bool CED25519Priv_BIP32::VerifySignature(const unsigned char *msg, unsigned int msg_size, const unsigned char *signature)
{
    return ed25519_VerifySignature(signature, m_PublicKey, msg, msg_size) == 1;
}

#ifdef BIP32_ENABLE_BLINDING
void CED25519Priv_BIP32::setGenkeyBlindingCTX()
{
    unsigned char seed[64]; 
    GetRandomBytes(seed, sizeof(seed));
    m_genkey_blinding = (BLINDING_CTX *)ed25519_Blinding_Init(NULL, seed, sizeof(seed));
}

void CED25519Priv_BIP32::setSigningBlindingCTX()
{
    unsigned char seed[64];
    GetRandomBytes(seed, sizeof(seed));
    m_signing_blinding = (BLINDING_CTX*)ed25519_Blinding_Init(NULL, seed, sizeof(seed));
}

void CED25519Priv_BIP32::freeGenkeyBlindingCTX()
{
    if (isGenkeyBlindingSet())
        ed25519_Blinding_Finish(m_genkey_blinding);
}

void CED25519Priv_BIP32::freeSigningBlindingCTX()
{
    if (isSigningBlindingSet())
        ed25519_Blinding_Finish(m_signing_blinding);
}

bool CED25519Priv_BIP32::isGenkeyBlindingSet()
{
    if (m_genkey_blinding != NULL)
        return true;
    return false;
}

bool CED25519Priv_BIP32::isSigningBlindingSet()
{
    if (m_signing_blinding != NULL)
        return true;
    return false;
}
#endif

CED25519Pub_BIP32::CED25519Pub_BIP32(const unsigned char *publicKey)
{
    SetNull();
    SetPublicKey(publicKey);
}

CED25519Pub_BIP32::CED25519Pub_BIP32(const unsigned char *publicKey, const unsigned char *chainCode)
{
    SetNull();
    SetPublicKey(publicKey);
    SetChainCode(chainCode);
}

CED25519Pub_BIP32::~CED25519Pub_BIP32()
{
    SetNull();
}

void CED25519Pub_BIP32::SetNull()
{
    memset(m_PublicKey, 0, PublicKeySize);
    memset(m_ChainCode, 0, ChainCodeSize);
}

void CED25519Pub_BIP32::GetPublicKeyBytes(unsigned char *pubKey)
{
    if (pubKey) 
    {
        memcpy(pubKey, m_PublicKey, PublicKeySize);
    }
}

void CED25519Pub_BIP32::SetPublicKey(const unsigned char *pubKey)
{
    if (pubKey)
    {
        memcpy(m_PublicKey, pubKey, PublicKeySize);
    }
}

void CED25519Pub_BIP32::SetChainCode(const unsigned char *chaincode)
{
    if (chaincode) {
        memcpy(m_ChainCode, chaincode, ChainCodeSize);
    }
}

int CED25519Pub_BIP32::DerivePublicKey(CHILDPubKey& pubChild, const unsigned int idx)
{
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned char parentPubKey[PublicKeySize];
    unsigned char buf[PublicKeySize + 5];
    unsigned char pchIndex[4];
    int len;

    if ((idx & 0x80000000) != 0)
        return -1;

    pubChild.index = idx;
    for (int i = 0; i < sizeof(pchIndex); i++)
        pchIndex[i] = (idx >> (i * 8)) & 0xff;

    buf[0] = 0x02;
    GetPublicKeyBytes(parentPubKey);
    memcpy(buf + 1, parentPubKey, PublicKeySize);
    len = PublicKeySize + 1;
    memcpy(buf + len, pchIndex, sizeof(pchIndex));
    len += 4;
    HMAC512(buf, len, (unsigned char*)m_ChainCode, hmac);

    // Calculate ChildPubKey = (8*ZL)*B + parentPubKey
    unsigned char ZL[PublicKeySize] = { 0 };
    BIGNUM *zl = BN_new();
    m8add(zl, hmac, 28, NULL, 0);
    BN_bn2lebinpad(zl, ZL, 32);
    BN_free(zl);

    U_WORD t[K_WORDS];
    ecp_BytesToWords(t, ZL);
    const unsigned char one[PublicKeySize] = { 0x1, };
    Affine_POINT Q, T;
    ed25519_UnpackPoint(&Q, parentPubKey);
    edp_dualPointMultiply(&T, ZL, one, &Q);
    ecp_EncodeInt(pubChild.childpubkey, T.y, (U8)(T.x[0] & 1));

    // Check that (x, y) is not equal to (0, 1)
    bool bTx = ecp_CmpNE(T.x, _w_Zero);
    bool bTy = ecp_CmpNE(T.y, _w_One);
    pubChild.valid = (bTx == false && bTy == false) ? 0 : 1;

    // Derive the Child Chaincode
    buf[0] = 0x03;
    memcpy(buf + 1, parentPubKey, PublicKeySize);
    len = PublicKeySize + 1;
    memcpy(buf + len, pchIndex, sizeof(pchIndex));
    len += 4;
    HMAC512(buf, len, (unsigned char*)m_ChainCode, hmac);
    memcpy(pubChild.childchaincode, (hmac + 32), 32);

    return 0;
}

CHILDPriKey::CHILDPriKey()
{
    SetNull();
}

CHILDPriKey::~CHILDPriKey()
{
    SetNull();
}

void CHILDPriKey::SetNull()
{
    index = 0;
    valid = 0;
    memset(childpubkey, 0, PublicKeySize);
    memset(childprivkey, 0, PrivateKeySize);
    memset(childchaincode, 0, ChainCodeSize);
}

void CHILDPriKey::SignMessage_BIP32(const unsigned char *msg, unsigned int msg_size, unsigned char *signature)
{
#ifdef BIP32_ENABLE_BLINDING
 #ifndef BIP32_ENABLE_STATIC_BLINDING
    SetSigningBlindingCTX();
    if (IsSigningBlindingSet())
        ed25519_SignMessage_BIP32(signature, childpubkey, childprivkey, m_signing_blinding, msg, msg_size);
    else
        ed25519_SignMessage_BIP32(signature, childpubkey, childprivkey, NULL, msg, msg_size);
    FreeSigningBlindingCTX();
 #else
    ed25519_SignMessage_BIP32(signature, childpubkey, childprivkey, &edp_signature_blinding, msg, msg_size);
 #endif
#else
    ed25519_SignMessage_BIP32(signature, childpubkey, childprivkey, NULL, msg, msg_size);
#endif
}

#ifdef BIP32_ENABLE_BLINDING
void CHILDPriKey::SetSigningBlindingCTX()
{
    unsigned char seed[64];
    GetRandomBytes(seed, sizeof(seed));
    m_signing_blinding = (BLINDING_CTX*)ed25519_Blinding_Init(NULL, seed, sizeof(seed));
}

void CHILDPriKey::FreeSigningBlindingCTX()
{
    if (IsSigningBlindingSet())
        ed25519_Blinding_Finish(m_signing_blinding);
}

bool CHILDPriKey::IsSigningBlindingSet()
{
    if (m_signing_blinding != NULL)
        return true;
    return false;
}
#endif

void CHILDPubKey::SetNull()
{
    index = 0;
    valid = 0;
    memset(childpubkey, 0, PublicKeySize);
    memset(childchaincode, 0, ChainCodeSize);
}

bool CHILDPubKey::VerifySignature(const unsigned char * msg, unsigned int msg_size, const unsigned char * signature)
{
    return ed25519_VerifySignature(signature, childpubkey, msg, msg_size) == 1;
}
