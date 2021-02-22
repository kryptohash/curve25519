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
#ifndef __ed25519_bip32_h__
#define __ed25519_bip32_h__

#include "ed25519.h"

#define BIP32_ENABLE_BLINDING 1

class CHILDPubKey
{
public:
    CHILDPubKey() { SetNull(); }
    ~CHILDPubKey() { SetNull(); }

    enum { PublicKeySize = 32, ChainCodeSize = 32 };

    void SetNull();
    bool VerifySignature(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        const unsigned char* signature);    /* IN: [64 bytes] signature (R,S) */

    unsigned int index;
    unsigned int valid;
    unsigned char childpubkey[PublicKeySize];
    unsigned char childchaincode[ChainCodeSize];
};

class CED25519Pub_BIP32
{
public:
    CED25519Pub_BIP32(const unsigned char *publicKey);
    CED25519Pub_BIP32(const unsigned char *publicKey, const unsigned char *chainCode);
    ~CED25519Pub_BIP32();

    enum { PublicKeySize = 32, ChainCodeSize = 32 };

    void SetNull();
    void GetPublicKeyBytes(unsigned char *pubKey);
    void SetPublicKey(const unsigned char *pubKey);
    void SetChainCode(const unsigned char *chaincode);
    int DerivePublicKey(CHILDPubKey& pubChild, const unsigned int idx);

private:
    unsigned char m_PublicKey[PublicKeySize];
    unsigned char m_ChainCode[ChainCodeSize];
};

class CHILDPriKey
{
public:
    CHILDPriKey();
    ~CHILDPriKey();

    enum { PublicKeySize = 32, PrivateKeySize = 64, ChainCodeSize = 32 };

    void SetNull();
    void SignMessage_BIP32(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        unsigned char* signature);          /* OUT: [64 bytes] signature (R,S) */

    unsigned int index;
    unsigned int valid;
    unsigned char childpubkey[PublicKeySize];
    unsigned char childprivkey[PrivateKeySize];
    unsigned char childchaincode[ChainCodeSize];

    void getExtPrivateKeyBytes(unsigned char* extPrivKey);
    void getPublicKeyBytes(unsigned char* pubKey);
    void getChainCodeBytes(unsigned char* chainCode);

#ifdef BIP32_ENABLE_BLINDING
    // Ugly hack to take advantage of the existing Blinding Context 'C' structure (please don't scold me).
    // ToDo: Create a Class for the Blinding Context.
    struct BLINDING_CTX {
        unsigned int bl[8];
        unsigned int zr[8];
        struct PE_POINT {
            unsigned int YpX[8];
            unsigned int YmX[8];
            unsigned int T2d[8];
            unsigned int Z2[8];
        } BP;
    } *m_signing_blinding;

    void SetSigningBlindingCTX();
    void FreeSigningBlindingCTX();
    bool IsSigningBlindingSet();
#endif
};

class CED25519Priv_BIP32
{
public:
    /* Constructors/Destructor */
    CED25519Priv_BIP32();
    CED25519Priv_BIP32(const unsigned char *secret);
    CED25519Priv_BIP32(const unsigned char *extPrivateKey, const unsigned char *chainCode);
    ~CED25519Priv_BIP32();
    
    enum { SecretSize = 32, PublicKeySize = 32, PrivateKeySize = 64, SignatureBytes = 64, ChainCodeSize = 32 };

    void SetNull();
    void getExtPrivateKeyBytes(unsigned char* extPrivKey);
    void getPublicKeyBytes(unsigned char *pubKey);
    void deriveRootChainCode();
    void getChainCodeBytes(unsigned char *chainCode);
    void derivePrivateChildKey(CHILDPriKey& privChild, const unsigned int idx);
    void SignMessage(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        unsigned char* signature);          /* OUT: [64 bytes] signature (R,S) */
    void SignMessage_BIP32(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        unsigned char* signature);          /* OUT: [64 bytes] signature (R,S) */
    bool VerifySignature(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        const unsigned char* signature);    /* IN: [64 bytes] signature (R,S) */
private:
    unsigned char m_PublicKey[PublicKeySize];
    unsigned char m_PrivKey[SecretSize];
    unsigned char m_ExtPrivKey[PrivateKeySize];
    unsigned char m_ChainCode[ChainCodeSize];

#ifdef BIP32_ENABLE_BLINDING
    // Ugly hack to take advantage of the existing Blinding Context 'C' structure (please don't scold me).
    // ToDo: Create a Class for the Blinding Context.
    struct BLINDING_CTX {
        unsigned int bl[8];
        unsigned int zr[8];
        struct PE_POINT {
            unsigned int YpX[8];
            unsigned int YmX[8];
            unsigned int T2d[8];
            unsigned int Z2[8];
        } BP;
    } *m_genkey_blinding, *m_signing_blinding;

    void setGenkeyBlindingCTX();
    void setSigningBlindingCTX();
    void freeGenkeyBlindingCTX();
    void freeSigningBlindingCTX();
    bool isGenkeyBlindingSet();
    bool isSigningBlindingSet();
#endif
};


#endif // __ed25519_bip32_h__
