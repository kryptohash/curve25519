// ed25519_bip32_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../C++/ed25519_bip32.h"
#include "../../C++/ed25519_bip32_utils.h"
#include "../../C++/custom_blinds.h"

#include "openssl\sha.h"
#include "openssl\rand.h"

#include <string>
#include <iostream>
#include <iomanip>

using namespace std;

int main()
{
    unsigned char hash[32] = { 0 };
    const string MasterSecret = "This Is My Master Secret Phrase!";
    const string Message = "Hello World";
    unsigned char Signature[64];

    cout << "Testing cofactor adjustment .... " << endl;
    {
        unsigned char rng_bytes[32], data_bytes[32];

        RAND_bytes(rng_bytes, sizeof(rng_bytes));
        rng_bytes[31] &= 0b00011111;
        memcpy(&data_bytes, rng_bytes, 32);
        mul_scalar_by_eight(&data_bytes[0]);
        div_scalar_by_eight(&data_bytes[0]);
        if (memcmp(&data_bytes, &rng_bytes, 32) != 0)
            cout << "Cofactor adjustment mul/div by 8 test ... FAILED";
        else
            cout << "Cofactor adjustment mul/div by 8 test ... PASSED";
        cout << endl;

        RAND_bytes(rng_bytes, sizeof(rng_bytes));
        rng_bytes[0] &= 0b11111000;
        memcpy(&data_bytes, rng_bytes, 32);
        div_scalar_by_eight(&data_bytes[0]);
        mul_scalar_by_eight(&data_bytes[0]);
        if (memcmp(&data_bytes, &rng_bytes, 32) != 0)
            cout << "cofactor adjustment div/mul by 8 test ... FAILED";
        else
            cout << "Cofactor adjustment div/mul by 8 test ... PASSED";
        cout << endl << endl;
    }

    SHA256(reinterpret_cast<const unsigned char*>(MasterSecret.c_str()), MasterSecret.length(), hash);
    cout << "Testing Root private/public key pair .... ";
    {
        CED25519Priv_BIP32 testKey = CED25519Priv_BIP32(hash);

        testKey.SignMessage(reinterpret_cast<const unsigned char *>(Message.c_str()), (unsigned int)Message.length(), Signature);
        if (testKey.VerifySignature(reinterpret_cast<const unsigned char *>(Message.c_str()), (unsigned int)Message.length(), Signature))
            cout << "Signature Verified" << endl;
        else
            cout << "Signature Failed Verification" << endl;

        cout << "Testing Extended Root private key ....... ";
        testKey.SignMessage_BIP32(reinterpret_cast<const unsigned char *>(Message.c_str()), (unsigned int)Message.length(), Signature);
        if (testKey.VerifySignature(reinterpret_cast<const unsigned char *>(Message.c_str()), (unsigned int)Message.length(), Signature))
            cout << "Signature Verified" << endl;
        else
            cout << "Signature Failed Verification" << endl;
        cout << endl;
    }

    cout << "Testing Hardened Child Private Key and Chain Code.... ";
    {
        const unsigned char D0_Priv[64] =
        {
            0xf8, 0xa2, 0x92, 0x31, 0xee, 0x38, 0xd6, 0xc5, 0xbf, 0x71, 0x5d, 0x5b, 0xac, 0x21, 0xc7, 0x50,
            0x57, 0x7a, 0xa3, 0x79, 0x8b, 0x22, 0xd7, 0x9d, 0x65, 0xbf, 0x97, 0xd6, 0xfa, 0xde, 0xa1, 0x5a,
            0xdc, 0xd1, 0xee, 0x1a, 0xbd, 0xf7, 0x8b, 0xd4, 0xbe, 0x64, 0x73, 0x1a, 0x12, 0xde, 0xb9, 0x4d,
            0x36, 0x71, 0x78, 0x41, 0x12, 0xeb, 0x6f, 0x36, 0x4b, 0x87, 0x18, 0x51, 0xfd, 0x1c, 0x9a, 0x24
        };
        const unsigned char D0_ChainCode[32] =
        {
            0x73, 0x84, 0xdb, 0x9a, 0xd6, 0x00, 0x3b, 0xbd, 0x08, 0xb3, 0xb1, 0xdd, 0xc0, 0xd0, 0x7a, 0x59,
            0x72, 0x93, 0xff, 0x85, 0xe9, 0x61, 0xbf, 0x25, 0x2b, 0x33, 0x12, 0x62, 0xed, 0xdf, 0xad, 0x0d
        };
        const unsigned char D1_Priv[64] =
        {
            0x60, 0xd3, 0x99, 0xda, 0x83, 0xef, 0x80, 0xd8, 0xd4, 0xf8, 0xd2, 0x23, 0x23, 0x9e, 0xfd, 0xc2,
            0xb8, 0xfe, 0xf3, 0x87, 0xe1, 0xb5, 0x21, 0x91, 0x37, 0xff, 0xb4, 0xe8, 0xfb, 0xde, 0xa1, 0x5a,
            0x38, 0x04, 0x11, 0x96, 0x1b, 0x3f, 0x4c, 0xf8, 0xc0, 0x81, 0x0c, 0x1f, 0x39, 0xd6, 0xe5, 0x94,
            0x7c, 0x01, 0xf7, 0x2a, 0xf4, 0xd0, 0x97, 0xa1, 0xe3, 0xe2, 0xbc, 0xa6, 0x3d, 0x91, 0x40, 0x06
        };
        const unsigned char D1_ChainCode[32] =
        {
            0x60, 0x87, 0x63, 0x77, 0x0e, 0xdd, 0xf7, 0x72, 0x48, 0xab, 0x65, 0x29, 0x84, 0xb2, 0x1b, 0x84,
            0x97, 0x60, 0xd1, 0xda, 0x74, 0xa6, 0xf5, 0xbd, 0x63, 0x3c, 0xe4, 0x1a, 0xdc, 0xee, 0xf0, 0x7a
        }; 

        CED25519Priv_BIP32 rootKey = CED25519Priv_BIP32(D0_Priv, D0_ChainCode);
        CHILDPriKey childPrivKey = CHILDPriKey();
        rootKey.derivePrivateChildKey(childPrivKey, 0x80000000);
        if (CRYPTO_memcmp(childPrivKey.childprivkey, D1_Priv, CHILDPriKey::PrivateKeySize) == 0 &&
            CRYPTO_memcmp(childPrivKey.childchaincode, D1_ChainCode, CHILDPriKey::ChainCodeSize) == 0)
            cout << "Passed" << endl;
        else
            cout << "Failed" << endl;
        cout << endl;
    }

    cout << "Testing 100 sequential non-Hardened Child keys." << endl;
    {
        CED25519Priv_BIP32 rootPrivateKey = CED25519Priv_BIP32(hash);
        unsigned char pk[32], cc[32];
        rootPrivateKey.getPublicKeyBytes(pk);
        rootPrivateKey.getChainCodeBytes(cc);
        CED25519Pub_BIP32 rootPublicKey = CED25519Pub_BIP32(pk, cc);

        for (int i = 0; i < 100; i++) 
        {
            bool ret;
            cout << "Index " << i << " ... ";
            {
                // Sign the message using a newly derived Child Private Key.
                CHILDPriKey childPrivKey = CHILDPriKey();
                rootPrivateKey.derivePrivateChildKey(childPrivKey, i);
                if (!childPrivKey.valid) {
                    cout << "Invalid Private Child Key at index: " << i << endl;
                    break;
                }
                childPrivKey.SignMessage_BIP32(reinterpret_cast<const unsigned char*>(Message.c_str()), (unsigned int)Message.length(), Signature);

                // Verify the signature using a newly derived Child Public Key.
                CHILDPubKey childPubKey = CHILDPubKey();
                rootPublicKey.DerivePublicKey(childPubKey, i);
                if (!childPubKey.valid) {
                    cout << "Invalid Public Child Key at index: " << i << endl;
                    break;
                }
                ret = childPubKey.VerifySignature(reinterpret_cast<const unsigned char*>(Message.c_str()), (unsigned int)Message.length(), Signature);
            }
            if (ret) {
                cout << "Signature Verified" << endl;
            }
            else {
                cout << "Signature Failed Verification" << endl;
                break;
            }
        }
        cout << endl;
    }

    cout << "Testing 100 Random Hardened Child keys." << endl;
    {
        unsigned char pk[32], cc[32], epk[64];
        bool ret;
        int i, j, randomDepth, randomIndex;

        // Create a "root" Private/Public keypair using the hash of our secret passphrase.
        {
            CED25519Priv_BIP32 rootPrivateKey = CED25519Priv_BIP32(hash);
            // Save the Extended Private Key, Public Key and Chain Code to epk[], pk[] and cc[] respectively.
            rootPrivateKey.getPublicKeyBytes(pk);
            rootPrivateKey.getChainCodeBytes(cc);
            rootPrivateKey.getExtPrivateKeyBytes(epk);
        }

        CHILDPriKey childPrivKey = CHILDPriKey();
        CHILDPubKey childPubKey = CHILDPubKey();

        for (j = 0; j < 100; j++)
        {
            randomDepth = rand() % 1000;
            randomIndex = rand() % 1000;

            cout << "Child keys at depth: " << setfill('0') << setw(5) << randomDepth << ", Index: " << setfill('0') << setw(5) << randomIndex << " ... ";
            for (i = 0; i < randomDepth; i++)
            {
                // Create the "root" using saved epk[], pk[] and cc[].
                CED25519Priv_BIP32 currentRoot = CED25519Priv_BIP32(epk, cc);

                // Derive a Hardened Child Extended Private Key, Public Key and Chain Code.
                currentRoot.derivePrivateChildKey(childPrivKey, (i | 0x80000000));
                if (!childPrivKey.valid) {
                    cout << endl << "Invalid Hardened Private Child Key" << endl;
                    break;
                }
                // Save the derived Extended Private Key, Public Key and Chain Code.
                // They will become our "root" in the next iteration.
                childPrivKey.getExtPrivateKeyBytes(epk);
                childPrivKey.getPublicKeyBytes(pk);
                childPrivKey.getChainCodeBytes(cc);
            }

            // Create the root using saved epk[], pk[] and cc[].
            CED25519Priv_BIP32 newRootPrivKey = CED25519Priv_BIP32(epk, cc);
            CED25519Pub_BIP32 newRootPublicKey = CED25519Pub_BIP32(pk, cc);

            newRootPrivKey.derivePrivateChildKey(childPrivKey, randomIndex);
            if (!childPrivKey.valid) {
                cout << "Invalid Private Child Key at index: " << randomIndex << endl;
            }
            childPrivKey.SignMessage_BIP32(reinterpret_cast<const unsigned char*>(Message.c_str()), (unsigned int)Message.length(), Signature);

            // Verify the signature using a newly derived Child Public Key.
            newRootPublicKey.DerivePublicKey(childPubKey, randomIndex);
            if (!childPubKey.valid) {
                cout << "Invalid Public Child Key at index: " << randomIndex << endl;
            }
            ret = childPubKey.VerifySignature(reinterpret_cast<const unsigned char*>(Message.c_str()), (unsigned int)Message.length(), Signature);
            if (ret) {
                cout << "Signature Verified" << endl;
            }
            else {
                cout << "Signature Failed Verification" << endl;
            }
        }
        cout << endl;
    }

    return 0;
}

