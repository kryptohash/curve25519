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
#ifndef __ed25519_bip32_utils_h__
#define __ed25519_bip32_utils_h__

#include "../source/BaseTypes.h"
#include "../source/curve25519_mehdi.h"
#include <openssl/hmac.h>
#include <openssl/bn.h>

const PA_POINT   _w_base_folding8[256];
#define _w_Zero  _w_base_folding8[0].T2d
#define _w_One   _w_base_folding8[0].YpX


void edp_dualPointMultiply(Affine_POINT *r, const unsigned char *a, const unsigned char *b, const Affine_POINT *q);
void * HMAC512(unsigned char *dataIn, size_t dataLen, unsigned char *key, unsigned char *dataOut);
int amodl(BIGNUM *r, const BIGNUM *a);
int aplusbmodl(BIGNUM* r, const unsigned char* a_str, const size_t a_len, const unsigned char* b_str, const size_t b_len);
int m8add(BIGNUM *r, const unsigned char *a_str, const size_t a_len, const unsigned char *b_str, const size_t b_len);
int addMod2pow256(BIGNUM *r, const unsigned char *a_str, const size_t a_len, const unsigned char *b_str, const size_t b_len);

#endif // __ed25519_bip32_utils_h__