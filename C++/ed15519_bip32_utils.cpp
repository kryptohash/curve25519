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

#include "ed25519_bip32_utils.h"

const U_WORD _w_2d[K_WORDS] = W256(0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A, 0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC);

// point R = a*P + b*Q  where P is base point
void edp_dualPointMultiply(Affine_POINT *r, const unsigned char *a, const unsigned char *b, const Affine_POINT *q)
{
    int i, j;
    M32 k;
    Ext_POINT S;
    PA_POINT U;
    PE_POINT V;

    /* U = pre-compute(Q) */
    ecp_AddReduce(U.YpX, q->y, q->x);
    ecp_SubReduce(U.YmX, q->y, q->x);
    ecp_MulReduce(U.T2d, q->y, q->x);
    ecp_MulReduce(U.T2d, U.T2d, _w_2d);

    /* set V = pre-compute(P + Q) */
    ecp_Copy(S.x, q->x);
    ecp_Copy(S.y, q->y);
    ecp_SetValue(S.z, 1);
    ecp_MulReduce(S.t, S.x, S.y);
    edp_AddBasePoint(&S);   /* S = P + Q */
                            /*  */
    ecp_AddReduce(V.YpX, S.y, S.x);
    ecp_SubReduce(V.YmX, S.y, S.x);
    ecp_MulReduce(V.T2d, S.t, _w_2d);
    ecp_AddReduce(V.Z2, S.z, S.z);

    /* Set S = (0,1) */
    ecp_SetValue(S.x, 0);
    ecp_SetValue(S.y, 1);
    ecp_SetValue(S.z, 1);
    ecp_SetValue(S.t, 0);

    for (i = 32; i-- > 0;)
    {
        k.u8.b0 = a[i];
        k.u8.b1 = b[i];
        for (j = 0; j < 8; j++)
        {
            edp_DoublePoint(&S);
            switch (k.u32 & 0x8080)
            {
            case 0x0080: edp_AddBasePoint(&S); break;
            case 0x8000: edp_AddAffinePoint(&S, &U); break;
            case 0x8080: edp_AddPoint(&S, &S, &V); break;
            }
            k.u32 <<= 1;
        }
    }
    ecp_Inverse(S.z, S.z);
    ecp_MulMod(r->x, S.x, S.z);
    ecp_MulMod(r->y, S.y, S.z);
}


// r = a mod l,  where l = 2^252 + 27742317777372353535851937790883648493.
int amodl(BIGNUM *r, const BIGNUM *a)
{
    BIGNUM *l, *m;
    BN_CTX *ctx;
    int ret = 0;

    if (r == NULL || a == NULL)
        return 1;

    l = BN_new();
    m = BN_new();
    ctx = BN_CTX_new();

    if (l == NULL || m == NULL || ctx == NULL)
        ret = 1;
    else {
        BN_set_bit(l, 252);
        BN_dec2bn(&m, "27742317777372353535851937790883648493");
        BN_add(l, l, m);
        BN_mod(r, a, l, ctx);
    }

    if (m)
        BN_free(m);
    if (l)
        BN_free(l);
    if (ctx)
        BN_CTX_free(ctx);

    return 0;
}


// r = 8 * ((a + b) mod l),  where l = 2^252 + 27742317777372353535851937790883648493.
int aplusbmodl(BIGNUM* r, const unsigned char* a_str, const size_t a_len, const unsigned char* b_str, const size_t b_len)
{
    BIGNUM *a, *b, *e, *m, *s;
    BN_CTX* ctx;
    int ret = 0;

    if (r == NULL || a_str == NULL)
        return 1;

    a = BN_lebin2bn(a_str, (int)a_len, NULL);
    if (b_str == NULL || b_len == 0) {
        b = BN_new();
        BN_zero(b);
    }
    else {
        b = BN_lebin2bn(b_str, (int)b_len, NULL);
    }
    e = BN_new();
    m = BN_new();
    s = BN_new();
    ctx = BN_CTX_new();

    if (a == NULL || b == NULL || e == NULL || m == NULL || s == NULL || ctx == NULL)
        ret = 1;
    else {
        BN_add(e, a, b);
        ret = amodl(m, e);
        if (ret == 0) {
            BN_dec2bn(&s, "8");
            BN_mul(r, m, s, ctx);
        }
    }

    if (a)
        BN_free(a);
    if (b)
        BN_free(b);
    if (e)
        BN_free(e);
    if (m)
        BN_free(m);
    if (s)
        BN_free(s);
    if (ctx)
        BN_CTX_free(ctx);

    return ret;
}


// r = 8*a + b
int m8add(BIGNUM *r, const unsigned char *a_str, const size_t a_len, const unsigned char *b_str, const size_t b_len)
{
    BIGNUM *a, *b, *e, *m;
    BN_CTX *ctx;
    int ret = 0;

    if (r == NULL || a_str == NULL)
        return 1;

    a = BN_lebin2bn(a_str, (int)a_len, NULL);
    if (b_str == NULL || b_len == 0) {
        b = BN_new();
        BN_zero(b);
    }
    else {
        b = BN_lebin2bn(b_str, (int)b_len, NULL);
    }
    e = BN_new();
    m = BN_new();
    ctx = BN_CTX_new();

    if (a == NULL || b == NULL || e == NULL || m == NULL || ctx == NULL)
        ret = 1;
    else {
        BN_dec2bn(&m, "8");
        BN_mul(e, a, m, ctx);
        BN_add(r, b, e);
    }

    if (a)
        BN_free(a);
    if (b)
        BN_free(b);
    if (e)
        BN_free(e);
    if (m)
        BN_free(m);
    if (ctx)
        BN_CTX_free(ctx);

    return ret;
}

// r = (a + b) mod 2^256
int addMod2pow256(BIGNUM *r, const unsigned char *a_str, const size_t a_len, const unsigned char *b_str, const size_t b_len)
{
    BIGNUM *a, *b, *d, *m;
    BN_CTX *ctx;
    int ret = 0;

    if (r == NULL || a_str == NULL || b_str == NULL)
        return 1;

    a = BN_lebin2bn(a_str, (int)a_len, NULL);
    b = BN_lebin2bn(b_str, (int)b_len, NULL);
    d = BN_new();
    m = BN_new();
    ctx = BN_CTX_new();

    if (a == NULL || b == NULL || d == NULL || m == NULL || ctx == NULL)
        ret = 1;
    else {
        BN_add(d, a, b);
        BN_set_bit(m, 256);
        BN_mod(r, d, m, ctx);
    }

    if (m)
        BN_free(m);
    if (a)
        BN_free(a);
    if (b)
        BN_free(b);
    if (d)
        BN_free(d);
    if (ctx)
        BN_CTX_free(ctx);

    return ret;
}



void * HMAC512(unsigned char *dataIn, size_t dataLen, unsigned char *key, unsigned char *dataOut)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned int len;
    unsigned char *md = dataOut;

    if (md == NULL)
        md = (unsigned char *)calloc(1, EVP_MAX_MD_SIZE);

    if (md) {
        HMAC_Init(ctx, (const void *)key, 32, EVP_sha512());
        HMAC_Update(ctx, dataIn, dataLen);
        HMAC_Final(ctx, md, &len);
        HMAC_CTX_free(ctx);
    }

    return md;
}
