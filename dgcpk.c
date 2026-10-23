/* ------------------------------------------------------------------ *
 *  dgcpk.c - the DGC archiver (the packer)
 *
 *  It writes the same format as DGCA / DGC Archiver v1.10 (dgcac.exe):
 *  a DGCA chunk with a DATA chunk (the compressed blocks) and an INFO
 *  chunk (the IARC, the IFDT and the IFNM).
 *
 *  The format is described in NOTES-dgca-format.md; the codec is the
 *  inverse of the one in dgcunp.c:
 *      the data -> the pre-transform (an LZ77 with an implicit distance)
 *                 -> the literals + the model stream
 *              -> the CM literal coder (stream A) and the gamma symbol
 *                 coder (stream B)
 *
 *  usage: dgcpk a [-n] [-f] [-i] [-r<n>] <archive> <file>...
 *         -n     do not compress (the blocks are stored)
 *         -f     one block per file (not the solid mode)
 *         -i     identity: do not write the time stamps
 *         -r<n>  append the recovery data (the parity table)
 * ------------------------------------------------------------------ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys\stat.h>
#include <windows.h>
#include <math.h>

typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned short     u16;
typedef __int64            u64;

/* ----------------------------- the CRC-32 ----------------------------- */
static u32 crc_tab[256];
static int crc_ready = 0;

static void crc_init(void)
{
    u32 i;
    int k;
    for (i = 0; i < 256; i++) {
        u32 v = i;
        for (k = 0; k < 8; k++)
            v = (v & 1) ? (0xEDB88320u ^ (v >> 1)) : (v >> 1);
        crc_tab[i] = v;
    }
    crc_ready = 1;
}

static u32 crc32_update(u32 crc, const u8 *p, u32 n)
{
    u32 i;
    if (!crc_ready) crc_init();
    for (i = 0; i < n; i++)
        crc = crc_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc;
}

static u32 crc32_buf(const u8 *p, u32 n)
{
    return crc32_update(0xFFFFFFFFu, p, n) ^ 0xFFFFFFFFu;
}

/* ----------------------------- the buffer ----------------------------- */
typedef struct { u8 *p; u32 len, cap; } buf_t;

static void bput(buf_t *b, const void *d, u32 n)
{
    if (b->len + n > b->cap) {
        u32 nc = b->cap ? b->cap * 2 : 4096;
        u8 *np;
        while (nc < b->len + n) nc *= 2;
        np = (u8 *)realloc(b->p, nc);
        if (!np) { fprintf(stderr, "out of memory\n"); exit(2); }
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

static void bput8(buf_t *b, u8 v) { bput(b, &v, 1); }
static void bput16(buf_t *b, u16 v) { bput(b, &v, 2); }
static void bput32(buf_t *b, u32 v) { bput(b, &v, 4); }
static void bput64(buf_t *b, u64 v) { bput(b, &v, 8); }
static void bputz(buf_t *b, u32 n) { while (n--) bput8(b, 0); }

static u32 rd32le(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static u64 rd64le(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }

/* ------------------------------------------------------------------ *
 *  The crypto of DGCA v1.10 (the "SecureCryptograph" class)
 *
 *  It is a self inverse XOR stream:
 *      encrypt: in=buf[i]; k1=prng(); k2=prng();
 *               buf[i] = in^k1^k2 ;  feedback = in^k1
 *      decrypt: in=buf[i]; k1=prng(); k2=prng();
 *               buf[i] = in^k1^k2 ;  feedback = in^k2
 *  The key stream comes from a SHA-512 that is stretched over 39 rounds
 *  and used to seed a MT19937 variant.  The SHA-512 of the binary keeps
 *  the standard state and the standard K constants, but every 8 byte
 *  group of the message is byte reversed when it is loaded.
 * ------------------------------------------------------------------ */
typedef unsigned __int64 u64x;   /* the crypto of DGCA v1.10 */

static const u64x sha512_k[80] = {
    0x428A2F98D728AE22UI64, 0x7137449123EF65CDUI64, 0xB5C0FBCFEC4D3B2FUI64,
    0xE9B5DBA58189DBBCUI64, 0x3956C25BF348B538UI64, 0x59F111F1B605D019UI64,
    0x923F82A4AF194F9BUI64, 0xAB1C5ED5DA6D8118UI64, 0xD807AA98A3030242UI64,
    0x12835B0145706FBEUI64, 0x243185BE4EE4B28CUI64, 0x550C7DC3D5FFB4E2UI64,
    0x72BE5D74F27B896FUI64, 0x80DEB1FE3B1696B1UI64, 0x9BDC06A725C71235UI64,
    0xC19BF174CF692694UI64, 0xE49B69C19EF14AD2UI64, 0xEFBE4786384F25E3UI64,
    0x0FC19DC68B8CD5B5UI64, 0x240CA1CC77AC9C65UI64, 0x2DE92C6F592B0275UI64,
    0x4A7484AA6EA6E483UI64, 0x5CB0A9DCBD41FBD4UI64, 0x76F988DA831153B5UI64,
    0x983E5152EE66DFABUI64, 0xA831C66D2DB43210UI64, 0xB00327C898FB213FUI64,
    0xBF597FC7BEEF0EE4UI64, 0xC6E00BF33DA88FC2UI64, 0xD5A79147930AA725UI64,
    0x06CA6351E003826FUI64, 0x142929670A0E6E70UI64, 0x27B70A8546D22FFCUI64,
    0x2E1B21385C26C926UI64, 0x4D2C6DFC5AC42AEDUI64, 0x53380D139D95B3DFUI64,
    0x650A73548BAF63DEUI64, 0x766A0ABB3C77B2A8UI64, 0x81C2C92E47EDAEE6UI64,
    0x92722C851482353BUI64, 0xA2BFE8A14CF10364UI64, 0xA81A664BBC423001UI64,
    0xC24B8B70D0F89791UI64, 0xC76C51A30654BE30UI64, 0xD192E819D6EF5218UI64,
    0xD69906245565A910UI64, 0xF40E35855771202AUI64, 0x106AA07032BBD1B8UI64,
    0x19A4C116B8D2D0C8UI64, 0x1E376C085141AB53UI64, 0x2748774CDF8EEB99UI64,
    0x34B0BCB5E19B48A8UI64, 0x391C0CB3C5C95A63UI64, 0x4ED8AA4AE3418ACBUI64,
    0x5B9CCA4F7763E373UI64, 0x682E6FF3D6B2B8A3UI64, 0x748F82EE5DEFB2FCUI64,
    0x78A5636F43172F60UI64, 0x84C87814A1F0AB72UI64, 0x8CC702081A6439ECUI64,
    0x90BEFFFA23631E28UI64, 0xA4506CEBDE82BDE9UI64, 0xBEF9A3F7B2C67915UI64,
    0xC67178F2E372532BUI64, 0xCA273ECEEA26619CUI64, 0xD186B8C721C0C207UI64,
    0xEADA7DD6CDE0EB1EUI64, 0xF57D4F7FEE6ED178UI64, 0x06F067AA72176FBAUI64,
    0x0A637DC5A2C898A6UI64, 0x113F9804BEF90DAEUI64, 0x1B710B35131C471BUI64,
    0x28DB77F523047D84UI64, 0x32CAAB7B40C72493UI64, 0x3C9EBE0A15C9BEBCUI64,
    0x431D67C49C100D4CUI64, 0x4CC5D4BECB3E42B6UI64, 0x597F299CFC657E2AUI64,
    0x5FCB6FAB3AD6FAECUI64, 0x6C44198C4A475817UI64
};
static const u64x sha512_iv[8] = {
    0x6A09E667F3BCC908UI64, 0xBB67AE8584CAA73BUI64, 0x3C6EF372FE94F82BUI64,
    0xA54FF53A5F1D36F1UI64, 0x510E527FADE682D1UI64, 0x9B05688C2B3E6C1FUI64,
    0x1F83D9ABFB41BD6BUI64, 0x5BE0CD19137E2179UI64
};

typedef struct {
    u64x h[8];
    u8   buf[128];
    u32  idx;
    u64x bits;      /* the low 64 bits of the message length in bits */
    u64x bitshi;    /* the high 64 bits */
} sha512_t;

static u64x rotr64(u64x x, int n) { return (x >> n) | (x << (64 - n)); }
static u64x be64(const u8 *p)
{
    return ((u64x)p[0] << 56) | ((u64x)p[1] << 48) | ((u64x)p[2] << 40) |
           ((u64x)p[3] << 32) | ((u64x)p[4] << 24) | ((u64x)p[5] << 16) |
           ((u64x)p[6] << 8) | (u64x)p[7];
}
static void put64le(u8 *p, u64x v)
{
    p[0] = (u8)v;         p[1] = (u8)(v >> 8);  p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24); p[4] = (u8)(v >> 32); p[5] = (u8)(v >> 40);
    p[6] = (u8)(v >> 48); p[7] = (u8)(v >> 56);
}

static void sha512_compress(sha512_t *s, const u8 *block)
{
    u64x w[80], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++) w[i] = be64(block + i * 8);
    for (i = 16; i < 80; i++) {
        u64x x = w[i - 15], y = w[i - 2];
        u64x s0 = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
        u64x s1 = rotr64(y, 19) ^ rotr64(y, 61) ^ (y >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 80; i++) {
        t1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) +
             ((e & f) ^ ((~e) & g)) + sha512_k[i] + w[i];
        t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) +
             ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha512_init(sha512_t *s)
{
    memcpy(s->h, sha512_iv, sizeof(sha512_iv));
    s->idx = 0;
    s->bits = 0;
    s->bitshi = 0;
}

static void sha512_update(sha512_t *s, const u8 *data, u32 n)
{
    {
        u64x old = s->bits;
        s->bits += (u64x)n * 8;
        if (s->bits < old) s->bitshi++;
    }
    while (n) {
        u32 k = 128 - s->idx;
        if (k > n) k = n;
        memcpy(s->buf + s->idx, data, k);
        s->idx += k;
        data += k;
        n -= k;
        if (s->idx == 128) { sha512_compress(s, s->buf); s->idx = 0; }
    }
}

static void sha512_final(sha512_t *s)
{
    u64x bits = s->bits, bitshi = s->bitshi;
    u8 pad[256];
    u32 padlen;
    int i;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    padlen = (s->idx < 112) ? (112 - s->idx) : (240 - s->idx);
    sha512_update(s, pad, padlen);
    for (i = 0; i < 8; i++) pad[i] = (u8)(bitshi >> (56 - 8 * i));
    sha512_update(s, pad, 8);
    for (i = 0; i < 8; i++) pad[i] = (u8)(bits >> (56 - 8 * i));
    sha512_update(s, pad, 8);
    s->bits = bits;
    s->bitshi = bitshi;
}

/* the 64 raw bytes of the state (as the binary's getState() returns them:
 * the low dword of every 64 bit word comes first) */
static void sha512_state(sha512_t *s, u8 *out)
{
    int i;
    for (i = 0; i < 8; i++) put64le(out + i * 8, s->h[i]);
}

/* ---------------- the MT19937 variant of the binary ----------------
 * The state is seeded directly (state[i] = key[i % len]), the twist is
 * the standard MT19937 twist and the tempered words are copied into a
 * separate output array (so the state keeps the untempered values). */
typedef struct { u32 st[624], out[624]; u32 idx; } mt_t;

static void mt_twist(mt_t *m)
{
    u32 *st = m->st;
    int i;
    for (i = 0; i < 624 - 397; i++) {
        u32 y = (st[i] & 0x80000000u) | (st[i + 1] & 0x7FFFFFFFu);
        st[i] = st[i + 397] ^ (y >> 1) ^ ((y & 1) ? 0x9908B0DFu : 0u);
    }
    for (; i < 623; i++) {
        u32 y = (st[i] & 0x80000000u) | (st[i + 1] & 0x7FFFFFFFu);
        st[i] = st[i + (397 - 624)] ^ (y >> 1) ^ ((y & 1) ? 0x9908B0DFu : 0u);
    }
    {
        u32 y = (st[623] & 0x80000000u) | (st[0] & 0x7FFFFFFFu);
        st[623] = st[396] ^ (y >> 1) ^ ((y & 1) ? 0x9908B0DFu : 0u);
    }
    for (i = 0; i < 624; i++) {
        u32 y = st[i];
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C5680u;
        y ^= (y << 15) & 0xEFC60000u;
        y ^= y >> 18;
        m->out[i] = y;
    }
    m->idx = 0;
}

static void mt_init(mt_t *m, const u32 *seed)
{
    memcpy(m->st, seed, 624 * sizeof(u32));
    m->idx = 624;
    mt_twist(m);
}

static u32 mt_next(mt_t *m)
{
    if (m->idx >= 624) mt_twist(m);
    return m->out[m->idx++];
}

/* ---------------- the SecureCryptograph object ---------------- */
typedef struct {
    sha512_t hash;
    mt_t     mt;
    u8       keybuf[64];
    u8       rolling[128];
    u32      index;
    u32      counter;
    u8       feedback;
} crypt_t;

/* the key derivation: SHA-512(material|password) stretched over 39 rounds
 * and used to seed the MT19937 */
static void crypt_setkey(crypt_t *c, const u8 *material, u32 matlen,
                         const u8 *password, u32 pwlen)
{
    u8 hist[39 * 64], cur[64];
    u32 seed[624];
    int i;

    sha512_init(&c->hash);
    sha512_update(&c->hash, material, matlen);
    sha512_update(&c->hash, password, pwlen);
    sha512_final(&c->hash);
    sha512_state(&c->hash, cur);
    for (i = 0; i < 39; i++) {
        memcpy(hist + i * 64, cur, 64);
        sha512_update(&c->hash, cur, 64);
        sha512_update(&c->hash, cur, 64);
        sha512_state(&c->hash, cur);
    }
    seed[0] = 0xFFFFFFFFu;
    for (i = 0; i < 623; i++) memcpy(&seed[1 + i], hist + i * 4, 4);
    mt_init(&c->mt, seed);
    sha512_init(&c->hash);              /* the hash is reset after the stretch */
    memset(c->keybuf, 0, 64);
    memset(c->rolling, 0, 128);
    c->index = 0;
    c->counter = 0;
    c->feedback = 0;
}

static u8 crypt_prng(crypt_t *c)
{
    u8 fb, ret;
    if (c->index == 0 || c->counter < 64) {
        u8 tmp[128];
        int i;
        for (i = 0; i < 32; i++) {
            u32 v = mt_next(&c->mt);
            tmp[i * 4 + 0] = (u8)v;
            tmp[i * 4 + 1] = (u8)(v >> 8);
            tmp[i * 4 + 2] = (u8)(v >> 16);
            tmp[i * 4 + 3] = (u8)(v >> 24);
        }
        sha512_update(&c->hash, tmp, 128);
        sha512_update(&c->hash, c->rolling, 128);
        sha512_state(&c->hash, c->keybuf);
        if (c->counter < 64) c->counter++;
    }
    fb = c->feedback;
    ret = (u8)(c->keybuf[c->index] ^ fb);
    c->rolling[c->index] = fb;
    c->rolling[64 + c->index] = fb;  /* the scratch overlaps the rolling */
    c->feedback = 0;
    c->index = (c->index + 1) & 0x3F;
    return ret;
}

static void crypt_encrypt(crypt_t *c, u8 *buf, u32 n)
{
    u32 i;
    for (i = 0; i < n; i++) {
        u8 in = buf[i], k1, k2;
        k1 = crypt_prng(c);
        k2 = crypt_prng(c);
        buf[i] = (u8)(in ^ k1 ^ k2);
        c->feedback = (u8)(in ^ k1);
    }
}

static void crypt_decrypt(crypt_t *c, u8 *buf, u32 n)
{
    u32 i;
    for (i = 0; i < n; i++) {
        u8 in = buf[i], k1, k2;
        k1 = crypt_prng(c);
        k2 = crypt_prng(c);
        buf[i] = (u8)(in ^ k1 ^ k2);
        c->feedback = (u8)(in ^ k2);
    }
}

/* the key of the recovery data: the fixed password "SecureCryptograph"
 * and an 8 byte block of zeros */
static void crypt_setkey_fixed(crypt_t *c)
{
    static const u8 zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    crypt_setkey(c, zero, 8, (const u8 *)"SecureCryptograph", 17);
}

/* the self test: the key stream of the fixed key */
static int crypto_selftest(void)
{
    crypt_t c;
    sha512_t h;
    u8 buf[64], st[64];
    int i;
    sha512_init(&h);
    sha512_update(&h, (const u8 *)"abc", 3);
    sha512_final(&h);
    sha512_state(&h, st);
    printf("sha512(\"abc\") = ");
    for (i = 0; i < 64; i++) printf("%02x", st[i]);
    printf("\n");
    crypt_setkey_fixed(&c);
    memset(buf, 0, sizeof(buf));
    crypt_encrypt(&c, buf, 64);
    for (i = 0; i < 64; i++) printf("%02x", buf[i]);
    printf("\n");
    return 0;
}

/* --------------------------- the range coder --------------------------- *
 *  the carryless range encoder of the binary (sub_426F80) */
typedef struct {
    u32 low, range, byte, pending;
    buf_t *out;
} rng_t;

static void rng_init(rng_t *e, buf_t *out)
{
    e->low = 0;
    e->range = 0x80000000u;
    e->byte = 0;
    e->pending = 0;
    e->out = out;
}

static void rng_emit(rng_t *e)
{
    u32 v = e->low;
    if (v >= 0x7F800000u) {
        if (v >= 0x80000000u) {
            bput8(e->out, (u8)((e->byte + 1) & 0xFF));
            while (e->pending) { bput8(e->out, 0); e->pending--; }
            e->pending = 0;
            e->byte = v >> 23;
            e->low = (v & 0x7FFFFF) << 8;
        } else {
            e->pending++;
            e->low = (v & 0x7FFFFF) << 8;
        }
    } else {
        bput8(e->out, (u8)e->byte);
        while (e->pending) { bput8(e->out, 0xFF); e->pending--; }
        e->pending = 0;
        e->byte = v >> 23;
        e->low = (v & 0x7FFFFF) << 8;
    }
}

static void rng_renorm(rng_t *e)
{
    while (e->range <= 0x800000u) {
        rng_emit(e);
        e->range <<= 8;
        if (e->range == 0) { e->range = 0x800000u; return; }
    }
}

static void rng_flush(rng_t *e)
{
    int i;
    rng_renorm(e);
    for (i = 0; i < 5; i++) rng_emit(e);
}

/* --------------------- the CM literal coder (the encoder) ---------------------
 *  the mirror image of the decoder in dgcunp.c (sub_427260) */
typedef struct {
    u16 lit[256];
    u16 ctx[32];
    u16 run[32 * 256];
    u16 pair[256 * 256];
    u32 state;
    int prev;
} models_t;

typedef struct {
    int p_lit, p_pairb, p_pair, p_ctx, p_run;
} params_t;

static void models_init(models_t *m, int firstbyte_zero)
{
    int i;
    for (i = 0; i < 256; i++) m->lit[i] = 2048;
    for (i = 0; i < 32; i++) m->ctx[i] = 2048;
    for (i = 0; i < 32 * 256; i++) m->run[i] = 2048;
    for (i = 0; i < 256 * 256; i++) m->pair[i] = 2048;
    m->state = 0;
    m->prev = firstbyte_zero ? 0xFF : 0;
}

static int bsr32(u32 x)
{
    int n = 0;
    if (!x) return 31;          /* the code pre-loads 1Fh before the BSR */
    while (!(x & 0x80000000u)) { x <<= 1; n++; }
    return 31 - n;
}

/* the prepare pass: the tree of the previous byte, from the deepest node up */
static void cm_prepare(models_t *m, u16 saved[8])
{
    u32 chain = (u32)(m->prev | 0x100);
    u32 scale = 0x2000;
    int k;
    for (k = 0; k < 8; k++) {
        u32 node = chain >> 1;
        int bit = chain & 1;
        u32 p = m->lit[node];
        u32 d;
        saved[k] = (u16)p;
        if (bit) {
            d = ((4096u - p) * scale) >> 13;
            m->lit[node] = (u16)(p + d);
        } else {
            d = (p * scale) >> 13;
            m->lit[node] = (u16)(p - d);
        }
        scale = d;
        chain = node;
    }
}

/* the restore pass: the same nodes, from the deepest node up */
static void cm_restore(models_t *m, params_t *P, int cur, u16 saved[8])
{
    u32 chain = (u32)(m->prev | 0x100);
    int k;
    for (k = 0; k < 8; k++) {
        u32 node = chain >> 1;
        int bit = chain & 1;
        u32 p = saved[k];
        u16 *q = &m->pair[cur * 256 + node];
        u32 v = *q;
        if (bit) {
            m->lit[node] = (u16)(p - (p >> P->p_lit));
            *q = (u16)(v - (v >> P->p_pairb));
        } else {
            m->lit[node] = (u16)(p + ((4096u - p) >> P->p_lit));
            *q = (u16)(v + ((4096u - v) >> P->p_pairb));
        }
        chain = node;
    }
}

/* code the 8 bits of cur (the encoder, sub_427970) */
static void cm_literal(rng_t *e, models_t *m, params_t *P, int cur)
{
    int slot = bsr32(m->state);
    u32 w = m->ctx[slot];
    u16 saved[8];
    u32 v61 = 0x80000, v60 = 0x80000;
    u32 node = 1;
    int base = m->prev * 256;
    int k;

    cm_prepare(m, saved);
    for (k = 0; k < 8; k++) {
        int bit = (cur >> (7 - k)) & 1;
        u32 pr = (w * m->lit[node] + (u32)m->pair[base + node] * (4096u - w)) >> 12;
        u32 p, bound;
        if (e->range <= 0x800000u) rng_renorm(e);
        bound = (pr * (e->range >> 12)) & 0xFFFFFFFFu;
        if (bit) {
            e->low = (e->low + bound) & 0xFFFFFFFFu;
            e->range = (e->range - bound) & 0xFFFFFFFFu;
            v61 = (v61 * (4096u - m->lit[node])) >> 12;
            p = m->pair[base + node];
            v60 = (v60 * (4096u - p)) >> 12;
            m->pair[base + node] = (u16)(p - (p >> P->p_pair));
        } else {
            e->range = bound;
            v61 = (v61 * m->lit[node]) >> 12;
            p = m->pair[base + node];
            v60 = (v60 * p) >> 12;
            m->pair[base + node] = (u16)(p + ((4096u - p) >> P->p_pair));
        }
        node = 2 * node + bit;
    }
    cm_restore(m, P, cur, saved);
    m->state = (w * v61 + (4096u - w) * v60) >> 12;
    if (v61 < v60) {
        w = w - (w >> P->p_ctx);
        m->ctx[slot] = (u16)w;
    } else if (v61 > v60) {
        w = w + ((4096u - w) >> P->p_ctx);
        m->ctx[slot] = (u16)w;
    }
}

/* the gamma symbol coder (sub_427880): the value's bit length, then the
 * (len-1) raw bits.  It codes both the run lengths of the CM coder and
 * the symbols of the model stream. */
static int gamma_put(rng_t *e, u16 *probs, int base, int shift, u32 value)
{
    int i = 0;
    for (;;) {
        u32 p = probs[base + i];
        u32 bound;
        if (e->range <= 0x800000u) rng_renorm(e);
        bound = (p * (e->range >> 12)) & 0xFFFFFFFFu;
        if ((value >> i) == 0) {
            /* the "small" branch: the bit 1 */
            e->low = (e->low + bound) & 0xFFFFFFFFu;
            e->range = (e->range - bound) & 0xFFFFFFFFu;
            probs[base + i] = (u16)(p - (p >> shift));
            break;
        }
        /* the "continue" branch: the bit 0 */
        e->range = bound;
        probs[base + i] = (u16)(p + ((4096u - p) >> shift));
        i++;
        if (i >= 32) break;
    }
    if (i > 1) {
        int b;
        for (b = i - 2; b >= 0; b--) {
            if (e->range <= 0x800000u) rng_renorm(e);
            {
                u32 half = e->range >> 1;
                if ((value >> b) & 1) {
                    e->low = (e->low + half) & 0xFFFFFFFFu;
                    e->range = (e->range - half) & 0xFFFFFFFFu;
                } else {
                    e->range = half;
                }
            }
        }
    }
    return i;
}

/* ------------------------ the pre-transform ------------------------ *
 *  the LZ77 with an implicit distance: the hash table maps the key
 *  ((the previous byte) << 8) | the byte to the last position.  The
 *  output is the literals and the model stream (the pairs of the
 *  literal run length and the match length - minmatch). */
static void pre_transform(rng_t *me, const u8 *data, u32 size,
                          int minlen_exp, int model_shift,
                          buf_t *lits, buf_t *model)
{
    u32 *tbl;
    u32 key = 0, pos = 0, runlen = 0;
    u32 minlen = 1u << minlen_exp;
    u16 lit_model[32], match_model[32];
    int i;

    for (i = 0; i < 32; i++) { lit_model[i] = 2048; match_model[i] = 2048; }
    tbl = (u32 *)malloc(sizeof(u32) * 65536);
    if (!tbl) { fprintf(stderr, "out of memory\n"); exit(2); }
    for (i = 0; i < 65536; i++) tbl[i] = 0xFFFFFFFFu;

    while (pos < size) {
        u32 cand = tbl[key];
        u32 mlen = 0;
        if (cand != 0xFFFFFFFFu && cand < pos && data[cand] == data[pos]) {
            u32 dist = pos - cand;
            u32 l = 1;
            while (pos + l < size && l < dist && data[cand + l] == data[pos + l]) l++;
            mlen = l;
        }
        if (mlen >= minlen) {
            /* a match: the literal run and the match length - minmatch */
            gamma_put(me, lit_model, 0, model_shift, runlen);
            gamma_put(me, match_model, 0, model_shift, mlen - minlen);
            runlen = 0;
            while (mlen > 0) {
                tbl[key] = pos;
                key = ((key & 0xFF) << 8) | data[pos];
                pos++;
                mlen--;
            }
            continue;
        }
        /* a literal */
        bput8(lits, data[pos]);
        tbl[key] = pos;
        key = ((key & 0xFF) << 8) | data[pos];
        runlen++;
        pos++;
    }
    /* the last literal run */
    gamma_put(me, lit_model, 0, model_shift, runlen);
    free(tbl);
}

/* --------------------- the CM coder (the whole stream) --------------------- */
static void cm_stream(const u8 *data, u32 n, u32 params, int firstbyte_zero,
                      buf_t *out)
{
    models_t m;
    params_t P;
    rng_t e;
    u32 i = 0;

    P.p_lit   = (params >> 4) & 0xF;
    P.p_pairb = (params >> 8) & 0xF;
    P.p_pair  = (params >> 12) & 0xF;
    P.p_ctx   = (params >> 16) & 0xF;
    P.p_run   = (params >> 20) & 0xF;
    models_init(&m, firstbyte_zero);
    rng_init(&e, out);
    while (i < n) {
        u8 b = data[i];
        u32 j = i + 1;
        u32 runlen;
        while (j < n && data[j] == b) j++;
        runlen = j - i - 1;
        cm_literal(&e, &m, &P, b);
        gamma_put(&e, m.run, b * 32, P.p_run, runlen);
        m.prev = b;
        i = j;
    }
    rng_flush(&e);
}

/* the "match" literal coder (the params' bit 1, sub_427D60): a plain 8 bit
 * literal coder without the prepare/restore passes and without the run
 * model.  Its decoder is cm_match in dgcunp.c; this reproduces the
 * original's streams of the uniform columns byte for byte. */
static void cm_match_put(rng_t *e, models_t *m, params_t *P, int cur)
{
    int ci = bsr32(m->state);
    u32 w = m->ctx[ci];
    u32 v18 = 0x80000, v17 = 0x80000;
    u32 node = 1;
    int base = m->prev * 256;
    int k;
    for (k = 0; k < 8; k++) {
        int bit = (cur >> (7 - k)) & 1;
        u32 pr = (w * m->lit[node] + (u32)m->pair[base + node] * (4096u - w)) >> 12;
        u32 p, bound;
        if (e->range <= 0x800000u) rng_renorm(e);
        bound = (pr * (e->range >> 12)) & 0xFFFFFFFFu;
        if (bit) {
            e->low = (e->low + bound) & 0xFFFFFFFFu;
            e->range = (e->range - bound) & 0xFFFFFFFFu;
            v18 = (v18 * (4096u - m->lit[node])) >> 12;
            p = m->pair[base + node];
            v17 = (v17 * (4096u - p)) >> 12;
            m->pair[base + node] = (u16)(p - (p >> P->p_pair));
            m->lit[node] = (u16)(m->lit[node] - (m->lit[node] >> P->p_lit));
        } else {
            e->range = bound;
            v18 = (v18 * m->lit[node]) >> 12;
            p = m->pair[base + node];
            v17 = (v17 * p) >> 12;
            m->pair[base + node] = (u16)(p + ((4096u - p) >> P->p_pair));
            m->lit[node] = (u16)(m->lit[node] + ((4096u - m->lit[node]) >> P->p_lit));
        }
        node = 2 * node + (u32)bit;
    }
    m->state = (w * v18 + (4096u - w) * v17) >> 12;
    if (v18 < v17) m->ctx[ci] = (u16)(w - (w >> P->p_ctx));
    else if (v18 > v17) m->ctx[ci] = (u16)(w + ((4096u - w) >> P->p_ctx));
}

static void match_stream(const u8 *data, u32 n, u32 params, int firstbyte_zero,
                         buf_t *out)
{
    models_t m;
    params_t P;
    rng_t e;
    u32 i;
    P.p_lit   = (params >> 4) & 0xF;
    P.p_pairb = (params >> 8) & 0xF;
    P.p_pair  = (params >> 12) & 0xF;
    P.p_ctx   = (params >> 16) & 0xF;
    P.p_run   = (params >> 20) & 0xF;
    models_init(&m, firstbyte_zero);
    rng_init(&e, out);
    for (i = 0; i < n; i++) {
        cm_match_put(&e, &m, &P, data[i]);
        m.prev = data[i];
    }
    rng_flush(&e);
}

/* ------------------------- the block compressor ------------------------- *
 *  the block stream: the tag 1 block (the compressed data) */

/* the LZ stage (sub_428270): the token buffer is the fixed point of the
 * rank iteration below.  Every byte gets the rank of its value (the stable
 * order by value); the ranks are then re-sorted by the rank of the NEXT
 * byte until nothing changes.  The decoder's chain walk (dgcunp.c,
 * lz_inverse) inverts it; `start` is the rank of the first byte.
 * It reproduces the original's token buffer byte for byte (the text.txt
 * block of all.dgc: start 50856, stream A 19649). */
#define LZ_MAX (8u * 1024u * 1024u)   /* the rank arrays are 16 bytes a byte */

static int lz_stage(const u8 *data, u32 n, u8 *tok, u32 *start)
{
    u32 *rank, *newr, *a, *inva;
    u32 base[256], cnt[256], w[256];
    u32 i, k, v, it;
    int ok = 0;

    if (!n) { *start = 0; return 1; }
    if (n > LZ_MAX) return 0;
    rank = (u32 *)malloc(sizeof(u32) * n);
    newr = (u32 *)malloc(sizeof(u32) * n);
    a    = (u32 *)malloc(sizeof(u32) * n);
    inva = (u32 *)malloc(sizeof(u32) * n);
    if (!rank || !newr || !a || !inva) {
        free(rank); free(newr); free(a); free(inva);
        return 0;
    }
    memset(cnt, 0, sizeof(cnt));
    for (i = 0; i < n; i++) cnt[data[i]]++;
    base[0] = 0;
    for (v = 1; v < 256; v++) base[v] = base[v - 1] + cnt[v - 1];
    /* the stable rank by value */
    memset(w, 0, sizeof(w));
    for (i = 0; i < n; i++) {
        v = data[i];
        rank[i] = base[v] + w[v]++;
    }
    for (it = 0; it < 128; it++) {
        for (k = 0; k < n; k++) a[k] = rank[(k + 1) % n];
        for (k = 0; k < n; k++) inva[a[k]] = k;
        /* the members of every value group, in the order of their rank
         * (i.e. by a[]), get the ranks base[v]..base[v]+cnt[v]-1 */
        memcpy(w, base, sizeof(w));
        for (k = 0; k < n; k++) {
            i = inva[k];
            v = data[i];
            newr[i] = w[v]++;
        }
        if (!memcmp(newr, rank, sizeof(u32) * n)) { ok = 1; break; }
        memcpy(rank, newr, sizeof(u32) * n);
    }
    if (ok) {
        for (k = 0; k < n; k++) tok[a[k]] = data[k];
        *start = rank[0];
    }
    free(rank); free(newr); free(a); free(inva);
    return ok;
}

static void compress_block(const u8 *data, u32 size, u32 params,
                           buf_t *out)
{
    buf_t lits, model, A, B;
    u8 *tok = NULL;
    u32 start = 0;
    int lz = 0;
    int minlen_exp = (params >> 24) & 0xF;
    int model_shift = (params >> 28) & 0xF;
    int firstbyte_zero = (params & 1) != 0;

    memset(&lits, 0, sizeof(lits));
    memset(&model, 0, sizeof(model));
    memset(&A, 0, sizeof(A));
    memset(&B, 0, sizeof(B));
    /* the model stream is coded with its own range coder */
    {
        rng_t me;
        rng_init(&me, &model);
        pre_transform(&me, data, size, minlen_exp, model_shift, &lits, &model);
        rng_flush(&me);
    }
    /* the LZ stage: a permutation of the literals (flags bit 1).  The
     * fixed point iteration does not settle on every input, so the plain
     * stream is coded as well and the smaller of the two is kept. */
    cm_stream(lits.p, lits.len, params, firstbyte_zero, &A);
    if (lits.len) {
        buf_t A2;
        memset(&A2, 0, sizeof(A2));
        tok = (u8 *)malloc(lits.len);
        if (tok && lz_stage(lits.p, lits.len, tok, &start)) {
            cm_stream(tok, lits.len, params, firstbyte_zero, &A2);
            if (A2.len < A.len) {
                lz = 1;
                free(A.p);
                A = A2;
            } else {
                free(A2.p);
            }
        }
    }
    /* the block header */
    bput32(out, 1);           /* the tag */
    bput32(out, size);        /* the original size */
    bput32(out, lz ? 0x06 : 0x04);  /* the flags: pre-transform (+ LZ) */
    bput32(out, params);
    bput32(out, lz ? start : 0);    /* v22: the chain walk's start */
    bput32(out, lits.len);    /* v7: the token buffer's size */
    bput32(out, A.len);
    bput32(out, model.len);
    bput(out, A.p, A.len);
    bput(out, model.p, model.len);
    free(tok);
    free(lits.p);
    free(model.p);
    free(A.p);
    free(B.p);
}

/* the stored block */
static void store_block(const u8 *data, u32 size, buf_t *out)
{
    bput32(out, 0);
    bput32(out, size);
    bput(out, data, size);
}

/* ------------------- the column method (tag 2, sub_424FE0) -------------------
 *  The data is split into `stride` interleaved columns; every column is
 *  delta transformed (the order is chosen per column from the spread of
 *  its byte histogram) and compressed as its own tag 1 block with the
 *  pre-transform switched off.  The tag 2 header is
 *      tag = 2, size = the stride
 *  and the columns follow as tag 1 blocks.
 *  (the original also runs the LZ stage on the columns and the "match"
 *  coder on the very uniform ones; both are optional for the decoder) */

/* the deviation of the byte histogram from the uniform one - the writer's
 * measure of how well a column compresses (larger = more concentrated) */
static double col_spread(const u8 *p, u32 n)
{
    u32 cnt[256], i;
    double s = 0.0;
    if (!n) return 0.0;
    memset(cnt, 0, sizeof(cnt));
    for (i = 0; i < n; i++) cnt[p[i]]++;
    for (i = 0; i < 256; i++) {
        double v = (double)cnt[i] * 256.0 / (double)n - 1.0;
        s += v * v;
    }
    return sqrt(s * 0.00392156862745098);
}

/* the stride of the column method (1..16), 0 when the data is not
 * "column friendly".  sub_423F90: the mean |x[i]-x[i-d]| is computed for
 * every lag; the columns are used when the best lag is far better than
 * the average one (best * 4 < the average). */
static int choose_stride(const u8 *p, u32 n)
{
    double m[17], avg = 0.0, best;
    int d, bi;
    if (n < 0x400) return 0;
    for (d = 1; d <= 16; d++) {
        u64 sum = 0;
        u32 i, cnt = 0;
        for (i = (u32)d; i < n; i++) {
            int v = (int)p[i] - (int)p[i - (u32)d];
            sum += (u64)(v < 0 ? -v : v);
            cnt++;
        }
        m[d] = cnt ? (double)sum / (double)cnt : 0.0;
        avg += m[d];
    }
    avg /= 16.0;
    best = m[1]; bi = 1;
    for (d = 2; d <= 16; d++) if (m[d] < best) { best = m[d]; bi = d; }
    if (best * 4.0 < avg) return bi;
    return 0;
}

/* the forward delta (the inverse of inverse_delta in dgcunp.c) */
static void delta_fwd(u8 *p, u32 n, int order)
{
    int k;
    u32 i;
    for (k = 0; k < order; k++) {
        u8 prev = 0;
        for (i = 0; i < n; i++) {
            u8 v = p[i];
            p[i] = (u8)(v - prev);
            prev = v;
        }
    }
}

/* build the tag 2 block; returns 0 if the data is not column friendly */
static int column_block(const u8 *data, u32 size, buf_t *out)
{
    int stride = choose_stride(data, size);
    u32 k, i, maxcol;
    u8 *col, *d1, *d2;
    if (!stride) return 0;
    maxcol = (size + (u32)stride - 1) / (u32)stride;
    col = (u8 *)malloc(maxcol ? maxcol : 1);
    d1  = (u8 *)malloc(maxcol ? maxcol : 1);
    d2  = (u8 *)malloc(maxcol ? maxcol : 1);
    if (!col || !d1 || !d2) { free(col); free(d1); free(d2); return 0; }
    bput32(out, 2);
    bput32(out, (u32)stride);
    for (k = 0; k < (u32)stride; k++) {
        u32 n = 0;
        int order = 0;
        double s0, s1, s2;
        buf_t A, tmp;
        u8 *ctok;
        u32 cstart = 0;
        int clz = 0, match = 0;
        for (i = k; i < size; i += (u32)stride) col[n++] = data[i];
        memcpy(d1, col, n);
        delta_fwd(d1, n, 1);
        s0 = col_spread(col, n);
        s1 = col_spread(d1, n);
        if (s0 * 1.2 <= s1) {
            memcpy(d2, d1, n);
            delta_fwd(d2, n, 1);
            s2 = col_spread(d2, n);
            order = (s1 * 1.1 < s2 && s2 * s0 * 1.8 > s1 * s1) ? 2 : 1;
        }
        if (order == 1) memcpy(col, d1, n);
        else if (order == 2) memcpy(col, d2, n);
        /* the best of the four: the literal coder or the match coder,
         * each with and without the LZ stage */
        memset(&A, 0, sizeof(A));
        cm_stream(col, n, 0x46443320u, 0, &A);
        memset(&tmp, 0, sizeof(tmp));
        match_stream(col, n, 0x46443322u, 0, &tmp);
        if (tmp.len < A.len) { free(A.p); A = tmp; match = 1; }
        else free(tmp.p);
        ctok = (u8 *)malloc(n ? n : 1);
        if (ctok && lz_stage(col, n, ctok, &cstart)) {
            memset(&tmp, 0, sizeof(tmp));
            cm_stream(ctok, n, 0x46443320u, 0, &tmp);
            if (tmp.len < A.len) { free(A.p); A = tmp; match = 0; clz = 1; }
            else free(tmp.p);
            memset(&tmp, 0, sizeof(tmp));
            match_stream(ctok, n, 0x46443322u, 0, &tmp);
            if (tmp.len < A.len) { free(A.p); A = tmp; match = 1; clz = 1; }
            else free(tmp.p);
        }
        bput32(out, 1);
        bput32(out, n);
        bput32(out, ((u32)order << 16) | (clz ? 2 : 0));
        bput32(out, match ? 0x46443322u : 0x46443320u);
        bput32(out, clz ? cstart : 0);   /* v22 */
        bput32(out, n);                  /* v7 */
        bput32(out, A.len);
        bput32(out, 0);                  /* lenB */
        bput(out, A.p, A.len);
        free(ctok);
        free(A.p);
    }
    free(col); free(d1); free(d2);
    return 1;
}

/* one data block: stored, the plain compressed block, or the columns */
static void put_data_block(const u8 *data, u32 size, u32 params, int nocompress,
                           buf_t *out)
{
    buf_t plain, col;
    if (nocompress) { store_block(data, size, out); return; }
    memset(&plain, 0, sizeof(plain));
    compress_block(data, size, params, &plain);
    if (plain.len >= size + 8) {      /* the writer stores when it does not pay */
        store_block(data, size, out);
        free(plain.p);
        return;
    }
    memset(&col, 0, sizeof(col));
    if (column_block(data, size, &col) && col.len < plain.len) {
        bput(out, col.p, col.len);
        free(col.p);
        free(plain.p);
        return;
    }
    free(col.p);
    bput(out, plain.p, plain.len);
    free(plain.p);
}

/* ----------------------------- the chunks ----------------------------- */
static void put_chunk(buf_t *out, const char *id, u32 flags, const u8 *payload,
                      u32 plen)
{
    u8 hdr[32];
    u32 crc;
    memcpy(hdr, id, 4);
    memset(hdr + 4, 0, 28);
    hdr[4] = 0x20; hdr[5] = hdr[6] = hdr[7] = 0;      /* the header size */
    hdr[8] = (u8)plen; hdr[9] = (u8)(plen >> 8);
    hdr[10] = (u8)(plen >> 16); hdr[11] = (u8)(plen >> 24);
    hdr[12] = hdr[13] = hdr[14] = hdr[15] = 0;          /* zero_0c */
    hdr[16] = (u8)flags; hdr[17] = (u8)(flags >> 8);
    hdr[18] = hdr[19] = 0;
    hdr[20] = 0x10; hdr[21] = hdr[22] = hdr[23] = 0;   /* the alignment */
    crc = crc32_buf(payload, plen);
    hdr[24] = (u8)crc; hdr[25] = (u8)(crc >> 8);
    hdr[26] = (u8)(crc >> 16); hdr[27] = (u8)(crc >> 24);
    memset(hdr + 28, 0, 4);              /* the crc_header field is zero */
    crc = crc32_buf(hdr, 32);
    hdr[28] = (u8)crc; hdr[29] = (u8)(crc >> 8);
    hdr[30] = (u8)(crc >> 16); hdr[31] = (u8)(crc >> 24);
    bput(out, hdr, 32);
    bput(out, payload, plen);
    while (out->len & 15) bput8(out, 0);
}

/* the name in the archive: the path relative to the current directory */
static const char *relpath(const char *path)
{
    static char cwd[1024];
    size_t n;
    if (!GetCurrentDirectoryA(sizeof(cwd), cwd)) return path;
    n = strlen(cwd);
    if (n && !_strnicmp(path, cwd, n) && path[n] == '\\')
        return path + n + 1;
    return path;
}

/* the file time (a FILETIME) */
static u64 file_time(const char *path, int which)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    FILETIME ft;
    ULARGE_INTEGER u;
    u.LowPart = 0; u.HighPart = 0;
    if (h != INVALID_HANDLE_VALUE) {
        if (which) GetFileTime(h, NULL, NULL, &ft);
        else GetFileTime(h, &ft, NULL, NULL);
        CloseHandle(h);
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
    }
    return u.QuadPart;
}

typedef struct {
    char path[1024];       /* the name in the archive */
    char file[1024];       /* the file on the disk */
    u32 size;
    u32 crc;
    u32 attr;
    u64 ctime, mtime;
} entry_t;
/* ------------------------- the recovery data ------------------------- *
 *  the parity table of the archive: the matrix is
 *  pages x rows x 256 columns 4 byte words (the archive's bytes padded
 *  with zeros), part 1 is the column parity, part 2 the row parity and
 *  part 3 the offsets of the row blocks.  The whole thing is encrypted
 *  with the fixed key of the SecureCryptograph class. */

/* the rows and the pages of the matrix (the same formula as the tool) */
static void recovery_params(u32 size, int level, u32 *rows, u32 *pages)
{
    u32 cols = 256, r, p;
    r = (u32)(((u64)size + ((u64)(cols >> (level - 1)) * 1024) - 1) /
              ((u64)(cols >> (level - 1)) * 1024));
    if (r < 4) r = 4;
    p = (u32)(((u64)size + (u64)r * 1024 - 1) / ((u64)r * 1024));
    if (p == 1) r = (size + 1023) / 1024;
    *rows = r;
    *pages = p;
}

static void recovery_data(const u8 *arch, u32 size, int level, buf_t *out)
{
    u32 rows, pages, cols = 256, i, j, k, words;
    u8 *par, *rowx, *off;
    buf_t plain;
    crypt_t c;

    recovery_params(size, level, &rows, &pages);
    words = rows * cols * pages;

    memset(&plain, 0, sizeof(plain));
    par  = (u8 *)calloc(rows * cols, 4);
    rowx = (u8 *)calloc(pages * rows, 4);
    off  = (u8 *)calloc(rows, 4);
    if (!par || !rowx || !off) { fprintf(stderr, "out of memory\n"); exit(2); }

    /* the parity of the pages (part 1) and of the columns (part 2) */
    for (k = 0; k < pages; k++) {
        for (i = 0; i < rows; i++) {
            for (j = 0; j < cols; j++) {
                u32 idx = (k * rows + i) * cols + j;
                u32 w = 0;
                if (idx < words && (u64)idx * 4 + 4 <= size)
                    w = ((const u32 *)arch)[idx];
                {
                    u32 *p1 = (u32 *)(par + (i * cols + j) * 4);
                    u32 *p2 = (u32 *)(rowx + (k * rows + i) * 4);
                    *p1 ^= w;
                    *p2 ^= w;
                }
            }
        }
    }
    /* part 3: the CRC-32 of every row of the matrix (the words of the
     * row over all the pages) */
    for (i = 0; i < rows; i++) {
        u32 c = 0xFFFFFFFFu;
        u8 tmp[4];
        for (k = 0; k < pages; k++) {
            for (j = 0; j < cols; j++) {
                u32 idx = (k * rows + i) * cols + j;
                u32 w = 0;
                if (idx < words && (u64)idx * 4 + 4 <= size)
                    w = ((const u32 *)arch)[idx];
                tmp[0] = (u8)w; tmp[1] = (u8)(w >> 8);
                tmp[2] = (u8)(w >> 16); tmp[3] = (u8)(w >> 24);
                c = crc32_update(c, tmp, 4);
            }
        }
        c ^= 0xFFFFFFFFu;
        memcpy(off + i * 4, &c, 4);
    }
    bput(&plain, par, rows * cols * 4);
    bput(&plain, rowx, pages * rows * 4);
    bput(&plain, off, rows * 4);
    free(par);
    free(rowx);
    free(off);

    /* the encryption with the fixed key */
    crypt_setkey_fixed(&c);
    crypt_encrypt(&c, plain.p, plain.len);
    bput(out, plain.p, plain.len);
    free(plain.p);
}

/* ------------------------- the spanning files ------------------------- *
 *  A big file can be split into parts; every part is a chunk tree of its
 *  own and the parts are named <base>%04d.dgd:
 *
 *      DGCD
 *      |-- INFO  (116 bytes)  the material (96 bytes) + the name
 *      |-- DFDT  (32 bytes)   the CRC-32 of the whole file + the FILETIME
 *      `-- DATA  (the part's bytes - they are NOT compressed)
 *
 *  The material (96 bytes):
 *      +0x00 u32  the flags (bit 0 = encrypted)
 *      +0x04 u32  the index of the part
 *      +0x08 u32  the number of the parts
 *      +0x10 u32  the size of this part
 *      +0x18 u32  the size of the whole file
 *      +0x20 64B  the SHA-512 of the whole file
 *  The name (at INFO+0x60) is the name of the file that is split.
 *
 *  With the recovery data the same parts are also written as
 *  <base>%04d.dgdr: the DATA chunk of the first part is then shorter (the
 *  recovery data needs the room) and a DGCR chunk with the parity table
 *  is appended; the other parts hold the rest of the file.
 *
 *  The crypto is the archive's: key1 = SHA-512(8 zeros | password) for
 *  the 92 bytes of the material at +4 and key2 = SHA-512(the PLAINTEXT
 *  material | password) for the name, the DFDT and the DATA (each of
 *  them with its own key stream).
 * ------------------------------------------------------------------ */

/* the overhead of the DGCR chunk: its header (32) + the INFO chunk (32 +
 * 48) + the DATA chunk's header (32) + the trailing chunk (32) */
#define DGCR_OVERHEAD 176

static int write_file(const char *path, const u8 *data, u32 len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", path); return 0; }
    if (len && fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "write error\n");
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}

/* the password of a -k key file: the hex text of the SHA-512 of the
 * content of the file (the standard digest, 128 characters) */
static u32 password_from_keyfile(const char *path, u8 *out, u32 outmax)
{
    u8 *buf;
    u32 n, i, g, j;
    sha512_t h;
    u8 st[64];
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    n = (u32)ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (u8 *)malloc(n ? n : 1);
    if (!buf) { fclose(f); return 0; }
    if (n && fread(buf, 1, n, f) != n) { fclose(f); free(buf); return 0; }
    fclose(f);
    sha512_init(&h);
    sha512_update(&h, buf, n);
    sha512_final(&h);
    sha512_state(&h, st);
    free(buf);
    if (outmax < 129) return 0;
    /* the state holds every 64 bit word with its low dword first: the
     * digest (and its hex text) needs the bytes of every group in
     * reverse order */
    for (g = 0; g < 8; g++)
        for (i = 0; i < 8; i++) {
            j = g * 8 + i;
            sprintf((char *)out + j * 2, "%02x", st[g * 8 + 7 - i]);
        }
    out[128] = 0;
    return 128;
}

/* the parameters of one spanning file */
typedef struct {
    const u8 *data;       /* the whole file */
    u32 totalsize;
    const u8 *st;         /* the SHA-512 of the whole file */
    const u8 *dfdt;       /* the 32 bytes of the DFDT */
    const char *name;
    u32 namelen;
    u32 partidx, nparts;
    const u8 *pw;
    u32 pwlen;
} span_t;

/* write one part of a spanning file (.dgd or .dgdr) */
static int span_write_part(const span_t *S, const char *path, u32 doff,
                            u32 dlen, int recovery, int level)
{
    u8 mat[96], info[96 + 4 + 1024], edfdt[32], *edata;
    u32 ilen, v;
    buf_t kids, out;
    crypt_t c;
    static const u8 zeros8[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    /* the material (the plain text one) */
    memset(mat, 0, 96);
    v = S->pwlen ? 1u : 0u;  memcpy(mat + 0x00, &v, 4);
    v = S->partidx;          memcpy(mat + 0x04, &v, 4);
    v = S->nparts;           memcpy(mat + 0x08, &v, 4);
    v = dlen;                memcpy(mat + 0x10, &v, 4);
    v = S->totalsize;        memcpy(mat + 0x18, &v, 4);
    memcpy(mat + 0x20, S->st, 64);

    /* the INFO payload: the material + the name */
    ilen = 96 + 4 + S->namelen;
    memset(info, 0, ilen);
    memcpy(info, mat, 96);
    memcpy(info + 96, &S->namelen, 4);
    memcpy(info + 100, S->name, S->namelen);
    if (S->pwlen) {
        u8 encmat[96];
        memcpy(encmat, mat, 96);
        crypt_setkey(&c, zeros8, 8, S->pw, S->pwlen);
        crypt_encrypt(&c, encmat + 4, 92);
        memcpy(info, encmat, 96);
        crypt_setkey(&c, mat, 96, S->pw, S->pwlen);
        crypt_encrypt(&c, info + 96, 4 + S->namelen);
    }
    /* the DFDT */
    memcpy(edfdt, S->dfdt, 32);
    if (S->pwlen) {
        crypt_setkey(&c, mat, 96, S->pw, S->pwlen);
        crypt_encrypt(&c, edfdt, 32);
    }
    /* the DATA (the part's bytes, not compressed) */
    edata = (u8 *)malloc(dlen ? dlen : 1);
    if (!edata) { fprintf(stderr, "out of memory\n"); exit(2); }
    memcpy(edata, S->data + doff, dlen);
    if (S->pwlen) {
        crypt_setkey(&c, mat, 96, S->pw, S->pwlen);
        crypt_encrypt(&c, edata, dlen);
    }
    memset(&kids, 0, sizeof(kids));
    put_chunk(&kids, "INFO", 0, info, ilen);
    put_chunk(&kids, "DFDT", 0, edfdt, 32);
    put_chunk(&kids, "DATA", 0, edata, dlen);
    free(edata);
    memset(&out, 0, sizeof(out));
    put_chunk(&out, "DGCD", 1, kids.p, kids.len);
    free(kids.p);

    /* the recovery data (the .dgdr) */
    if (recovery) {
        buf_t dgcr, rec;
        u8 dgcrinfo[48];
        u32 rows, pages, l;
        recovery_params(out.len, level, &rows, &pages);
        l = (rows * 256 + pages * rows + rows) * 4;
        memset(&rec, 0, sizeof(rec));
        recovery_data(out.p, out.len, level, &rec);
        memset(dgcrinfo, 0, sizeof(dgcrinfo));
        dgcrinfo[0] = 0x43;
        memcpy(dgcrinfo + 4, &l, 4);
        { u32 c2 = 256; memcpy(dgcrinfo + 0x10, &c2, 4); }
        memcpy(dgcrinfo + 0x14, &rows, 4);
        memcpy(dgcrinfo + 0x18, &pages, 4);
        { u32 o = out.len, c3 = crc32_buf(out.p, out.len);
          memcpy(dgcrinfo + 0x28, &o, 4);
          memcpy(dgcrinfo + 0x2C, &c3, 4); }
        memset(&dgcr, 0, sizeof(dgcr));
        put_chunk(&dgcr, "INFO", 0, dgcrinfo, 48);
        {
            buf_t dat;
            memset(&dat, 0, sizeof(dat));
            put_chunk(&dat, "DATA", 0, rec.p, rec.len);
            bput(&dgcr, dat.p, dat.len);
            free(dat.p);
        }
        put_chunk(&out, "DGCR", 1, dgcr.p, dgcr.len);
        free(dgcr.p);
        free(rec.p);
        /* the trailing chunk (the file is a multiple of 32 bytes) */
        put_chunk(&out, "    ", 0, (const u8 *)"", 0);
    }
    if (!write_file(path, out.p, out.len)) { free(out.p); return 1; }
    printf("  %s (%u bytes)\n", path, out.len);
    free(out.p);
    return 0;
}

/* write the spanning files of one file */
static int write_spanning(const char *base, const char *file, u32 partsize,
                          int recovery, const u8 *pw, u32 pwlen)
{
    u8 *data = NULL, st[64], dfdt[32];
    u32 size = 0, i, nparts, namelen, crc, poff, plen;
    u64 ft;
    char name[512], path[1024];
    FILE *f;
    sha512_t h;
    span_t S;

    /* the file */
    f = fopen(file, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", file); return 1; }
    fseek(f, 0, SEEK_END);
    { long l = ftell(f); if (l < 0) { fclose(f); return 1; } size = (u32)l; }
    fseek(f, 0, SEEK_SET);
    data = (u8 *)malloc(size ? size : 1);
    if (!data) { fprintf(stderr, "out of memory\n"); return 2; }
    if (size && fread(data, 1, size, f) != size) {
        fprintf(stderr, "read error\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    /* the name of the file (with its extension) */
    {
        const char *b = strrchr(file, '\\');
        const char *p = b ? b + 1 : file;
        namelen = (u32)strlen(p);
        if (namelen > sizeof(name) - 1) namelen = sizeof(name) - 1;
        memcpy(name, p, namelen);
        name[namelen] = 0;
    }

    /* the SHA-512 of the whole file, its CRC-32 and its time stamp */
    sha512_init(&h);
    sha512_update(&h, data, size);
    sha512_final(&h);
    sha512_state(&h, st);
    crc = crc32_buf(data, size);
    ft = file_time(file, 1);
    memset(dfdt, 0, sizeof(dfdt));
    memcpy(dfdt + 0x00, &crc, 4);
    { u32 v = 32; memcpy(dfdt + 0x04, &v, 4); }
    memcpy(dfdt + 0x10, &ft, 8);

    /* the number of the parts */
    if (!partsize) partsize = size ? size : 1;
    nparts = (size + partsize - 1) / partsize;
    if (!nparts) nparts = 1;

    printf("%s: %u bytes, %u part(s) of %u bytes\n", file, size, nparts,
           partsize);

    memset(&S, 0, sizeof(S));
    S.data = data;
    S.totalsize = size;
    S.st = st;
    S.dfdt = dfdt;
    S.name = name;
    S.namelen = namelen;
    S.pw = pw;
    S.pwlen = pwlen;

    /* the .dgd set */
    for (i = 0; i < nparts; i++) {
        S.partidx = i;
        S.nparts = nparts;
        poff = i * partsize;
        plen = size - poff;
        if (plen > partsize) plen = partsize;
        sprintf(path, "%s%04u.dgd", base, i);
        if (span_write_part(&S, path, poff, plen, 0, 0)) return 1;
    }
    /* the .dgdr set: the first part is shorter (the recovery data needs
     * the room), the other parts hold the rest of the file */
    if (recovery) {
        u32 dstart = 0, dlen, reclen = 0, off, rows, pages, k, dnparts = 1;
        /* the size of the parity table (it depends on the size of the
         * file, which depends on the size of the parity table) */
        for (k = 0; k < 16; k++) {
            u32 l;
            dlen = (partsize > DGCR_OVERHEAD + reclen) ?
                   partsize - DGCR_OVERHEAD - reclen : 0;
            off = 288 + dlen;
            recovery_params(off, recovery, &rows, &pages);
            l = (rows * 256 + pages * rows + rows) * 4;
            if (l == reclen) break;
            reclen = l;
        }
        dlen = (partsize > DGCR_OVERHEAD + reclen) ?
               partsize - DGCR_OVERHEAD - reclen : 0;
        while (dstart + dlen < size) {
            u32 rest = size - (dstart + dlen);
            dstart += dlen;
            dlen = rest > partsize ? partsize : rest;
            dnparts++;
        }
        dstart = 0;
        dlen = (partsize > DGCR_OVERHEAD + reclen) ?
               partsize - DGCR_OVERHEAD - reclen : 0;
        for (i = 0; i < dnparts; i++) {
            S.partidx = i;
            S.nparts = dnparts;
            sprintf(path, "%s%04u.dgdr", base, i);
            if (span_write_part(&S, path, dstart, dlen, 1, recovery)) return 1;
            dstart += dlen;
            {
                u32 rest = size - dstart;
                dlen = rest > partsize ? partsize : rest;
            }
        }
    }
    free(data);
    return 0;
}

/* ------------------------- the directory tree ------------------------- */
static void add_entry(entry_t **pents, int *nents, int *cap, const char *file,
                      const char *path, struct stat *st, int identity, int depth)
{
    entry_t *ents = *pents;
    if (*nents >= *cap) {
        int nc = *cap ? *cap * 2 : 256;
        entry_t *ne = (entry_t *)realloc(ents, (size_t)nc * sizeof(entry_t));
        if (!ne) { fprintf(stderr, "out of memory\n"); exit(2); }
        memset(ne + *cap, 0, (size_t)(nc - *cap) * sizeof(entry_t));
        ents = ne;
        *pents = ne;
        *cap = nc;
    }
    strncpy(ents[*nents].file, file, 1023);
    ents[*nents].file[1023] = 0;
    strncpy(ents[*nents].path, path, 1023);
    ents[*nents].path[1023] = 0;
    ents[*nents].size = (u32)st->st_size;
    ents[*nents].attr = (st->st_mode & S_IFDIR) ? 0x10 : 0x20;
    ents[*nents].ctime = identity ? 0 : file_time(file, 0);
    ents[*nents].mtime = identity ? 0 : file_time(file, 1);
    ents[*nents].crc = 0;
    (*nents)++;
    if (st->st_mode & S_IFDIR) {
        char dir[1024], sub[1024], *p;
        WIN32_FIND_DATAA fd;
        HANDLE h;
        strncpy(dir, file, 1023);
        dir[1023] = 0;
        strcat(dir, "\\*");
        h = FindFirstFileA(dir, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                struct stat s2;
                if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
                    continue;
                sprintf(sub, "%s\\%s", file, fd.cFileName);
                if (stat(sub, &s2) != 0) continue;
                {
                    char npath[1024];
                    sprintf(npath, "%s\\%s", path, fd.cFileName);
                    add_entry(pents, nents, cap, sub, npath, &s2, identity,
                              depth + 1);
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        p = 0; (void)p;
    }
}

/* the test mode: the CM coder of a file (-T) */
static int test_mode(const char *path)
{
    FILE *f = fopen(path, "rb");
    u8 *data;
    long n;
    buf_t out;
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    data = (u8 *)malloc(n ? n : 1);
    if (fread(data, 1, n, f) != (size_t)n) { fprintf(stderr, "read\n"); return 1; }
    fclose(f);
    memset(&out, 0, sizeof(out));
    cm_stream(data, (u32)n, 0x46453320u, 0, &out);
    {
        char name[1024];
        FILE *g;
        strcpy(name, path);
        strcat(name, ".cm");
        g = fopen(name, "wb");
        if (g) { fwrite(out.p, 1, out.len, g); fclose(g); }
        printf("%s: %ld bytes -> %u\n", name, n, out.len);
    }
    return 0;
}

/* ------------------------------- main ------------------------------- */


static void usage(void)
{
    printf("dgcpk - the DGC archiver (the format of DGCA v1.10)\n"
           "usage: dgcpk a [-n] [-f] [-i] [-r<n>] <archive> <file>...\n"
           "       dgcpk s [-S<n>] [-p<password>|-k<keyfile>] [-r<n>] <base> <file>\n"
           "  -n   do not compress\n"
           "  -f   one block per file\n"
           "  -i   identity: do not write the time stamps\n"
           "  -r<n>  append the recovery data (the parity table)\n"
           "  -S<n>  the size of a part of a spanning file (in bytes)\n"
           "  -p   the password of an encrypted spanning file (-p secret)\n"
           "  -k   the key file of an encrypted spanning file (-k mykey.key)\n"
           "\n"
           "  the command s writes the spanning files of a big file:\n"
           "  <base>0000.dgd, <base>0001.dgd, ... (and with -r the same\n"
           "  parts with the recovery data: <base>0000.dgdr, ...)\n");
    exit(1);
}

int main(int argc, char **argv)
{
    entry_t *ents = NULL;
    int nents = 0, i, j;
    int nocompress = 0, perfile = 0, identity = 0, recovery = 0;
    int spanning = 0;
    u32 partsize = 0;
    const char *outpath = NULL, *inpath = NULL, *pwarg = NULL, *keyfile = NULL;
    u8 pw[256];
    u32 pwlen = 0;
    buf_t out, dgcchunk, infochunk;
    u8 *alldata = NULL;
    u32 alldatasize = 0, dgcsize = 0;
    u32 params = 0x46453320u;
    FILE *f;
    u32 *coff = NULL, *csize = NULL;

    if (argc > 2 && !strcmp(argv[1], "-T")) return test_mode(argv[2]);
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "a")) continue;
        else if (!strcmp(argv[i], "s")) spanning = 1;
        else if (!strcmp(argv[i], "-n")) nocompress = 1;
        else if (!strcmp(argv[i], "-f")) perfile = 1;
        else if (!strcmp(argv[i], "-i")) identity = 1;
        else if (!strncmp(argv[i], "-r", 2)) recovery = atoi(argv[i] + 2);
        else if (!strncmp(argv[i], "-S", 2)) partsize = (u32)strtoul(argv[i] + 2, NULL, 0);
        else if (!strncmp(argv[i], "-p", 2) && argv[i][2]) pwarg = argv[i] + 2;
        else if (!strncmp(argv[i], "-k", 2) && argv[i][2]) keyfile = argv[i] + 2;
        else if (argv[i][0] == '-') usage();
        else if (!outpath) outpath = argv[i];
        else if (!inpath) inpath = argv[i];
    }
    if (!outpath) usage();

    /* the spanning files: dgcpk s [switches] <base> <file> */
    if (spanning) {
        if (!inpath) usage();
        if (pwarg) {
            pwlen = (u32)strlen(pwarg);
            if (pwlen > sizeof(pw) - 1) pwlen = sizeof(pw) - 1;
            memcpy(pw, pwarg, pwlen);
        } else if (keyfile) {
            pwlen = password_from_keyfile(keyfile, pw, sizeof(pw));
            if (!pwlen) return 1;
        }
        return write_spanning(outpath, inpath, partsize, recovery, pw, pwlen);
    }

    /* the archive encryption is not written by this packer - do not
     * silently write a plain archive when -p / -k was given */
    if (pwarg || keyfile) {
        fprintf(stderr, "dgcpk: -p / -k are only supported by the spanning "
                        "files (dgcpk s);\n"
                        "        this packer does not write encrypted "
                        "archives.\n");
        return 1;
    }

    {
        int cap = 0;
        for (i = 1; i < argc; i++) {
            struct stat st;
            if (!strcmp(argv[i], "a") || argv[i][0] == '-') continue;
            if (outpath == argv[i]) continue;
            if (stat(argv[i], &st) != 0) {
                fprintf(stderr, "cannot stat %s\n", argv[i]);
                return 1;
            }
            add_entry(&ents, &nents, &cap, argv[i], relpath(argv[i]), &st,
                      identity, 0);
        }
    }
    if (!nents) usage();
    coff = (u32 *)calloc(nents, sizeof(u32));
    csize = (u32 *)calloc(nents, sizeof(u32));
    if (!coff || !csize) { fprintf(stderr, "out of memory\n"); return 2; }

    /* the data */
    {
        u32 total = 0;
        for (i = 0; i < nents; i++) total += ents[i].size;
        alldata = (u8 *)malloc(total ? total : 1);
        if (!alldata) { fprintf(stderr, "out of memory\n"); return 2; }
        alldatasize = 0;
        for (i = 0; i < nents; i++) {
            FILE *g = fopen(ents[i].file, "rb");
            if (g) {
                alldatasize += (u32)fread(alldata + alldatasize, 1,
                                          ents[i].size, g);
                fclose(g);
            }
            ents[i].crc = crc32_buf(alldata + alldatasize - ents[i].size,
                                    ents[i].size);
        }
    }

    /* the DATA chunk: the DGCC chunk(s) */
    memset(&dgcchunk, 0, sizeof(dgcchunk));
    {
        buf_t blocks;
        memset(&blocks, 0, sizeof(blocks));
        if (perfile) {
            u32 off = 0;
            for (i = 0; i < nents; i++) {
                buf_t blk, dgcc;
                memset(&blk, 0, sizeof(blk));
                memset(&dgcc, 0, sizeof(dgcc));
                put_data_block(alldata + off, ents[i].size, params, nocompress, &blk);
                off += ents[i].size;
                put_chunk(&dgcc, "DGCC", 0, blk.p, blk.len);
                coff[i] = dgcchunk.len;
                csize[i] = dgcc.len;
                bput(&dgcchunk, dgcc.p, dgcc.len);
                free(dgcc.p);
                free(blk.p);
            }
        } else {
            buf_t blk, dgcc;
            memset(&blk, 0, sizeof(blk));
            memset(&dgcc, 0, sizeof(dgcc));
            put_data_block(alldata, alldatasize, params, nocompress, &blk);
            put_chunk(&dgcc, "DGCC", 0, blk.p, blk.len);
            for (i = 0; i < nents; i++) { coff[i] = 0; csize[i] = dgcc.len; }
            bput(&dgcchunk, dgcc.p, dgcc.len);
            free(dgcc.p);
            free(blk.p);
        }
        dgcsize = dgcchunk.len;
        free(blocks.p);
    }

    memset(&infochunk, 0, sizeof(infochunk));

    /* the IARC (the first child of the INFO chunk) */
    {
        u8 iarc[80];
        u64 n = (u64)nents, total = 0, idxtbl = (u64)nents * 64;
        u64 ctime;
        u32 namelen = 0;
        memset(iarc, 0, sizeof(iarc));
        memcpy(iarc + 4, " 001", 4);
        ctime = identity ? 0 : file_time(outpath, 1);
        memcpy(iarc + 16, &ctime, 8);
        for (i = 0; i < nents; i++) {
            total += ents[i].size;
            namelen += 4 + (u32)strlen(ents[i].path);
        }
        memcpy(iarc + 0x28, &n, 8);
        memcpy(iarc + 0x30, &total, 8);
        memcpy(iarc + 0x38, &idxtbl, 8);
        memcpy(iarc + 0x40, &namelen, 4);
        put_chunk(&infochunk, "IARC", 0, iarc, 80);
    }

    /* the index: the 64 byte entries, transposed */
    {
        u8 *idx = (u8 *)calloc(nents, 64);
        buf_t blk, dgcc;
        if (!idx) { fprintf(stderr, "out of memory\n"); return 2; }
        for (i = 0; i < nents; i++) {
            u8 row[64];
            u64 v;
            memset(row, 0, 64);
            v = ents[i].crc;      memcpy(row + 0x00, &v, 4);
            v = ents[i].attr;     memcpy(row + 0x04, &v, 4);
            v = ents[i].ctime;    memcpy(row + 0x08, &v, 8);
            v = ents[i].mtime;    memcpy(row + 0x10, &v, 8);
            v = ents[i].size;     memcpy(row + 0x18, &v, 8);
            v = csize[i];         memcpy(row + 0x20, &v, 8);
            v = coff[i];          memcpy(row + 0x28, &v, 8);
            for (j = 0; j < 64; j++) idx[j * nents + i] = row[j];
        }
        memset(&blk, 0, sizeof(blk));
        memset(&dgcc, 0, sizeof(dgcc));
        put_data_block(idx, nents * 64, params, nocompress, &blk);
        put_chunk(&dgcc, "DGCC", 0, blk.p, blk.len);
        put_chunk(&infochunk, "IFDT", 0, dgcc.p, dgcc.len);
        free(dgcc.p);
        free(blk.p);
        free(idx);
    }

    /* the name list */
    {
        buf_t names, blk, dgcc;
        u32 namelen = 0;
        memset(&names, 0, sizeof(names));
        memset(&blk, 0, sizeof(blk));
        memset(&dgcc, 0, sizeof(dgcc));
        for (i = 0; i < nents; i++) {
            u32 l = (u32)strlen(ents[i].path);
            bput32(&names, l);
            bput(&names, ents[i].path, l);
            namelen += 4 + l;
        }
        put_data_block(names.p, names.len, params, nocompress, &blk);
        put_chunk(&dgcc, "DGCC", 0, blk.p, blk.len);
        put_chunk(&infochunk, "IFNM", 0, dgcc.p, dgcc.len);
        free(dgcc.p);
        free(blk.p);
        free(names.p);

    }

    /* the archive */
    memset(&out, 0, sizeof(out));
    {
        buf_t dgca;
        memset(&dgca, 0, sizeof(dgca));
        put_chunk(&dgca, "DATA", 0, dgcchunk.p, dgcchunk.len);
        put_chunk(&dgca, "INFO", 1, infochunk.p, infochunk.len);
        put_chunk(&out, "DGCA", 1, dgca.p, dgca.len);
        free(dgca.p);
    }
    /* the recovery data (the DGCR chunk) */
    if (recovery) {
        buf_t rec, dgcr;
        u8 info[48];
        u32 crc;
        memset(&rec, 0, sizeof(rec));
        memset(&dgcr, 0, sizeof(dgcr));
        recovery_data(out.p, out.len, recovery, &rec);
        memset(info, 0, sizeof(info));
        info[0] = 0x43;
        {
            u32 l = rec.len;
            u32 cols = 256, rows, pages;
            u64 sz = out.len;
            memcpy(info + 4, &l, 4);
            /* the rows and the pages (the same formula as the tool) */
            rows = (u32)(((u64)sz + ((u64)(cols >> (recovery - 1)) * 1024) - 1) /
                         ((u64)(cols >> (recovery - 1)) * 1024));
            if (rows < 4) rows = 4;
            pages = (u32)(((u64)sz + (u64)rows * 1024 - 1) / ((u64)rows * 1024));
            if (pages == 1) rows = (u32)((sz + 1023) / 1024);
            memcpy(info + 0x10, &cols, 4);
            memcpy(info + 0x14, &rows, 4);
            memcpy(info + 0x18, &pages, 4);
        }
        {
            u32 off = out.len;
            crc = crc32_buf(out.p, out.len);
            memcpy(info + 0x28, &off, 4);
            memcpy(info + 0x2C, &crc, 4);
        }
        put_chunk(&dgcr, "INFO", 0, info, 48);
        {
            buf_t dat;
            memset(&dat, 0, sizeof(dat));
            put_chunk(&dat, "DATA", 0, rec.p, rec.len);
            bput(&dgcr, dat.p, dat.len);
            free(dat.p);
        }
        put_chunk(&out, "DGCR", 1, dgcr.p, dgcr.len);
        free(dgcr.p);
        free(rec.p);
    }
    f = fopen(outpath, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", outpath); return 1; }
    fwrite(out.p, 1, out.len, f);
    fclose(f);
    printf("%s: %d entries, %u bytes\n", outpath, nents, out.len);
    free(out.p);
    free(dgcchunk.p);
    free(infochunk.p);
    free(alldata);
    free(ents);
    free(coff);
    free(csize);
    return 0;
}
