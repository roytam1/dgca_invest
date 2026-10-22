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

static u32 crc32_buf(const u8 *p, u32 n)
{
    u32 c = 0xFFFFFFFFu, i;
    if (!crc_ready) crc_init();
    for (i = 0; i < n; i++)
        c = crc_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
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
    if (!x) return 31;
    while (!(x & 0x80000000u)) { x <<= 1; n++; }
    return n;
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

/* ------------------------- the block compressor ------------------------- *
 *  the block stream: the tag 1 block (the compressed data) */
static void compress_block(const u8 *data, u32 size, u32 params,
                           buf_t *out)
{
    buf_t lits, model, A, B;
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
    /* the token buffer (the literals) with the CM coder */
    cm_stream(lits.p, lits.len, params, firstbyte_zero, &A);
    /* the block header */
    bput32(out, 1);           /* the tag */
    bput32(out, size);        /* the original size */
    bput32(out, 0x04);        /* the flags: the pre-transform */
    bput32(out, params);
    bput32(out, 0);          /* v22: the chain walk's start (not used) */
    bput32(out, lits.len);    /* v7: the token buffer's size */
    bput32(out, A.len);
    bput32(out, model.len);
    bput(out, A.p, A.len);
    bput(out, model.p, model.len);
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
    hdr[18] = hdr[19] = hdr[20] = hdr[21] = 0;
    hdr[20] = 1; hdr[21] = hdr[22] = hdr[23] = 0;      /* the version */
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
static void recovery_data(const u8 *arch, u32 size, int level, buf_t *out)
{
    u32 rows, pages, cols = 256, i, j, k, words;
    u8 *par, *rowx, *off;
    buf_t plain;
    crypt_t c;

    rows = (u32)(((u64)size + ((u64)(cols >> (level - 1)) * 1024) - 1) /
                 ((u64)(cols >> (level - 1)) * 1024));
    if (rows < 4) rows = 4;
    pages = (u32)(((u64)size + (u64)rows * 1024 - 1) / ((u64)rows * 1024));
    if (pages == 1) rows = (size + 1023) / 1024;
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
    /* the offsets of the row blocks (part 3) */
    for (i = 0; i < rows; i++) {
        u32 v = i * cols * pages * 4;
        memcpy(off + i * 4, &v, 4);
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

/* ------------------------- the directory tree ------------------------- */
static void add_entry(entry_t *ents, int *nents, int maxents, const char *file,
                      const char *path, struct stat *st, int identity, int depth)
{
    if (*nents >= maxents) return;
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
                    add_entry(ents, nents, maxents, sub, npath, &s2, identity,
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
           "  -n   do not compress\n"
           "  -f   one block per file\n"
           "  -i   identity: do not write the time stamps\n"
           "  -r<n>  append the recovery data (the parity table)\n");
    exit(1);
}

int main(int argc, char **argv)
{
    entry_t *ents;
    int nents = 0, i, j;
    int nocompress = 0, perfile = 0, identity = 0, recovery = 0;
    const char *outpath = NULL;
    buf_t out, dgcchunk, infochunk;
    u8 *alldata = NULL;
    u32 alldatasize = 0, dgcsize = 0;
    u32 params = 0x46453320u;
    FILE *f;
    u32 *coff = NULL, *csize = NULL;

    if (argc > 2 && !strcmp(argv[1], "-T")) return test_mode(argv[2]);
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "a")) continue;
        else if (!strcmp(argv[i], "-n")) nocompress = 1;
        else if (!strcmp(argv[i], "-f")) perfile = 1;
        else if (!strcmp(argv[i], "-i")) identity = 1;
        else if (!strncmp(argv[i], "-r", 2)) recovery = atoi(argv[i] + 2);
        else if (argv[i][0] == '-') usage();
        else if (!outpath) outpath = argv[i];
    }
    if (!outpath) usage();
    ents = (entry_t *)calloc(argc, sizeof(entry_t));
    coff = (u32 *)calloc(argc, sizeof(u32));
    csize = (u32 *)calloc(argc, sizeof(u32));
    if (!ents || !coff || !csize) { fprintf(stderr, "out of memory\n"); return 2; }
    for (i = 1; i < argc; i++) {
        struct stat st;
        if (!strcmp(argv[i], "a") || argv[i][0] == '-') continue;
        if (outpath == argv[i]) continue;
        if (stat(argv[i], &st) != 0) {
            fprintf(stderr, "cannot stat %s\n", argv[i]);
            return 1;
        }
        add_entry(ents, &nents, argc, argv[i], relpath(argv[i]), &st,
                  identity, 0);
    }
    if (!nents) usage();

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
                if (nocompress) store_block(alldata + off, ents[i].size, &blk);
                else compress_block(alldata + off, ents[i].size, params, &blk);
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
            if (nocompress) store_block(alldata, alldatasize, &blk);
            else compress_block(alldata, alldatasize, params, &blk);
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
        if (nocompress) store_block(idx, nents * 64, &blk);
        else compress_block(idx, nents * 64, params, &blk);
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
        if (nocompress) store_block(names.p, names.len, &blk);
        else compress_block(names.p, names.len, params, &blk);
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
