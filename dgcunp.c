/* ------------------------------------------------------------------ *
 *  dgcunp.c  -  Unpacker / lister for DGC archives (.dgc / .dgcr)
 *
 *  Reverse engineered from dgcac.exe (DGCA / DGC Archiver v1.10,
 *  SYN (Shin-ichi TSURUTA), 2000-2005).
 *
 *  Container format (all little endian):
 *
 *    struct Chunk {                 32 bytes
 *        char   id[4];              "DGCA" "DATA" "INFO" "IARC"
 *                                   "IFDT" "IFNM" "DGCC" "DGCR"
 *        uint32 hdr_size;           always 0x20
 *        uint32 payload_size;       bytes following this header
 *        uint32 zero_0c;
 *        uint32 flags;              1 on DGCA / INFO / DGCR
 *        uint32 align;              always 0x10
 *        uint32 crc_payload;        CRC-32 of the payload
 *        uint32 crc_header;         CRC-32 of these 32 bytes with
 *                                   this field set to zero
 *    };
 *
 *    A container's payload is the concatenation of its child records;
 *    every child record (32 byte header + payload) is zero padded to the
 *    next 16 byte boundary and the padding is counted in the parent's
 *    payload size.
 *
 *    DGCC payload = a stream of blocks:
 *        u32 tag, u32 size
 *        tag 0 : STORE      -> `size` raw bytes
 *        tag 1 : COMPRESSED -> 32 byte block header, stream A, stream B
 *        tag 2 : CHAIN      -> `size` blocks follow, each tag 1
 *
 *  Usage:  dgcunp [-l] [-v] [-o outdir] <archive>
 * ------------------------------------------------------------------ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <direct.h>
#include <sys\stat.h>
#include <windows.h>

typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned short     w16_t;   /* MSVC6: wchar_t is a C++ type */
typedef __int64            u64;

static u32 crc32_buf(const u8 *p, u32 n)
{
    static u32 tab[256];
    static int init = 0;
    u32 c = 0xFFFFFFFFu, i;
    int k;
    if (!init) {
        for (k = 0; k < 256; k++) {
            u32 v = (u32)k;
            int b;
            for (b = 0; b < 8; b++)
                v = (v & 1) ? (0xEDB88320u ^ (v >> 1)) : (v >> 1);
            tab[k] = v;
        }
        init = 1;
    }
    for (i = 0; i < n; i++)
        c = tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ------------------------- byte buffer ------------------------- */
typedef struct { u8 *p; u32 len, cap; } buf_t;

static void bput(buf_t *b, const void *d, u32 n)
{
    if (b->len + n > b->cap) {
        u32 nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + n) nc *= 2;
        b->p = (u8 *)realloc(b->p, nc);
        if (!b->p) { fprintf(stderr, "out of memory\n"); exit(2); }
        b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

static u32 rd32(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static u64 rd64(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }

/* ------------------------- chunk tree ------------------------- */
#define MAXCHUNK 64
typedef struct {
    u32 off, psize, depth;
    char id[5];
} chunk_t;

static chunk_t g_chunks[MAXCHUNK];
static int    g_nchunk;
static u8    *g_img;
static u32    g_imgsize;
static int    g_broken;

static int chunk_is_container(const char *id)
{
    return !strcmp(id, "DGCA") || !strcmp(id, "DATA") || !strcmp(id, "INFO") ||
           !strcmp(id, "DGCR") || !strcmp(id, "IFDT") || !strcmp(id, "IFNM");
}

static u32 align16(u32 x) { return (x + 15u) & ~15u; }

static int chunk_id_known(const char *id)
{
    return !strcmp(id, "DGCA") || !strcmp(id, "DATA") || !strcmp(id, "INFO") ||
           !strcmp(id, "DGCR") || !strcmp(id, "IFDT") || !strcmp(id, "IFNM") ||
           !strcmp(id, "DGCC") || !strcmp(id, "IARC");
}

static void walk(u32 off, u32 end, u32 depth, const char *parent)
{
    u32 p = off;
    while (p + 32 <= end) {
        const u8 *h = g_img + p;
        u32 ps = rd32(h + 8);
        chunk_t *c;
        char id[5];
        if (g_nchunk >= MAXCHUNK) return;
        memcpy(id, h, 4); id[4] = 0;
        /* the recovery data (a DGCR chunk) is scrambled by design: don't
         * walk into it.  An encrypted archive has its DGCC headers
         * encrypted: stop there. */
        if (!chunk_id_known(id)) {
            if (!parent || strcmp(parent, "DGCR")) g_broken = 1;
            return;
        }
        c = &g_chunks[g_nchunk++];
        c->off = p; c->psize = ps; c->depth = depth;
        memcpy(c->id, h, 4); c->id[4] = 0;
        if (strcmp(c->id, "DGCR") && chunk_is_container(c->id))
            walk(p + 32, p + 32 + ps, depth + 1, c->id);
        p = align16(p + 32 + ps);
    }
}

static chunk_t *find_chunk(const char *id, u32 depth)
{
    int i;
    for (i = 0; i < g_nchunk; i++)
        if (!strcmp(g_chunks[i].id, id) && g_chunks[i].depth == depth)
            return &g_chunks[i];
    return NULL;
}

static chunk_t *child_chunk(chunk_t *parent, const char *id)
{
    static chunk_t res;
    u32 p = parent->off + 32, end = parent->off + 32 + parent->psize;
    while (p + 32 <= end) {
        const u8 *h = g_img + p;
        u32 ps = rd32(h + 8);
        if (!memcmp(h, id, 4)) {
            res.off = p; res.psize = ps; res.depth = parent->depth + 1;
            memcpy(res.id, h, 4); res.id[4] = 0;
            return &res;
        }
        p = align16(p + 32 + ps);
    }
    return NULL;
}

static int chunk_crc_ok(chunk_t *c, int verbose)
{
    const u8 *h = g_img + c->off;
    u32 pcrc = rd32(h + 24), hcrc = rd32(h + 28);
    u8 tmp[32];
    int okp, okh;
    memcpy(tmp, h, 32);
    memset(tmp + 28, 0, 4);
    okp = (crc32_buf(g_img + c->off + 32, c->psize) == pcrc);
    okh = (crc32_buf(tmp, 32) == hcrc);
    if (verbose && (!okp || !okh))
        printf("    ! %-4s @%#08x  payloadCRC %s  headerCRC %s\n",
               c->id, c->off, okp ? "ok" : "BAD", okh ? "ok" : "BAD");
    return okp && okh;
}

/* ---------------------- DGCC block framing ---------------------- */
typedef struct {
    u32 tag, size;         /* size: tag 1 -> the ORIGINAL uncompressed size */
    u32 flags, params, v22, v7, lenA, lenB;
    const u8 *A, *B;
} dblock_t;

static int dgc_blocks(const u8 *pay, u32 len, dblock_t *out, int max)
{
    u32 o = 0;
    int n = 0;
    while (o + 8 <= len && n < max) {
        dblock_t *b = &out[n];
        b->tag = rd32(pay + o);
        b->size = rd32(pay + o + 4);
        b->flags = b->params = b->v22 = b->v7 = b->lenA = b->lenB = 0;
        b->A = b->B = NULL;
        if (b->tag == 0) {
            if (o + 8 + b->size > len) return -1;
            b->A = pay + o + 8;
            o += 8 + b->size;
        } else if (b->tag == 1) {
            if (o + 32 > len) return -1;
            b->flags  = rd32(pay + o + 8);
            b->params = rd32(pay + o + 12);
            b->v22    = rd32(pay + o + 16);
            b->v7     = rd32(pay + o + 20);
            b->lenA   = rd32(pay + o + 24);
            b->lenB   = rd32(pay + o + 28);
            if (o + 32 + b->lenA + b->lenB > len) return -1;
            b->A = pay + o + 32;
            b->B = b->A + b->lenA;
            o += 32 + b->lenA + b->lenB;
        } else if (b->tag == 2) {
            /* CHAIN: `size` compressed blocks follow; expand them in place */
            u32 cnt = b->size, k, oo = o + 8;
            for (k = 0; k < cnt && n < max; k++) {
                dblock_t *ib = &out[n];
                if (oo + 32 > len) break;
                ib->tag = rd32(pay + oo);
                ib->size = rd32(pay + oo + 4);
                if (ib->tag == 0) {
                    if (oo + 8 + ib->size > len) break;
                    ib->A = pay + oo + 8;
                    ib->B = NULL;
                    ib->flags = ib->params = ib->v22 = ib->v7 = ib->lenA = ib->lenB = 0;
                    oo += 8 + ib->size;
                } else if (ib->tag == 1) {
                    ib->flags  = rd32(pay + oo + 8);
                    ib->params = rd32(pay + oo + 12);
                    ib->v22    = rd32(pay + oo + 16);
                    ib->v7     = rd32(pay + oo + 20);
                    ib->lenA   = rd32(pay + oo + 24);
                    ib->lenB   = rd32(pay + oo + 28);
                    if (oo + 32 + ib->lenA + ib->lenB > len) break;
                    ib->A = pay + oo + 32;
                    ib->B = ib->A + ib->lenA;
                    oo += 32 + ib->lenA + ib->lenB;
                } else break;
                n++;
            }
            o = oo;
            continue;                    /* the chain itself is not a block */
        } else {
            return -1;
        }
        n++;
    }
    return n;
}

/* ---------------------- GFL range decoder ---------------------- */
typedef struct {
    const u8 *buf; u32 len, pos;
    u32 code, range, prev;
} rng_t;

static void rng_init(rng_t *r, const u8 *buf, u32 len)
{
    u32 b;
    r->buf = buf; r->len = len; r->pos = 0;
    if (r->pos < r->len) r->pos++;              /* the encoder's dummy byte */
    b = (r->pos < r->len) ? r->buf[r->pos++] : 0;
    r->prev = b; r->code = b >> 1; r->range = 0x80;
}

static u32 rng_byte(rng_t *r)
{
    if (r->pos < r->len) return r->buf[r->pos++];
    r->pos++;
    return 0;
}

static void rng_renorm(rng_t *r)
{
    while (r->range <= 0x800000u) {
        u32 b;
        r->code = ((r->code << 1) | (r->prev & 1)) << 7;
        b = rng_byte(r);
        r->prev = b;
        r->code |= (b >> 1);
        r->range <<= 8;
        if (r->range == 0) { r->range = 0x800000u; return; }
    }
}

static u32 rng_raw(rng_t *r, int n)
{
    u32 v = 0; int i;
    for (i = 0; i < n; i++) {
        u32 half;
        rng_renorm(r);
        half = r->range >> 1;
        v <<= 1;
        if (r->code < half) r->range = half;
        else { v |= 1; r->code -= half; r->range -= half; }
    }
    return v;
}

/* gamma style symbol, level 0..count-1 */
static u32 rng_sym(rng_t *r, u32 *probs, int count, int shift, u32 base)
{
    int v = 0;
    for (;;) {
        u32 p, bound;
        rng_renorm(r);
        p = probs[base + v];
        bound = p * (r->range >> 12);
        if (r->code < bound) {
            r->range = bound;
            probs[base + v] += (4096u - probs[base + v]) >> shift;
            v++;
            if (v >= count) break;
        } else {
            r->range -= bound; r->code -= bound;
            probs[base + v] -= probs[base + v] >> shift;
            break;
        }
    }
    if (v <= 1) return (u32)v;
    return (1u << (v - 1)) + rng_raw(r, v - 1);
}

/* ---------------------- context mixing decoder ---------------------- */
typedef struct {
    u32 lit[256];
    u32 ctx[32];
    u32 run[32 * 256];
    u32 pair[65536];
    u32 state;
    int p_lit, p_pairb, p_pair, p_ctx, p_run, p_minlen, p_lzsh, mode;
} cm_t;

static int bsr32(u32 x) { int r = 31; if (x) { while (!(x & 0x80000000u)) { x <<= 1; r--; } } return r; }

static void cm_init(cm_t *c, u32 params)
{
    int i;
    for (i = 0; i < 256; i++) c->lit[i] = 2048;
    for (i = 0; i < 32; i++)  c->ctx[i] = 2048;
    for (i = 0; i < 32 * 256; i++) c->run[i] = 2048;
    for (i = 0; i < 65536; i++) c->pair[i] = 2048;
    c->state = 0;
    c->p_lit    = (params >> 4) & 0xF;
    c->p_pairb  = (params >> 8) & 0xF;
    c->p_pair   = (params >> 12) & 0xF;
    c->p_ctx    = (params >> 16) & 0xF;
    c->p_run    = (params >> 20) & 0xF;
    c->p_minlen = (params >> 24) & 0xF;
    c->p_lzsh   = (params >> 28) & 0xF;
    c->mode     = (params >> 1) & 1;
}

static u32 cm_literal(rng_t *r, cm_t *C, int prev)
{
    u32 *lit = C->lit, *pair = C->pair, *a5 = C->ctx;
    int ci = bsr32(C->state);
    u32 w = a5[ci];
    u32 chain, scale = 0x2000, node, value = 0;
    u32 saved[8];
    u32 v58 = 0x80000, v57 = 0x80000;   /* the two model confidences */
    int i;

    /* ---- the prepare pass -------------------------------------------
     * The tree of the PREVIOUS byte is walked from the deepest node up:
     *     node_k = (prev|0x100) >> k          (k = 1..8)
     *     bit_k  = (prev|0x100) >> (k-1) & 1
     * lit[node] is temporarily moved TOWARD that bit; the magnitude is
     *     d = ((4096-lit) or lit) * scale >> 13
     * and the scale of the NEXT level is that magnitude d.
     */
    chain = (u32)prev | 0x100;
    for (i = 0; i < 8; i++) {
        u32 bit = chain & 1, nd = chain >> 1, p = lit[nd], d;
        saved[i] = p;
        if (bit) { d = (scale * (4096u - p)) >> 13; lit[nd] = p + d; }
        else     { d = (scale * p) >> 13;         lit[nd] = p - d; }
        scale = d;
        chain = nd;
    }

    /* ---- the main loop: the 8 bits of the literal, MSB first -------- */
    node = 1;
    for (i = 0; i < 8; i++) {
        u32 pr, bound, code, rng, p;
        int bit;
        pr = (w * lit[node] + pair[256 * prev + node] * (4096u - w)) >> 12;
        rng_renorm(r);
        code = r->code; rng = r->range;
        bound = pr * (rng >> 12);
        if (code < bound) {
            bit = 0;
            r->range = bound;
            v58 = (v58 * lit[node]) >> 12;
            v57 = (v57 * pair[256 * prev + node]) >> 12;
            p = pair[256 * prev + node];
            pair[256 * prev + node] = p + ((4096u - p) >> C->p_pair);
        } else {
            bit = 1;
            r->range = rng - bound; r->code = code - bound;
            v58 = (v58 * (4096u - lit[node])) >> 12;
            p = pair[256 * prev + node];
            v57 = (v57 * (4096u - p)) >> 12;
            pair[256 * prev + node] = p - (p >> C->p_pair);
        }
        node = 2 * node + (u32)bit;
        value = 2 * value + (u32)bit;
    }

    /* ---- the restore pass: the same nodes as the prepare pass ------- */
    chain = (u32)prev | 0x100;
    for (i = 0; i < 8; i++) {
        u32 bit = chain & 1, nd = chain >> 1, p = saved[i], q;
        lit[nd] = p;
        if (bit) { lit[nd] = p - (p >> C->p_lit);
                   q = pair[256 * value + nd];
                   pair[256 * value + nd] = q - (q >> C->p_pairb); }
        else     { lit[nd] = p + ((4096u - p) >> C->p_lit);
                   q = pair[256 * value + nd];
                   pair[256 * value + nd] = q + ((4096u - q) >> C->p_pairb); }
        chain = nd;
    }

    /* ---- the state and the context weight --------------------------- */
    {
        int v55 = (v58 <= v57);
        C->state = (v58 * w + v57 * (4096u - w)) >> 12;
        if (v58 < v57) { a5[ci] -= a5[ci] >> C->p_ctx; v55 = (v58 <= v57); }
        if (!v55)     { a5[ci] += (4096u - a5[ci]) >> C->p_ctx; }
    }
    return value & 0xFF;
}

static u32 cm_match(rng_t *r, cm_t *C, int prev)
{
    u32 *lit = C->lit, *pair = C->pair, *a5 = C->ctx;
    int ci = bsr32(C->state);
    u32 w = a5[ci];
    u32 v18 = 0x80000, v17 = 0x80000, v19 = 0, v8 = 1;
    int v21 = 8;
    for (;;) {
        u32 pr, bound, code, rng;
        int v13, last;
        pr = (w * lit[v8] + pair[256 * prev + v8] * (4096u - w)) >> 12;
        rng_renorm(r);
        code = r->code; rng = r->range;
        bound = pr * (rng >> 12);
        if (code < bound) {
            u32 p;
            r->range = bound;
            v18 = (v18 * lit[v8]) >> 12;
            v17 = (v17 * pair[256 * prev + v8]) >> 12;
            v13 = 0;
            p = pair[256 * prev + v8]; pair[256 * prev + v8] = p + ((4096u - p) >> C->p_pair);
            lit[v8] += (4096u - lit[v8]) >> C->p_lit;
        } else {
            u32 p = pair[256 * prev + v8];
            r->range = rng - bound; r->code = code - bound;
            v18 = (v18 * (4096u - lit[v8])) >> 12;
            v17 = (v17 * (4096u - p)) >> 12;
            v13 = 1;
            pair[256 * prev + v8] = p - (p >> C->p_pair);
            lit[v8] -= lit[v8] >> C->p_lit;
        }
        last = (v21 == 1);
        v8 = (u32)v13 + 2 * v8;
        v19 = (u32)v13 + 2 * v19;
        v21--;
        if (last) break;
    }
    {
        int v15 = (v18 <= v17);
        C->state = (v18 * w + v17 * (4096u - w)) >> 12;
        if (v18 < v17) { a5[ci] -= a5[ci] >> C->p_ctx; v15 = (v18 <= v17); }
        if (!v15)     { a5[ci] += (4096u - a5[ci]) >> C->p_ctx; }
    }
    return v19 & 0xFF;
}

/* entropy decode: produces the token buffer (v7 bytes) */
static void entropy_decode(u32 params, const u8 *A, u32 lenA, u8 *out, u32 outlen)
{
    static cm_t C;
    rng_t r;
    u32 pos = 0;
    int prev;
    cm_init(&C, params);
    rng_init(&r, A, lenA);
    /* the object field this[0x2C] = 0xFF if the first byte of the block is 0 */
    prev = (params & 1) ? 0xFF : 0;
    while (pos < outlen) {
        if (C.mode) {
            u32 b = cm_match(&r, &C, prev);
            out[pos++] = (u8)b; prev = (int)b;
        } else {
            u32 b = cm_literal(&r, &C, prev);
            u32 rl, n, i;
            prev = (int)b;
            rl = rng_sym(&r, C.run, 32, C.p_run, 32 * b);
            n = rl + 1;
            if (pos + n > outlen) n = outlen - pos;
            for (i = 0; i < n; i++) out[pos++] = (u8)b;
        }
    }
}

/* LZ inverse: the chain walk over the byte histogram (sub_428990) */
static int lz_inverse(const u8 *src, u32 n, u32 start, u8 *dst)
{
    static u32 cnt[256];
    u32 *Block;
    u32 a = start, k;
    int i;
    if (n == 0) return 0;
    Block = (u32 *)malloc(sizeof(u32) * n);
    if (!Block) return -1;
    for (i = 0; i < 256; i++) cnt[i] = 0;
    for (k = 0; k < n; k++) cnt[src[k]]++;
    {
        u32 s = 0;
        for (i = 0; i < 256; i++) { u32 c = cnt[i]; cnt[i] = s; s += c; }
    }
    for (k = 0; k < n; k++) { Block[cnt[src[k]]] = k; cnt[src[k]]++; }
    for (k = 0; k < n; k++) {
        if (a >= n) { free(Block); return -1; }
        a = Block[a];
        if (a >= n) { free(Block); return -1; }
        dst[k] = src[a];
    }
    free(Block);
    return 0;
}

/* inverse pre-transform: LZ77 with an implicit distance (2 byte hash) */
static int pretransform_inverse(u32 params, const u8 *model, u32 lenModel,
                                const u8 *data, u32 n, u8 *out, u32 outlen)
{
    static cm_t C;
    static rng_t r;
    static u32 m1[32], m2[32];
    static u32 tbl[65536];
    u32 minlen, key = 0, op = 0, ip = 0;
    int i;
    cm_init(&C, params);
    rng_init(&r, model, lenModel);
    for (i = 0; i < 32; i++) { m1[i] = 2048; m2[i] = 2048; }
    for (i = 0; i < 65536; i++) tbl[i] = 0xFFFFFFFFu;
    minlen = 1u << C.p_minlen;
    while (op < outlen) {
        u32 nr = rng_sym(&r, m1, 32, C.p_lzsh, 0);
        u32 k;
        for (k = 0; k < nr && op < outlen; k++) {
            out[op] = (ip < n) ? data[ip] : 0;
            ip++;
            tbl[key] = op;
            key = ((key & 0xFF) << 8) | out[op];
            op++;
        }
        if (op >= outlen) break;
        {
            u32 ln = minlen + rng_sym(&r, m2, 32, C.p_lzsh, 0);
            if (ln && tbl[key] != 0xFFFFFFFFu) {
                u32 src = tbl[key];
                for (k = 0; k < ln && op < outlen; k++) {
                    if (src >= outlen) { out[op] = 0; src = 0; }
                    else out[op] = out[src];
                    src++;
                    tbl[key] = op;
                    key = ((key & 0xFF) << 8) | out[op];
                    op++;
                }
            }
        }
    }
    return 0;
}

/* the inverse delta transform of the "column" method (sub_424FE0):
 * the encoder stores d[i] = s[i] - s[i-1] (order 1) and
 * d[i] = d1[i] - d1[i-1] (order 2) */
static void inverse_delta(u8 *p, u32 n, int order)
{
    u8 prev = 0;
    u32 i;
    for (i = 0; i < n; i++) {
        u8 d = p[i];
        p[i] = (u8)(prev + d);
        prev = p[i];
    }
    if (order >= 2) {
        prev = 0;
        for (i = 0; i < n; i++) {
            u8 d = p[i];
            p[i] = (u8)(prev + d);
            prev = p[i];
        }
    }
}

/* decode one compressed block:
 *   entropy decode (stream A) -> token buffer (v7 bytes)
 *   LZ inverse  (chain walk)  -> pre-transform input
 *   pre-transform inverse (stream B) -> the original data (size bytes) */
static int decode_block(const dblock_t *b, u8 *out, u32 outlen)
{
    u8 *tok = (u8 *)malloc(b->v7 ? b->v7 : 1);
    u8 *lz = NULL;
    int rc = -1;
    if (!tok) return -1;
    entropy_decode(b->params, b->A, b->lenA, tok, b->v7);
    if (b->flags & 2) {
        lz = (u8 *)malloc(b->v7 ? b->v7 : 1);
        if (!lz) { free(tok); return -1; }
        if (lz_inverse(tok, b->v7, b->v22, lz) != 0) { free(lz); free(tok); return -1; }
    } else {
        lz = tok;
    }
    if (b->flags & 4) {
        rc = pretransform_inverse(b->params, b->B, b->lenB, lz, b->v7, out, outlen);
    } else {
        /* the column method: the delta transform (the flags' bits 16..19) */
        int order = (int)((b->flags >> 16) & 0xF);
        if (order) inverse_delta(lz, b->v7, order);
        memcpy(out, lz, b->v7 < outlen ? b->v7 : outlen);
        rc = 0;
    }
    if (lz != tok) free(lz);
    free(tok);
    return rc;
}

/* decode a whole DGCC payload (a stream of blocks) into a buffer.
 * A tag 2 block is the "column" method: `size` columns follow and have to
 * be de-interleaved again. */
static int dgc_decompress(const u8 *pay, u32 len, buf_t *out)
{
    u32 o = 0;
    while (o + 8 <= len) {
        u32 tag = rd32(pay + o), size = rd32(pay + o + 4);
        if (tag == 0) {
            if (o + 8 + size > len) return -1;
            bput(out, pay + o + 8, size);
            o += 8 + size;
        } else if (tag == 1) {
            dblock_t b;
            u8 *tmp;
            if (o + 32 > len) return -1;
            b.tag = 1;
            b.size = size;
            b.flags  = rd32(pay + o + 8);
            b.params = rd32(pay + o + 12);
            b.v22    = rd32(pay + o + 16);
            b.v7     = rd32(pay + o + 20);
            b.lenA   = rd32(pay + o + 24);
            b.lenB   = rd32(pay + o + 28);
            if (o + 32 + b.lenA + b.lenB > len) return -1;
            b.A = pay + o + 32;
            b.B = b.A + b.lenA;
            tmp = (u8 *)malloc(size ? size : 1);
            if (!tmp) return -1;
            if (decode_block(&b, tmp, size) == 0)
                bput(out, tmp, size);
            else {
                printf("  ! a compressed block could not be decoded\n");
                free(tmp);
                return -1;
            }
            free(tmp);
            o += 32 + b.lenA + b.lenB;
        } else if (tag == 2) {
            /* the column method: `size` columns, each a compressed block */
            u32 stride = size, oo = o + 8, k, i, total = 0, n;
            u8 **cols = NULL;
            u32 *csz = NULL;
            if (stride == 0) return -1;
            cols = (u8 **)malloc(sizeof(u8 *) * stride);
            csz = (u32 *)malloc(sizeof(u32) * stride);
            if (!cols || !csz) { free(cols); free(csz); return -1; }
            memset(cols, 0, sizeof(u8 *) * stride);
            memset(csz, 0, sizeof(u32) * stride);
            for (k = 0; k < stride; k++) {
                dblock_t b;
                u8 *tmp;
                if (oo + 32 > len) break;
                if (rd32(pay + oo) != 1) break;
                b.tag = 1;
                b.size = rd32(pay + oo + 4);
                b.flags  = rd32(pay + oo + 8);
                b.params = rd32(pay + oo + 12);
                b.v22    = rd32(pay + oo + 16);
                b.v7     = rd32(pay + oo + 20);
                b.lenA   = rd32(pay + oo + 24);
                b.lenB   = rd32(pay + oo + 28);
                if (oo + 32 + b.lenA + b.lenB > len) break;
                b.A = pay + oo + 32;
                b.B = b.A + b.lenA;
                tmp = (u8 *)malloc(b.size ? b.size : 1);
                if (!tmp) break;
                if (decode_block(&b, tmp, b.size) != 0) {
                    printf("  ! a compressed column could not be decoded\n");
                    free(tmp);
                    break;
                }
                cols[k] = tmp;
                csz[k] = b.size;
                total += b.size;
                oo += 32 + b.lenA + b.lenB;
            }
            /* de-interleave the columns */
            n = total / stride;
            {
                u8 *buf = (u8 *)malloc(total ? total : 1);
                if (buf) {
                    memset(buf, 0, total);
                    for (i = 0; i < n; i++)
                        for (k = 0; k < stride; k++)
                            if (i < csz[k]) buf[i * stride + k] = cols[k][i];
                    bput(out, buf, total);
                    free(buf);
                }
            }
            for (k = 0; k < stride; k++) if (cols[k]) free(cols[k]);
            free(cols);
            free(csz);
            o = oo;
        } else {
            return -1;
        }
    }
    return 0;
}

/* ------------------------- index / names ------------------------- */
typedef struct {
    u32 crc, attr;
    u64 ctime, mtime, size;
    u32 csize, doff;
    u32 nameoff, namelen;
} entry_t;

static entry_t *g_entries;
static int     g_nentry;
static u8     *g_nametab;
static u32     g_nametabsize;
static u8     *g_namepool;
static u32     g_namepoolsize, g_namepoolcap;

static void parse_index(chunk_t *ifdt)
{
    chunk_t *dg = child_chunk(ifdt, "DGCC");
    buf_t dec;
    const u8 *blob = NULL;
    u32 blobsize = 0;
    u32 n, e, c;
    if (!dg) return;
    memset(&dec, 0, sizeof(dec));
    if (dgc_decompress(g_img + dg->off + 32, dg->psize, &dec) != 0) {
        printf("note: the index table could not be decoded\n");
        free(dec.p);
        return;
    }
    blob = dec.p;
    blobsize = dec.len;
    n = blobsize / 64;
    if (n == 0) { free(dec.p); return; }
    if (!g_entries) {
        g_entries = (entry_t *)malloc(sizeof(entry_t) * n);
        if (!g_entries) { free(dec.p); return; }
    }
    for (e = 0; e < n; e++) {
        u8 row[64];
        for (c = 0; c < 64; c++) row[c] = blob[c * n + e];
        g_entries[e].crc   = rd32(row + 0);
        g_entries[e].attr  = rd32(row + 4);
        g_entries[e].ctime = rd64(row + 8);
        g_entries[e].mtime = rd64(row + 16);
        g_entries[e].size  = rd64(row + 24);
        g_entries[e].csize = rd32(row + 32);
        g_entries[e].doff  = rd32(row + 36);
    }
    g_nentry = (int)n;
}

static void parse_names(chunk_t *ifnm)
{
    chunk_t *dg = child_chunk(ifnm, "DGCC");
    buf_t dec;
    if (!dg) return;
    memset(&dec, 0, sizeof(dec));
    if (dgc_decompress(g_img + dg->off + 32, dg->psize, &dec) != 0) {
        printf("note: the name list could not be decoded\n");
        free(dec.p);
        return;
    }
    g_nametab = dec.p;
    g_nametabsize = dec.len;
}

/* ------------------- the recovery record (the DGCR chunk) -------------------
 * The DGCR chunk is appended after the DGCA chunk.  Its INFO chunk holds
 * the recovery parameters and, at +0x2C, the CRC-32 of the whole archive
 * (i.e. of everything in front of the DGCR chunk) - that is what the
 * tool's "dgcac k" command verifies. */
static void check_recovery(chunk_t *dgcr)
{
    chunk_t *info = child_chunk(dgcr, "INFO");
    const u8 *ip;
    u32 off, crc, c;
    if (!info) { printf("recovery record: no INFO chunk\n"); return; }
    if (info->psize < 0x30) { printf("recovery record: the INFO chunk is too small\n"); return; }
    ip = g_img + info->off + 32;
    off = rd32(ip + 0x28);
    crc = rd32(ip + 0x2C);
    if (off > g_imgsize) {
        printf("recovery record: the archive offset %u is outside the file\n", off);
        return;
    }
    c = crc32_buf(g_img, off);
    printf("recovery record: %u bytes, %u columns, %u rows, %u pages, "
           "the archive's checksum %08x %s\n",
           rd32(ip + 4), rd32(ip + 0x10), rd32(ip + 0x14), rd32(ip + 0x18), c,
           c == crc ? "ok" : "MISMATCH - the archive is DAMAGED");
}

/* ------------------- long / unicode paths -------------------
 * The names in the archive are UTF-8 and can be longer than MAX_PATH,
 * so the extraction uses the wide APIs with the "\\?\" prefix. */
static void utf8_to_utf16(const char *s, w16_t *out, int max)
{
    int o = 0;
    unsigned char c, b1, b2, b3;
    while (*s && o < max - 4) {
        c = (unsigned char)*s++;
        if (c < 0x80) {
            out[o++] = (w16_t)c;
        } else if ((c & 0xE0) == 0xC0 && *s) {
            b1 = (unsigned char)*s++; b1 &= 0x3F;
            out[o++] = (w16_t)(((c & 0x1F) << 6) | b1);
        } else if ((c & 0xF0) == 0xE0 && s[0] && s[1]) {
            b1 = (unsigned char)*s++; b1 &= 0x3F;
            b2 = (unsigned char)*s++; b2 &= 0x3F;
            out[o++] = (w16_t)(((c & 0x0F) << 12) | (b1 << 6) | b2);
        } else if ((c & 0xF8) == 0xF0 && s[0] && s[1] && s[2]) {
            b1 = (unsigned char)*s++; b1 &= 0x3F;
            b2 = (unsigned char)*s++; b2 &= 0x3F;
            b3 = (unsigned char)*s++; b3 &= 0x3F;
            out[o++] = (w16_t)(((c & 0x07) << 18) | (b1 << 12) | (b2 << 6) | b3);
        } else {
            out[o++] = (w16_t)c;
        }
    }
    out[o] = 0;
}

/* build the "\\?\" + absolute path of an UTF-8 path */
static void long_path_w(const char *path, w16_t *out, int max)
{
    w16_t tmp[2048], cwd[1024], full[2048];
    utf8_to_utf16(path, tmp, 2048);
    if ((tmp[0] == '\\' && tmp[1] == '\\') || (tmp[0] && tmp[1] == ':')) {
        /* already absolute */
        lstrcpynW(out, L"\\\\?\\", max);
        lstrcatW(out, tmp);
        return;
    }
    if (!GetCurrentDirectoryW(1024, cwd)) cwd[0] = 0;
    lstrcpynW(full, cwd, 2048);
    if (full[0] && full[lstrlenW(full) - 1] != '\\') lstrcatW(full, L"\\");
    lstrcatW(full, tmp);
    lstrcpynW(out, L"\\\\?\\", max);
    lstrcatW(out, full);
}

/* create every directory of a "\\?\..." path */
static void make_dirs_w(const w16_t *wpath)
{
    w16_t tmp[2048];
    int i;
    lstrcpynW(tmp, wpath, 2048);
    for (i = 4; tmp[i]; i++) {
        if (tmp[i] == '\\') {
            tmp[i] = 0;
            CreateDirectoryW(tmp, NULL);
            tmp[i] = '\\';
        }
    }
}

static int write_file_w(const w16_t *wpath, const u8 *data, u32 n)
{
    HANDLE h;
    DWORD w = 0;
    h = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (n) WriteFile(h, data, n, &w, NULL);
    CloseHandle(h);
    return 0;
}

/* ------------------------- main ------------------------- */
static u8 *slurp(const char *path, u32 *size){
    FILE *f = fopen(path, "rb");
    u8 *p;
    long n;
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    p = (u8 *)malloc((size_t)n + 16);
    if (!p) { fprintf(stderr, "oom\n"); exit(2); }
    if (fread(p, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "read error\n"); exit(1); }
    fclose(f);
    *size = (u32)n;
    return p;
}

static void usage(void)
{
    printf("dgcunp - DGC archive unpacker / lister (format of DGCA v1.10)\n"
           "usage: dgcunp [-v] [-l] [-o outdir] <archive.dgc>\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *path = NULL, *outdir = NULL;
    int verbose = 0, listonly = 0, i;
    chunk_t *info, *data, *ifdt, *ifnm, *iarc;
    const u8 *iarcpay;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "-l")) listonly = 1;
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) outdir = argv[++i];
        else if (argv[i][0] == '-') usage();
        else path = argv[i];
    }
    if (!path) usage();

    g_img = slurp(path, &g_imgsize);
    walk(0, g_imgsize, 0, NULL);

    printf("file      : %s (%u bytes)\n", path, g_imgsize);
    printf("chunks    : %d\n", g_nchunk);
    if (verbose) {
        int c;
        for (c = 0; c < g_nchunk; c++) {
            chunk_t *k = &g_chunks[c];
            printf("  %-4s @%#08x depth=%u payload=%u  crc:%s\n",
                   k->id, k->off, k->depth, k->psize,
                   chunk_crc_ok(k, 0) ? "ok" : "BAD");
        }
    } else {
        int c;
        for (c = 0; c < g_nchunk; c++) chunk_crc_ok(&g_chunks[c], verbose);
    }

    iarc = find_chunk("IARC", 2);
    ifdt = find_chunk("IFDT", 2);
    ifnm = find_chunk("IFNM", 2);
    data = find_chunk("DATA", 1);
    info = find_chunk("INFO", 1);
    (void)info;

    if (iarc) {
        iarcpay = g_img + iarc->off + 32;
        printf("\nIARC: version='%.4s' flags=%#x entries=%u total=%u idxtbl=%u namelen=%u\n",
               (const char *)iarcpay + 4, rd32(iarcpay),
               (unsigned)(u32)rd64(iarcpay + 0x28), (unsigned)(u32)rd64(iarcpay + 0x30),
               (unsigned)(u32)rd64(iarcpay + 0x38), rd32(iarcpay + 0x40));
        if (rd32(iarcpay) & 1) {
            printf("\n*** this archive is ENCRYPTED (-p / -k) - the decryption is not\n"
                   "    implemented yet, so nothing can be extracted.\n");
            return 1;
        }
    } else {
        printf("\nno IARC chunk - not a DGC archive?\n");
        return 1;
    }
    if (g_broken)
        printf("\n*** the chunk tree is broken (an encrypted archive?)\n");

    {
        chunk_t *dgcr = find_chunk("DGCR", 0);
        if (dgcr) {
            printf("\n");
            check_recovery(dgcr);
        }
    }

    if (ifdt) parse_index(ifdt);
    if (ifnm) parse_names(ifnm);

    {
        u32 o = 0, k;
        for (k = 0; k < (u32)g_nentry && g_nametab && o + 4 <= g_nametabsize; k++) {
            u32 nl = rd32(g_nametab + o);
            o += 4;
            if (o + nl > g_nametabsize) break;
            g_entries[k].nameoff = g_namepoolsize;
            g_entries[k].namelen = nl;
            if (g_namepoolsize + nl + 1 > g_namepoolcap) {
                u32 nc = g_namepoolcap ? g_namepoolcap * 2 : 65536;
                u8 *np;
                while (nc < g_namepoolsize + nl + 1) nc *= 2;
                np = (u8 *)realloc(g_namepool, nc);
                if (!np) break;
                g_namepool = np;
                g_namepoolcap = nc;
            }
            memcpy(g_namepool + g_namepoolsize, g_nametab + o, nl);
            g_namepool[g_namepoolsize + nl] = 0;
            g_namepoolsize += nl + 1;
            o += nl;
        }
    }

    printf("\n%-40s %10s %10s %s\n", "name", "original", "stored", "crc");
    {
        int k;
        for (k = 0; k < g_nentry; k++)
            printf("%-40s %10u %10u %08x\n",
                   (const char *)g_namepool + g_entries[k].nameoff,
                   (unsigned)(u32)g_entries[k].size,
                   g_entries[k].csize, g_entries[k].crc);
    }

    if (listonly || !outdir) {
        if (data) {
            u32 p = data->off + 32, end = data->off + 32 + data->psize;
            printf("\nDATA chunk: %u bytes\n", data->psize);
            while (p + 32 <= end) {
                const u8 *h = g_img + p;
                u32 ps = rd32(h + 8);
                dblock_t blk[64];
                int nb = dgc_blocks(g_img + p + 32, ps, blk, 64);
                int k;
                u32 rawtag = (ps >= 8) ? rd32(g_img + p + 32) : 0;
                u32 rawsize = (ps >= 8) ? rd32(g_img + p + 36) : 0;
                if (rawtag == 2)
                    printf("  DGCC @%#08x payload=%u : tag 2 (the column method), "
                           "stride=%u, %d column(s)\n", p, ps, rawsize, nb);
                else
                    printf("  DGCC @%#08x payload=%u : %d block(s)\n", p, ps, nb);
                for (k = 0; k < nb; k++) {
                    printf("     block %d: tag=%u size=%u", k, blk[k].tag, blk[k].size);
                    if (blk[k].tag == 1)
                        printf(" flags=%#x params=%#010x v22=%u v7=%u lenA=%u lenB=%u",
                               blk[k].flags, blk[k].params, blk[k].v22, blk[k].v7,
                               blk[k].lenA, blk[k].lenB);
                    printf("\n");
                }
                p = align16(p + 32 + ps);
            }
        }
        return 0;
    }

    /* ------------------------- extract ------------------------- */
    if (!data) { printf("no DATA chunk\n"); return 1; }
    {
        buf_t raw;
        u32 p = data->off + 32, end = data->off + 32 + data->psize;
        u32 done = 0;
        int e;
        memset(&raw, 0, sizeof(raw));
        while (p + 32 <= end) {
            const u8 *h = g_img + p;
            u32 ps = rd32(h + 8);
            if (dgc_decompress(g_img + p + 32, ps, &raw) != 0) {
                printf("  ! the data area could not be decoded completely\n");
                break;
            }
            p = align16(p + 32 + ps);
        }
        printf("\nextracting %d entries to %s (data area %u bytes, crc %08x)\n",
               g_nentry, outdir, (unsigned)raw.len,
               raw.len ? crc32_buf(raw.p, raw.len) : 0);
        for (e = 0; e < g_nentry; e++) {
            char pathbuf[2048];
            w16_t wpath[2048];
            u32 n = (u32)g_entries[e].size;
            const char *nm = (const char *)g_namepool + g_entries[e].nameoff;
            if (g_entries[e].attr & 0x10) {            /* directory */
                sprintf(pathbuf, "%s\\%s", outdir, nm);
                long_path_w(pathbuf, wpath, 2048);
                make_dirs_w(wpath);
                continue;
            }
            if (done + n > raw.len) {
                printf("  ! %s: beyond the data area\n", nm);
                continue;
            }
            sprintf(pathbuf, "%s\\%s", outdir, nm);
            long_path_w(pathbuf, wpath, 2048);
            make_dirs_w(wpath);
            if (write_file_w(wpath, raw.p + done, n) != 0) {
                printf("  ! cannot create %s (%s)\n", pathbuf, strerror(errno));
                continue;
            }
            done += n;
            {
                u32 c = crc32_buf(raw.p + done - n, n);
                printf("  %-40s %8u  crc %08x %s\n", nm, (unsigned)n, c,
                       c == g_entries[e].crc ? "ok" : "MISMATCH");
            }
        }
    }
    return 0;
}
