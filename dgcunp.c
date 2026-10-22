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
 *  Usage:  dgcunp [-l] [-v] [-R] [-p<password> | -k<keyfile>] [-o outdir] <archive>
 *
 *  A spanning file (.dgd / .dgdr) is accepted too: its parts are put
 *  together and the file is written out (see the section "The spanning
 *  files" further down).
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
 * tool's "dgcac k" command verifies.  (the functions that decode and
 * repair it are further down, next to the crypto) */

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
typedef unsigned __int64 u64x;

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

/* ------------------------------------------------------------------ *
 *  The encryption of the ARCHIVE ITSELF (-p / -k)
 *
 *  The writer encrypts every DGCC record (the 32 byte chunk header AND
 *  its payload) and the 48 bytes of the IARC payload at +0x20.  Two
 *  different keys are used:
 *
 *    key1 = SHA-512( 8 zero bytes | password )  stretched over 39 rounds
 *           -> the 32 byte chunk header and the IARC's +0x20 area
 *    key2 = SHA-512( the PLAINTEXT header | password )  stretched
 *           -> the chunk's payload
 *
 *  The password is the text given with -p.  With -k it is the hex text
 *  of the SHA-512 of the key file (the standard digest, 128 characters).
 * ------------------------------------------------------------------ */

/* the password of an archive, as the writer sees it */
static u8  g_pw[256];
static u32 g_pwlen;
static int g_encrypted;

static void crypt_setkey_pw1(crypt_t *c, const u8 *pw, u32 pwlen)
{
    static const u8 zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    crypt_setkey(c, zero, 8, pw, pwlen);
}

static void crypt_setkey_pw2(crypt_t *c, const u8 *hdr, u32 hlen,
                             const u8 *pw, u32 pwlen)
{
    crypt_setkey(c, hdr, hlen, pw, pwlen);
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

/* the chunk CRC fields: the CRC of the payload and the CRC of the
 * 32 byte header with the header CRC field set to zero.  The header CRC
 * is computed AFTER the payload CRC has been written (the header CRC
 * covers the payload CRC field). */
static void chunk_fix_crc(chunk_t *c)
{
    u8 *h = g_img + c->off;
    u8 tmp[32];
    u32 v;
    v = crc32_buf(g_img + c->off + 32, c->psize);
    memcpy(h + 24, &v, 4);
    memcpy(tmp, h, 32);
    memset(tmp + 28, 0, 4);
    v = crc32_buf(tmp, 32);
    memcpy(h + 28, &v, 4);
}

/* ------------------------------------------------------------------ *
 *  The decryption of an encrypted archive
 *
 *  The encrypted regions are:
 *    - every DGCC record: the 32 byte header and its payload;
 *    - the 48 bytes of the IARC payload at +0x20.
 *  The chunk headers of the outer levels (DGCA / DATA / INFO / IARC /
 *  IFDT / IFNM) are NOT encrypted, so the tree can be walked; only the
 *  DGCC records have to be decrypted one by one.
 *
 *  The CRCs of the chunks are computed over the CIPHERTEXT, so they
 *  have to be recomputed after the decryption.
 * ------------------------------------------------------------------ */

/* decrypt the DGCC records of one container (DATA / IFDT / IFNM) */
static void decrypt_dgcc_records(u32 off, u32 end)
{
    u32 p = off;
    crypt_t c1, c2;
    while (p + 32 <= end) {
        u8 hdr[32];
        u32 ps;
        crypt_setkey_pw1(&c1, g_pw, g_pwlen);
        crypt_decrypt(&c1, g_img + p, 32);
        memcpy(hdr, g_img + p, 32);
        if (memcmp(hdr, "DGCC", 4)) {
            /* not a DGCC record: restore the header and stop */
            crypt_setkey_pw1(&c1, g_pw, g_pwlen);
            crypt_encrypt(&c1, g_img + p, 32);
            return;
        }
        ps = rd32(hdr + 8);
        if (p + 32 + ps > end) return;
        crypt_setkey_pw2(&c2, hdr, 32, g_pw, g_pwlen);
        crypt_decrypt(&c2, g_img + p + 32, ps);
        p = align16(p + 32 + ps);
    }
}

/* decrypt the whole archive in place.  Returns 0 if the password is
 * obviously wrong (the decrypted IARC does not look sane). */
static int decrypt_archive(void)
{
    crypt_t c;
    int i;
    /* the DGCC records of the containers */
    for (i = 0; i < g_nchunk; i++) {
        chunk_t *k = &g_chunks[i];
        if (!strcmp(k->id, "DATA") || !strcmp(k->id, "IFDT") || !strcmp(k->id, "IFNM"))
            decrypt_dgcc_records(k->off + 32, k->off + 32 + k->psize);
    }
    /* the IARC payload's +0x20 area (48 bytes) */
    for (i = 0; i < g_nchunk; i++) {
        chunk_t *k = &g_chunks[i];
        if (!strcmp(k->id, "IARC") && k->psize >= 0x50) {
            crypt_setkey_pw1(&c, g_pw, g_pwlen);
            crypt_decrypt(&c, g_img + k->off + 32 + 0x20, 48);
            /* the number of entries and the name blob length must be
             * plausible - a wrong password gives garbage */
            if (rd64(g_img + k->off + 32 + 0x28) > 0x1000000UI64 ||
                rd32(g_img + k->off + 32 + 0x40) > 0x1000000u)
                return 0;
            break;
        }
    }
    return 1;
}

/* the password of a -k key file: the hex text of the SHA-512 of its
 * content.  The binary formats the state word by word: the HIGH dword
 * first, then the low one - that is the standard SHA-512 digest. */
static int password_from_keyfile(const char *path, u8 *out, u32 outmax)
{
    u8 *buf;
    u32 n, i, g, j;
    sha512_t h;
    u8 st[64];
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open the key file %s\n", path); return 0; }
    fseek(f, 0, SEEK_END); n = (u32)ftell(f); fseek(f, 0, SEEK_SET);
    buf = (u8 *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); fprintf(stderr, "oom\n"); return 0; }
    if (fread(buf, 1, n, f) != n) { fclose(f); free(buf); fprintf(stderr, "read error\n"); return 0; }
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

/* ------------------------------------------------------------------ *
 *  The recovery record (the DGCR chunk)
 *
 *  The DGCR chunk holds an INFO chunk (the parameters) and a DATA chunk
 *  with the recovery data.  The data is a 2 dimensional parity code over
 *  the archive's 4 byte words:
 *      the archive = rows x 256 columns x pages words
 *      part 1: the parity of the pages for every (row, column)
 *      part 2: the parity of the columns for every (page, row)
 *      part 3: the offsets of the row blocks (a copy of the data)
 *  It is encrypted with the fixed key of the SecureCryptograph class.
 * ------------------------------------------------------------------ */
static void dgcr_report(chunk_t *dgcr, int verbose)
{
    chunk_t info;
    const u8 *ip;
    u32 off, crc, c, len, cols, rows, pages;
    info = *child_chunk(dgcr, "INFO");
    if (!info.id[0]) { printf("recovery record: no INFO chunk\n"); return; }
    if (info.psize < 0x30) { printf("recovery record: the INFO chunk is too small\n"); return; }
    ip = g_img + info.off + 32;
    off = rd32(ip + 0x28);
    crc = rd32(ip + 0x2C);
    len = rd32(ip + 4);
    cols = rd32(ip + 0x10);
    rows = rd32(ip + 0x14);
    pages = rd32(ip + 0x18);
    if (off > g_imgsize) {
        printf("recovery record: the archive offset %u is outside the file\n", off);
        return;
    }
    c = crc32_buf(g_img, off);
    printf("recovery record: %u bytes, %u columns, %u rows, %u pages, "
           "the archive's checksum %08x %s\n",
           len, cols, rows, pages, c,
           c == crc ? "ok" : "MISMATCH - the archive is DAMAGED");
    (void)verbose;
}

/* the repair: use the parity table to restore the damaged words.  The
 * archive's checksum (in the INFO chunk) is the final check.
 * off = the offset of the end of the covered area, crc = its checksum
 * (0 if the record has none - the .dgdr of a spanning file). */
static int dgcr_repair(chunk_t *dgcr, u32 off, u32 crc, const char *path,
                       int verbose)
{
    chunk_t info, data;
    const u8 *ip;
    u8 *rec, *par, *rowx;
    u32 len, cols, rows, pages, i, j, k, fixed = 0, bad = 0, alen;
    crypt_t c;

    info = *child_chunk(dgcr, "INFO");
    data = *child_chunk(dgcr, "DATA");
    if (!info.id[0] || !data.id[0]) { printf("recovery record: incomplete\n"); return 0; }
    if (info.psize < 0x30) { printf("recovery record: the INFO chunk is too small\n"); return 0; }
    ip = g_img + info.off + 32;
    len = rd32(ip + 4);
    cols = rd32(ip + 0x10);
    rows = rd32(ip + 0x14);
    pages = rd32(ip + 0x18);
    alen = off;
    if (off > g_imgsize) { printf("the archive offset is outside the file\n"); return 0; }
    if (data.psize < len || len < (rows * cols + pages * rows + rows) * 4) {
        printf("the recovery data is too short\n");
        return 0;
    }
    rec = (u8 *)malloc(len);
    if (!rec) { printf("out of memory\n"); return 0; }
    memcpy(rec, g_img + data.off + 32, len);
    crypt_setkey_fixed(&c);
    crypt_decrypt(&c, rec, len);
    par  = rec;                        /* rows*cols words */
    rowx = rec + rows * cols * 4;      /* pages*rows words */
    /* the word of the archive: (page, row, column).  The matrix is padded
     * with zeros if the archive is shorter than rows*cols*pages words. */
#define ARCHWORD(pg, rw, cl) \
    ((((pg) * rows + (rw)) * cols + (cl)) * 4 + 4 > alen ? 0u : \
     rd32(g_img + (((pg) * rows + (rw)) * cols + (cl)) * 4))

    /* 1. the columns whose parity does not match */
    for (i = 0; i < rows; i++) {
        for (j = 0; j < cols; j++) {
            u32 x = 0;
            for (k = 0; k < pages; k++) x ^= ARCHWORD(k, i, j);
            if (x != rd32(par + (i * cols + j) * 4)) {
                u32 cand = 0, kp = 0;
                int found = 0;
                /* try every page of the column: the damaged word must also
                 * repair the row parity */
                for (k = 0; k < pages; k++) {
                    u32 y = 0, z, w;
                    for (w = 0; w < pages; w++)
                        if (w != k) y ^= ARCHWORD(w, i, j);
                    cand = rd32(par + (i * cols + j) * 4) ^ y;
                    /* does it repair the row parity of (k, i)? */
                    z = 0;
                    for (w = 0; w < cols; w++) {
                        u32 ww = (w == j) ? cand : ARCHWORD(k, i, w);
                        z ^= ww;
                    }
                    if (z == rd32(rowx + (k * rows + i) * 4)) {
                        kp = k;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    /* no page repairs the row parity (more than one word of
                     * the row is damaged): take the most likely candidate */
                    u32 y = 0, w;
                    for (w = 1; w < pages; w++) y ^= ARCHWORD(w, i, j);
                    cand = rd32(par + (i * cols + j) * 4) ^ y;
                    kp = 0;
                    bad++;
                }
                {
                    u32 *p = (u32 *)(g_img + (((kp) * rows + (i)) * cols + (j)) * 4);
                    *p = cand;
                }
                fixed++;
            }
        }
    }
#undef ARCHWORD
    printf("the recovery: %u words restored, %u columns could not be verified\n",
           fixed, bad);
    {
        u32 c2 = crc32_buf(g_img, off);
        if (crc) {
            printf("the archive's checksum %08x %s\n", c2,
                   c2 == crc ? "ok - the archive is repaired" :
                   (bad ? "still damaged" : "MISMATCH"));
            if (c2 == crc) {
                /* write the repaired archive next to the original */
                char out[1024];
                FILE *f;
                sprintf(out, "%s.repaired", path);
                f = fopen(out, "wb");
                if (f) {
                    fwrite(g_img, 1, off, f);
                    fclose(f);
                    printf("the repaired archive was written to %s\n", out);
                }
            }
        } else {
            printf("the recovery data has been applied (%u bytes)\n", off);
        }
    }
    (void)verbose;
    free(rec);
    return (int)fixed;
}

/* the helpers of the long / unicode paths (they are defined further down) */
static void utf8_to_utf16(const char *s, w16_t *out, int max);
static void long_path_w(const char *path, w16_t *out, int max);
static void make_dirs_w(const w16_t *wpath);
static int  write_file_w(const w16_t *wpath, const u8 *data, u32 n);

/* load a file; returns NULL if it cannot be read */
static u8 *slurp2(const char *path, u32 *size){
    FILE *f = fopen(path, "rb");
    u8 *p;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    p = (u8 *)malloc((size_t)n + 16);
    if (!p) { fclose(f); return NULL; }
    if (fread(p, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(p); return NULL;
    }
    fclose(f);
    *size = (u32)n;
    return p;
}

/* ------------------------------------------------------------------ *
 *  The spanning files (.dgd / .dgdr)
 *
 *  A file that is too big for a single archive is split into parts and
 *  every part is a chunk tree of its own.  The parts are named
 *  <base>%04d.dgd (the writer uses the format "%04d").  The recon
 *  function of the binary (sub_414A20) globs the directory for the
 *  *.dgd and *.dgdr files and puts the parts back together.
 *
 *      DGCD  (the root)
 *      |-- INFO  (116 bytes)
 *      |     +0x00 u32  flags          (bit 0 = encrypted)
 *      |     +0x04 u32  the index of this part
 *      |     +0x08 u32  the number of the parts
 *      |     +0x0c u32  0
 *      |     +0x10 u32  the size of this part
 *      |     +0x14 u32  0
 *      |     +0x18 u32  the size of the whole file
 *      |     +0x1c u32  0
 *      |     +0x20 64B  the SHA-512 of the whole file
 *      |     +0x60 u32  the length of the name
 *      |     +0x64      the name (UTF-8)
 *      |-- DFDT  (32 bytes)  the date and the time of the file
 *      `-- DATA  (this part's bytes)
 *
 *  A .dgdr has the same structure but a shorter DATA chunk and a
 *  trailing DGCR chunk with the recovery data of the file (the parity
 *  covers the bytes of the .dgdr in front of the DGCR chunk).
 *
 *  The encryption is the same as the archive's:
 *      key1 = SHA-512( 8 zero bytes | password )
 *             -> the 92 bytes of the INFO material at +4
 *      key2 = SHA-512( the PLAINTEXT 96 byte material | password )
 *             -> the name, the DFDT and the DATA payload
 *  (each of them with its own key stream)
 * ------------------------------------------------------------------ */

#define MAXPART 128
#define DGNAME 512

typedef struct {
    char path[1024];
    u8   mat[96];        /* the INFO material (decrypted) */
    char name[DGNAME];
    u32  namelen;
    u32  part;           /* the index of the part */
    u32  partsize;
    u32  total;
    u32  nparts;
    int  encrypted;
} dgpart_t;

static dgpart_t g_part[MAXPART];
static int      g_npart;

/* find a child chunk of a container (the container's header is at base) */
static int dgcd_child(const u8 *img, u32 base, u32 psize, const char *id,
                      u32 *coff, u32 *cps)
{
    u32 p = base + 32, end = base + 32 + psize;
    while (p + 32 <= end) {
        const u8 *h = img + p;
        u32 ps = rd32(h + 8);
        if (!memcmp(h, id, 4)) { *coff = p; *cps = ps; return 1; }
        p = align16(p + 32 + ps);
    }
    return 0;
}

/* read the INFO chunk of a .dgd: the material (96 bytes, decrypted if
 * the file is encrypted) and the name.  Returns 0 if the file is not a
 * .dgd and -1 if it is encrypted but no password is known. */
static int dgcd_info(const u8 *img, u32 size, dgpart_t *p)
{
    u32 ioff, ips, flags, nl;
    u8 mat[96], *nm;
    crypt_t c;
    if (size < 32 || memcmp(img, "DGCD", 4)) return 0;
    if (!dgcd_child(img, 0, rd32(img + 8), "INFO", &ioff, &ips)) return 0;
    if (ips < 96) return 0;
    memcpy(mat, img + ioff + 32, 96);
    flags = rd32(mat);
    p->encrypted = (flags & 1) ? 1 : 0;
    if (p->encrypted) {
        if (!g_pwlen) return -1;
        crypt_setkey_pw1(&c, g_pw, g_pwlen);
        crypt_decrypt(&c, mat + 4, 92);
    }
    memcpy(p->mat, mat, 96);
    p->part      = rd32(mat + 4);
    p->nparts    = rd32(mat + 8);
    p->partsize  = rd32(mat + 16);
    p->total     = rd32(mat + 24);
    /* the name: the length and the text are encrypted with key2 */
    p->namelen = 0;
    p->name[0] = 0;
    if (ips > 96) {
        nm = (u8 *)malloc(ips - 96);
        if (!nm) return 0;
        memcpy(nm, img + ioff + 32 + 96, ips - 96);
        if (p->encrypted) {
            crypt_setkey_pw2(&c, mat, 96, g_pw, g_pwlen);
            crypt_decrypt(&c, nm, ips - 96);
        }
        nl = rd32(nm);
        if (nl > ips - 100) nl = 0;
        if (nl > DGNAME - 1) nl = DGNAME - 1;
        memcpy(p->name, nm + 4, nl);
        p->name[nl] = 0;
        p->namelen = nl;
        free(nm);
    }
    return 1;
}

/* pick one candidate per part index; the sizes must add up to the size
 * of the whole file */
static int dgcd_choose(dgpart_t *cand, int ncand, int idx, u32 need,
                       dgpart_t *chosen, int nparts)
{
    int i;
    if (idx >= nparts) return need == 0;
    for (i = 0; i < ncand; i++) {
        if (cand[i].part != (u32)idx) continue;
        if (cand[i].partsize > need) continue;
        chosen[idx] = cand[i];
        if (dgcd_choose(cand, ncand, idx + 1, need - cand[i].partsize,
                        chosen, nparts))
            return 1;
    }
    return 0;
}

/* collect the candidate files of the directory */
static void dgcd_scan(const char *dir, const u8 *refhash, u32 nparts)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pat[1024];
    int pass;
    for (pass = 0; pass < 2; pass++) {
        sprintf(pat, "%s\\*.%s", dir, pass ? "dgdr" : "dgd");
        h = FindFirstFileA(pat, &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            u8 *img;
            u32 size;
            dgpart_t p;
            char full[1024];
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            sprintf(full, "%s\\%s", dir, fd.cFileName);
            img = slurp2(full, &size);
            if (!img) continue;
            memset(&p, 0, sizeof(p));
            p.part = 0xFFFFFFFFu;
            if (dgcd_info(img, size, &p) == 1 && p.nparts == nparts &&
                !memcmp(p.mat + 0x20, refhash, 64) && g_npart < MAXPART) {
                strcpy(p.path, full);
                g_part[g_npart++] = p;
            }
            free(img);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
}

/* the main routine of the spanning files */
static int dgcd_main(const char *path, const char *outdir, int verbose,
                     int listonly, int repair)
{
    u8 *img;
    u32 size;
    dgpart_t ref, chosen[MAXPART];
    int i, rc;
    u32 off, nparts, total;
    u8 *buf;
    char dir[1024], outpath[2048];

    img = slurp2(path, &size);
    if (!img) { printf("cannot open %s\n", path); return 1; }
    memset(&ref, 0, sizeof(ref));
    rc = dgcd_info(img, size, &ref);
    if (rc < 0) {
        printf("\n*** this file is ENCRYPTED (-p / -k).\n"
               "    Use -p<password> or -k<keyfile> to decrypt it.\n");
        free(img);
        return 1;
    }
    if (rc == 0) {
        printf("%s is not a spanning file (.dgd)\n", path);
        free(img);
        return 1;
    }
    printf("file      : %s (%u bytes)\n", path, size);
    printf("spanning  : %u parts, %u bytes in total, the name is '%s'\n",
           ref.nparts, ref.total, ref.name);
    printf("this part : %u, %u bytes\n", ref.part, ref.partsize);
    if (verbose) {
        u32 i2;
        printf("the SHA-512 of the whole file: ");
        for (i2 = 0; i2 < 64; i2++) printf("%02x", ref.mat[0x20 + i2]);
        printf("\n");
    }
    if (listonly) { free(img); return 0; }

    nparts = ref.nparts;
    total  = ref.total;
    if (nparts == 0 || nparts > MAXPART) {
        printf("the number of the parts is not plausible\n");
        free(img);
        return 1;
    }

    /* the directory of the file */
    strcpy(dir, path);
    {
        char *b = strrchr(dir, '\\');
        if (b) *b = 0; else strcpy(dir, ".");
    }
    g_npart = 0;
    dgcd_scan(dir, ref.mat + 0x20, nparts);
    /* the file itself is always a candidate */
    if (g_npart < MAXPART) {
        strcpy(g_part[g_npart].path, path);
        g_part[g_npart] = ref;
        strcpy(g_part[g_npart].path, path);
        g_npart++;
    }
    printf("found     : %d part files in %s\n", g_npart, dir);
    if (verbose) {
        for (i = 0; i < g_npart; i++)
            printf("  part %u  %8u bytes  %s\n", g_part[i].part,
                   g_part[i].partsize, g_part[i].path);
    }
    memset(chosen, 0, sizeof(chosen));
    if (!dgcd_choose(g_part, g_npart, 0, total, chosen, (int)nparts)) {
        printf("\n*** the parts of the file are missing or do not fit "
               "together\n");
        free(img);
        return 1;
    }

    /* put the parts together */
    buf = (u8 *)malloc(total ? total : 1);
    if (!buf) { printf("out of memory\n"); free(img); return 1; }
    off = 0;
    for (i = 0; i < (int)nparts; i++) {
        u8 *pimg;
        u32 psize, doff, dps;
        pimg = slurp2(chosen[i].path, &psize);
        if (!pimg) { printf("cannot open %s\n", chosen[i].path); free(buf); free(img); return 1; }
        if (repair) {
            /* a .dgdr carries the recovery data of its own bytes */
            u32 goff = align16(32 + rd32(pimg + 8));
            if (goff + 32 <= psize && !memcmp(pimg + goff, "DGCR", 4)) {
                u8 *simg = g_img;
                u32 ssize = g_imgsize;
                chunk_t dg;
                g_img = pimg; g_imgsize = psize;
                dg.off = goff; dg.psize = rd32(pimg + goff + 8); dg.depth = 0;
                memcpy(dg.id, "DGCR", 5);
                printf("\n*** the recovery data of %s\n", chosen[i].path);
                dgcr_repair(&dg, goff, 0, chosen[i].path, verbose);
                /* write the repaired file next to the original */
                {
                    char out[1024];
                    FILE *f;
                    sprintf(out, "%s.repaired", chosen[i].path);
                    f = fopen(out, "wb");
                    if (f) {
                        fwrite(pimg, 1, goff, f);
                        fclose(f);
                        printf("the repaired file was written to %s\n", out);
                    }
                }
                g_img = simg; g_imgsize = ssize;
            }
        }
        if (!dgcd_child(pimg, 0, rd32(pimg + 8), "DATA", &doff, &dps)) {
            printf("%s has no DATA chunk\n", chosen[i].path);
            free(pimg); free(buf); free(img);
            return 1;
        }
        if (dps > total - off) dps = total - off;
        memcpy(buf + off, pimg + doff + 32, dps);
        if (chosen[i].encrypted) {
            crypt_t c;
            crypt_setkey_pw2(&c, chosen[i].mat, 96, g_pw, g_pwlen);
            crypt_decrypt(&c, buf + off, dps);
        }
        off += dps;
        free(pimg);
    }
    free(img);
    printf("assembled  : %u bytes\n", off);

    /* the SHA-512 of the whole file must match the INFO's */
    {
        sha512_t h;
        u8 st[64];
        int ok;
        sha512_init(&h);
        sha512_update(&h, buf, total);
        sha512_final(&h);
        sha512_state(&h, st);
        ok = !memcmp(st, ref.mat + 0x20, 64);
        printf("the SHA-512: %s\n", ok ? "ok" : "MISMATCH - the file is DAMAGED");
        if (!ok) {
            free(buf);
            return 1;
        }
    }

    /* write the file */
    {
        char pathbuf[2048];
        w16_t wpath[2048];
        if (outdir) sprintf(pathbuf, "%s\\%s", outdir, ref.name);
        else       strcpy(pathbuf, ref.name);
        long_path_w(pathbuf, wpath, 2048);
        make_dirs_w(wpath);
        if (write_file_w(wpath, buf, total) != 0) {
            printf("cannot create %s\n", pathbuf);
            free(buf);
            return 1;
        }
        strcpy(outpath, pathbuf);
    }
    printf("written    : %s (%u bytes)\n", outpath, total);
    free(buf);
    return 0;
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
           "usage: dgcunp [-v] [-l] [-R] [-p<password> | -k<keyfile>] [-o outdir] <archive.dgc>\n"
           "  -R   repair a damaged archive with its recovery data (the DGCR chunk)\n"
           "  -p   the password of an encrypted archive (-p secret)\n"
           "  -k   the key file of an encrypted archive (-k mykey.key)\n"
           "  a spanning file (.dgd / .dgdr) is also accepted: its parts are\n"
           "  put together and the file is written out\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *path = NULL, *outdir = NULL, *keyfile = NULL;
    const char *pwarg = NULL;
    int verbose = 0, listonly = 0, repair = 0, i;
    chunk_t *info, *data, *ifdt, *ifnm, *iarc;
    const u8 *iarcpay;

    if (argc > 1 && !strcmp(argv[1], "-t")) { crypto_selftest(); return 0; }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "-l")) listonly = 1;
        else if (!strcmp(argv[i], "-R")) repair = 1;
        else if (!strncmp(argv[i], "-p", 2) && argv[i][2]) pwarg = argv[i] + 2;
        else if (!strncmp(argv[i], "-k", 2) && argv[i][2]) keyfile = argv[i] + 2;
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) outdir = argv[++i];
        else if (argv[i][0] == '-') usage();
        else path = argv[i];
    }
    if (!path) usage();

    if (pwarg) {
        g_pwlen = (u32)strlen(pwarg);
        if (g_pwlen > sizeof(g_pw)) g_pwlen = sizeof(g_pw);
        memcpy(g_pw, pwarg, g_pwlen);
    } else if (keyfile) {
        g_pwlen = password_from_keyfile(keyfile, g_pw, sizeof(g_pw));
        if (!g_pwlen) return 1;
    }

    g_img = slurp(path, &g_imgsize);
    walk(0, g_imgsize, 0, NULL);

    /* a spanning file (.dgd / .dgdr): the root chunk is "DGCD" */
    if (g_imgsize >= 4 && !memcmp(g_img, "DGCD", 4)) {
        int rc = dgcd_main(path, outdir, verbose, listonly, repair);
        free(g_img);
        return rc;
    }

    /* The recovery data (the DGCR chunk) covers the archive AS IT IS
     * STORED - i.e. the encrypted bytes of an encrypted archive.  So the
     * recovery has to be handled before the decryption. */
    {
        chunk_t *dgcr = find_chunk("DGCR", 0);
        if (dgcr) {
            chunk_t *info = child_chunk(dgcr, "INFO");
            u32 off = 0, crc = 0;
            if (info && info->id[0] && info->psize >= 0x30) {
                off = rd32(g_img + info->off + 32 + 0x28);
                crc = rd32(g_img + info->off + 32 + 0x2C);
            }
            printf("\n");
            dgcr_report(dgcr, verbose);
            if (repair) dgcr_repair(dgcr, off, crc, path, verbose);
        }
    }

    /* is the archive encrypted?  The IARC's flags have bit 0 set. */
    {
        chunk_t *k = find_chunk("IARC", 2);
        if (k && k->psize >= 4 && (rd32(g_img + k->off + 32) & 1)) {
            g_encrypted = 1;
            if (!g_pwlen) {
                printf("\n*** this archive is ENCRYPTED (-p / -k).\n"
                       "    Use -p<password> or -k<keyfile> to decrypt it.\n");
                return 1;
            }
            printf("\n*** the archive is encrypted - decrypting it\n");
            if (!decrypt_archive()) {
                printf("*** the password is wrong (the decrypted index is garbage)\n");
                return 1;
            }
            /* the tree has to be walked again: the DGCC headers were
             * encrypted and are readable now */
            g_nchunk = 0;
            g_broken = 0;
            walk(0, g_imgsize, 0, NULL);
            /* the CRCs were computed over the ciphertext: recompute them
             * (now that the whole tree is known).  The deepest chunks
             * first: a container's CRC covers its children's bytes. */
            {
                int k, d;
                for (d = 4; d >= 0; d--)
                    for (k = 0; k < g_nchunk; k++)
                        if ((int)g_chunks[k].depth == d) chunk_fix_crc(&g_chunks[k]);
            }
            g_encrypted = 0;
        }
    }

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
        if (g_encrypted) {
            printf("\n*** this archive is ENCRYPTED (-p / -k).\n"
                   "    The crypto of DGCA v1.10 is known (see NOTES-dgca-format.md),\n"
                   "    but the key material that the writer derives is not stored in the\n"
                   "    archive, so the data cannot be decrypted yet.\n");
            return 1;
        }
    } else {
        printf("\nno IARC chunk - not a DGC archive?\n");
        return 1;
    }
    if (g_broken)
        printf("\n*** the chunk tree is broken (an encrypted archive?)\n");

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
