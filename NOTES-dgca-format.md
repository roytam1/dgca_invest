DGC archive format (DGCA v1.10) - reverse engineering notes
==============================================================
Tool: dgcac.exe  (DGCA / DGC Archiver v1.10, SYN (Shin-ichi TSURUTA) 2000-2005)
Sources: dgcac.exe.c (Hex-Rays), dgcac.exe.lst (IDA), plus ~100 archives produced
         by running the tool itself (ground truth).

1. CONTAINER - a tree of chunks
------------------------------
  struct Chunk {                     32 bytes, little endian
      char   id[4];                  "DGCA" "DATA" "INFO" "IARC"
                                     "IFDT" "IFNM" "DGCC" "DGCR"
      u32    hdr_size;               always 0x20
      u32    payload_size;           bytes after this header
      u32    zero_0c;
      u32    flags;                  1 on DGCA / INFO / DGCR
      u32    align;                  always 0x10
      u32    crc_payload;            CRC-32 (zlib) of the payload
      u32    crc_header;             CRC-32 of the 32 header bytes with
                                     this field zeroed
  };
  A container's payload = concatenation of child records; every child record
  (32 byte header + payload) is zero padded to the next 16 byte boundary and
  the padding is counted in the parent's payload_size.
  Root "DGCA": payload_size = total file size - 32.

  tree:
    DGCA
    +- DATA                     file payload container
    |   +- DGCC  x1 (solid)  |  xN (-f / store)
    +- INFO                    metadata container
        +- IARC                80 byte fixed archive index
        +- IFDT -> DGCC        per entry index table (64 B/entry, TRANSPOSED)
        +- IFNM -> DGCC        name list

2. DGCC payload = stream of blocks
----------------------------------
  u32 tag, u32 size
  tag 0 : STORE      -> `size` raw bytes
  tag 1 : COMPRESSED -> 32 byte block header, stream A, stream B
  tag 2 : CHAIN      -> `size` compressed blocks follow

  tag 1 block header (32 bytes).  NOTE: the fields below are offsets inside
  the DGCC *payload* (the payload starts with the tag and the size):
    +0x00 u32 tag (1)
    +0x04 u32 original (uncompressed) size of the whole block
    +0x08 u32 flags (7 in every archive seen so far; meaning unknown)
    +0x0C u32 params : the shifts of the entropy coder, see below
    +0x10 u32 v22   (LZ stat / chain start index)
    +0x14 u32 v7    (size of the data fed to the entropy coder = the size of
                    the pre-transform's output, i.e. the literal bytes)
    +0x18 u32 lenA  (length of stream A)
    +0x1C u32 lenB  (length of stream B)
  VERIFIED against the decoder (sub_425A50): the decoder reads the block
  structure as {+0 tag, +4 ?, +8 ?, +0xC params, +0x10 v22, +0x14 size,
  +0x18 ?, +0x1C ?} relative to the payload start, uses +0x0C as the shift
  word, +0x10 as the chain start candidate, +0x14 as the size of the entropy
  output (= v7) and +0x18/+0x1C as the two stream lengths.

  params (from the class setup in sub_425A50, "this" = the coder object):
    bit 1        -> this[0x14]  = the pre-transform's min match exponent
                               (minmatch = 1 << this[0x14])
    bits 4-7     -> this[0x18]  = literal model shift   (p_lit)
    bits 8-11    -> this[0x1C]  = pair table shift      (p_pairb)
    bits 12-15   -> this[0x20]  = pair model shift     (p_pair)
    bits 16-19   -> this[0x24]  = context prob shift   (p_ctx)
    bits 20-23   -> this[0x28]  = run length shift     (p_run)
    bits 24-27   -> this[0x34]  = (unused by the CM coder)
    bits 28-31   -> this[0x38]  = (unused by the CM coder)
  The "first byte was 0" flag is NOT in the params: it is the object field
  this[0x2C], set to 0 or 0xFF before the block is coded.

  The pre-transform's model stream (stream B) is a sequence of
  (literal run length, match length - minmatch) pairs; their sum is the
  original block size.  Verified:
     4096 x 'A'      -> (3, 4029)      3 + 64 + 4029 = 4096
     390 byte text   -> (77, 249)      77 + 64 + 249 = 390
     128 byte index  -> (128, escape)  128 + 0 = 128

3. IARC (80 bytes)
-----------------
  +0x00 u32 flags      bit0 = encrypted, bit1 = identity(-i)
  +0x04 char[4] version, always " 001"
  +0x10 u64 FILETIME  archive creation time (0 with -i)
  +0x28 u64 number of entries (files AND directories)
  +0x30 u64 total uncompressed size
  +0x38 u64 index table size (64 * entries)
  +0x40 u32 name blob length
  +0x48 48 bytes archive name area

4. IFDT - the index table (64 bytes per entry, stored TRANSPOSED)
-----------------------------------------------------------------
  The stored blob is column major: blob[c*n + e] = entry[e][c]
  (writer: dgcac.exe.c:20936-20946, reader: 16557).
  entry layout:
    +0x00 u32 CRC-32 of the file contents (0 for directories)
    +0x04 u32 Windows file attributes (0x10 DIRECTORY, 0x20 ARCHIVE)
    +0x08 u64 FILETIME creation
    +0x10 u64 FILETIME last write
    +0x18 u64 original size
    +0x20 u64 "compressed" size  (the value dgcac l prints)
    +0x28 u64 offset of the file's record inside the DATA payload
    +0x2C u32 0
    +0x30..0x3F directory extra timestamps

5. IFNM - the name list
-----------------------
  u32 byte_length + name[length] repeated.  UTF-8, no terminator,
  paths use backslashes, the archived root directory is the first entry.

6. COMPRESSION PIPELINE
-----------------------
  ENCODER (sub_425600, the "compress one block" function) - the order is
  fixed by the disassembly:
      if (this[0x30])            "column" method: the pre-transform
          vtable+0x38(...)       (vtable+0x38) runs FIRST
      if (this[0x0C])            "delta/reorder" flag (options bit 1)
          sub_428270(dst=Block, src=<the block data>, len=size, &stat)
      sub_4244E0(this, Block, size)      the pre-transform
      vtable+0x30(this, stream, Block, size)   the entropy coder
  So in the normal path the order is
      [LZ stage] -> [pre-transform] -> [entropy coder]  => stream A
      the pre-transform's model                        => stream B
  and the LZ stage works on the ORIGINAL block data, its result is what the
  pre-transform compresses.

  DECODER (sub_425A50):
      vtable+0x34 (the entropy decode)  -> v7 bytes in a buffer
      if (this[0x0C]) sub_428990(dest, src=the entropy output, len, start)
      vtable+0x3C (the inverse pre-transform) -> the original data
  i.e.  stream A -> entropy -> chain walk -> pre-transform inverse.

  OPEN: the chain walk is size preserving (v7 -> v7) and its result is the
  input of the inverse pre-transform, i.e. the literal bytes, but the LZ
  stage was applied to the *original* data (size = the block's +0x04).  The
  two sizes only agree if the LZ stage is actually applied to the literals
  (i.e. the real order is pre-transform -> LZ stage).  This is the main
  remaining inconsistency of the pipeline and it has to be settled before
  the chain walk can be used.

  block size field = the ORIGINAL size; v7 = the size fed to the entropy coder.

  6a. GFL range coder  (sub_426F80 / sub_427110)
      state: low/code, range, pending byte, pending 0xFF count.
      encoder: low=0, range=0x80000000; emits low>>23, keeps 23 bits,
               carry handled by a pending 0xFF counter; flush = 5 bytes.
      decoder: SKIP ONE BYTE (the encoder's dummy byte), then
               code = b>>1, range = 0x80; renormalise:
                 code = ((code<<1)|(prev&1))<<7 | (b>>1); range <<= 8
      VERIFIED byte exact (encoder reproduces real stream B bytes).

  6b. Symbol coding (sub_427880 / sub_4271B0)
      gamma style: the value's bit length = the number of "small branch"
      decisions, followed by (len-1) raw bits (MSB first).  Model = 32
      entries of 12 bit probabilities, all initialised to 2048.
      NOTE: the encoder writes (len-1) raw bits, not len - an off by one
      here desynchronises everything after the first symbol.

  6c. Context mixing literal coder (sub_427970 encoder / sub_427260 decoder)
      tables (allocated in the caller sub_423C90 / sub_423950):
        lit[256]      order-1 model,  initialised to 2048
        ctx[32]       the mixing weights, initialised to 2048
        run[256*32]   the run length model, initialised to 2048
        pair[256*256] the order-2 model, initialised to 2048
      The literal is coded MSB first over a 9 bit tree:
         node   = 2*node + bit        (node starts at 1 = the root)
         value  = 2*value + bit       (value starts at 0 -> the byte)
      The encoder walks the tree with the *prefix* index
      node = (cur|0x100) >> (9-k), bit = ((cur|0x100) >> (8-k)) & 1, so the
      node and the value carry the same bit weights (first bit = most
      significant).  A "prepare" pass pre-computes the order-1 model updates
      for the 8 context nodes of a chain, and a "restore" pass writes them
      back and applies the probability shift.

      The prepare pass (verified in the disassembly):
        chain = arg|0x100 ; 8 levels:
            node  = chain>>1 ; saved[k] = lit[node]
            bit   = chain&1
            lit[node] = bit ? lit[node] + ((4096-lit[node])*scale >> 13)
                            : lit[node] - ( lit[node]        *scale >> 13)
            scale = node            (the scale of level k is the NODE of
                                     level k-1, not the running product)
            chain = node
        the first scale is 0x2000 (`mov ecx, 2000h`).
      The restore pass uses the SAME chain and does
        lit[node] = saved +/- (saved >> p_lit)
        pair[cur*256 + node] +/- (pair >> p_pairb)
      The main loop mixes the two models:
        pr = (w*lit[node] + (4096-w)*pair[prev*256+node]) >> 12
      with w = ctx[BSR(state)] (31 when the state is 0).

      The pair model index is prev*256+node and the run model index is
      cur*32+value (the caller passes byte*1024 bytes = byte*256 dwords
      for the pair table and byte*128 bytes = byte*32 dwords for the run
      table).  The run model's shift is this[0x28] = p_run.

      OPEN - the "chain" of the prepare/restore passes:
        the ENCODER calls sub_427970 with arg_20 = the current byte and
        arg_24 = the previous byte; the prepare/restore chain is arg_24
        (= previous byte|0x100) and the pair base is also previous*256.
        The DECODER calls sub_427260 with arg_24 = the previous byte (the
        pair base) and arg_20 = the object field this[0x24] (the chain),
        and that field is read ONCE per block - so the decoder's chain is
        constant while the encoder's varies with the previous byte.
        The two cannot both be right, and empirically neither the
        "previous byte" chain nor the "constant" chain reproduces every
        archive (see below), so one of the two readings is still wrong.

      VERIFIED: the range coder, this coder and the gamma symbol coder
      together reproduce real stream A bytes exactly for several archives
      (see the variant table below), e.g. the 4096 x 'A' sample ->
      004120000000.

  6d. Pre-transform (sub_424C30 / sub_424910)
      an LZ77 with an IMPLICIT distance: a 2 byte hash table maps
      (prev byte, byte) -> the last output position; the distance is
      never transmitted, the decoder rebuilds the same table.
      min match = 1 << this[14].  The model stream (stream B) carries
      (literal run length, match length - minlen) pairs.

  6e. LZ stage (sub_428270 / sub_428990)   *** NOT FULLY REVERSED ***
      The decoder side (sub_428990) is fully known:
        1. the histogram of the source bytes (256 counters)
        2. the prefix sums over the 256 counters (the start offset of each
           value group)
        3. Block[cnt[src[i]]++] = i   (the positions grouped by byte value,
           ascending inside a group)
        4. dest[k] = src[Block^k(start)]      (a chain walk)
        The start index is read as *(u32*)arg_C, i.e. arg_C is a POINTER to
        a structure whose first dword is the start index.  In the "column"
        path the caller passes the block header's +0x10 (v22) area; in the
        normal path it passes the destination buffer pointer itself, which
        looks like a bug or at least an anomaly that has to be explained.
      The walk preserves the byte multiset, so the LZ stage must be a pure
      permutation of its input.

      What is known about the encoder side (sub_428270): it is applied to
      the original block data, it is size preserving, it groups equal byte
      values together (the decoded LZ output of the 390 byte "hello world"
      sample is 21 49 8f*29 ff ef*3 99 23*2 0a*4 09 02 30*2 ca 37*29 - the
      values are clustered) and it changes the multiset, so besides the
      reordering it also transforms the values (delta/order transform; the
      encoder contains a chi-square analysis that picks the delta order and
      the "column" variant is method A).
      The open items: which buffer the chain consumes (the literals or the
      original data - see the pipeline note in section 6), the exact start
      index, and where the delta is inverted.
      This is what still blocks reading the index of a compressed archive.

  6f. Solid mode uses the "column" method (flags bit 2 set, delta order in
      bits 16..31) which is a different transform - not implemented.

  6g. EMPIRICAL ORACLE for the entropy coder
      The best test for the CM coder is: decode stream A, then RE-ENCODE the
      decoded bytes and compare with the original stream A.  A byte exact
      match proves that the whole model evolution (range coder, CM coder,
      symbol coder) is identical to the tool's.
      Scripts (scratch dir, "opencode\dgca"):
        pdec.py     the parameterised CM decoder (all the model variants)
        bf5.py      the matching CM encoder (the oracle)
        joint2.py   the joint search over the variants, scored on 11 blocks
        chain4.py   the chain variant matrix
      The best blocks to use as oracles (the longest stream A in the sample
      archives): t1000.bin.dgc/DATA (269 bytes), m_700.dgc/DATA (269),
      m_300_300.dgc/DATA (250), m_100_200_300.dgc/DATA (245),
      m_100_200_300.dgc/IFDT (76), m_300_300.dgc/IFDT (65),
      orc/idn.dgc/IFDT (35), c_hello.dgc/DATA (27), c_hello.dgc/IFDT (30).
      Result of the search (2026-10-21): no variant of {prepare chain,
      restore chain, scale, run context} reproduces ALL of them; the best
      ones get 3 of 11 blocks byte exact.  The index (IFDT) blocks behave
      much better than the DATA blocks, which points at the run length
      symbol or at the LZ stage rather than at the CM literal coder.
      The symbol coder itself is now verified line by line against
      sub_427880 (encoder) and sub_4271B0 (decoder) and matches the
      implementation in bf5.py / pdec.py exactly.

7. -r RECOVERY DATA
-------------------
  A "DGCR" chunk is appended after the DGCA chunk (extension .dgcr).
  DGCR payload = an INFO chunk (48 byte payload) + a DATA chunk with the
  parity data.
  INFO payload: +0x00 = 0x43, +0x04 = recovery length, +0x10 = 256 cols,
  +0x14 = rows, +0x18 = pages, +0x28 = file offset of the DGCR chunk,
  +0x2C = checksum.
  recovery bytes = 4 * rows * (256 + pages + 1)
  rows  = max(4, ceil(archivesize / ((256>>(level-1)) * 1024)))
  pages = ceil(archivesize / (rows*1024)); if pages == 1 rows = ceil(size/1024)
  VERIFIED for levels 1,5,9 on 100 byte .. 1 MB payloads.

8. ENCRYPTION (-p password / -k keyfile)
----------------------------------------
  Cipher (sub_421C30 encrypt / sub_421C80 decrypt), a self inverse XOR
  stream with one feedback byte:
     encrypt:  in=buf[i]; k1=prng(); k2=prng();
               buf[i] = in^k1^k2 ;  fb = in^k1
     decrypt:  in=buf[i]; k1=prng(); k2=prng();
               buf[i] = in^k1^k2 ;  fb = in^k2
  The feedback byte lives at this+0x1540, the 64 byte key buffer at
  this+0x1480, a 128 byte rolling state at this+0x14C0, the MT19937 pool at
  this+16 and the index/counter at this+8/this+12.

  Key derivation (sub_421CF0):
     h = SHA-512()
     h.update(chunk_header, 32)          <- the 32 byte chunk header
     h.update(password, strlen)
     state = h.digest()                  (64 bytes = 16 dwords)
     history = ""
     for i in 0..38:                     (39 rounds)
         history += state
         h.update(state, 64)
         h.update(state, 64)
         state = h.digest()
     MT19937.init_by_array([0xFFFFFFFF] + history_words, 624)
  The keystream (sub_421B70) re-derives the 64 byte key buffer (the SHA-512
  state formatted as 64 hex characters) from the MT pool, and consumes two
  PRNG words per data byte.

  Scope (measured by diffing an encrypted and a plain archive of the same
  input): the whole DGCC chunk (32 byte header + payload) is encrypted as one
  unit; every other chunk has only header bytes 0x18..0x1F encrypted; inside
  the IARC payload bytes 0x20..0x4F are encrypted and flags bit0 is set.

  A test pair for this: `dgcac a plain.dgc src` vs
  `dgcac a -p secret enc.dgc src` - the two files differ only at the chunk
  header CRC fields and in the DGCC chunk.

9. TOOL
-------
  dgcunp.c   MSVC6, C89.  -l list, -v verbose, -o outdir extract.
  works: container parse, CRC verify, IARC, index (stored form), names,
         stored data extraction (CRC verified), compressed data extraction
         for each-file mode (CRC verified).
  open: the compressed index (LZ inverse) and the solid "column" method.
