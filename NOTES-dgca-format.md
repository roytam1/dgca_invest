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
      decoder: SKIP ONE BYTE (the encoder's dummy byte - sub_4270A0
               does `inc edx; mov [eax+10h], edx` before it reads the
               code), then code = b>>1, range = 0x80; renormalise:
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

      The prepare pass (verified in the disassembly of sub_427970):
        chain = arg|0x100 ; 8 levels:
            node  = chain>>1 ; saved[k] = lit[node]
            bit   = chain&1
            lit[node] = bit ? lit[node] + ((4096-lit[node])*scale >> 13)
                            : lit[node] - ( lit[node]        *scale >> 13)
            scale = node            (the scale of level k is the NODE of
                                     level k-1, not the running product)
            chain = node
        the first scale is 0x2000 (`mov ecx, 2000h`).
        With chain = prev|0x100 and prev = 0 the scale chain is
        0x2000, 0x80, 0x40, 0x20, 0x10, 8, 4, 2 - a geometric hierarchy, and
        the tentative update of a level is of the same order as the shift
        the restore pass applies to the same node (that is the point of the
        prepare pass: the model is adapted to the symbol before it is
        coded, without changing the final state).
      The restore pass uses the SAME chain and does
        lit[node] = saved +/- (saved >> p_lit)
        pair[cur*256 + node] +/- (pair >> p_pairb)
      The main loop mixes the two models:
        pr = (w*lit[node] + (4096-w)*pair[prev*256+node]) >> 12
      with w = ctx[BSR(state)] (31 when the state is 0), and updates
        lit[node]   toward the coded bit (>> p_lit)
        pair[prev*256+node] toward the coded bit (>> p_pair)
      The pair model index is prev*256+node and the run model index is
      cur*32+value (the caller passes byte*1024 bytes = byte*256 dwords
      for the pair table and byte*128 bytes = byte*32 dwords for the run
      table).  The run model's shift is this[0x28] = p_run.

      OPEN - which byte the chain of the prepare/restore passes walks.
      The encoder passes the previous byte (arg_24 = var_484C6) and the
      decoder passes the object field this[0x24] (arg_20) which the
      disassembly says is p_ctx - a constant per block.
      A 6 byte test case pins it down: a 1000 byte file "A"*500 + "B"*500
      is stored as a 6 byte token stream, and the pre-transform's model
      stream (reproduced byte for byte) says that the token stream must be
      a permutation of the literals "AAAAAA".  The decoder produces
      0x42,0x52,0x52,0x0c,0xc0,0xc0: the first 6 bits of the first
      literal are right (010000 = the prefix of 0x41) and the 7th bit -
      the node 80 = (0x141)>>2, i.e. the current byte's chain - is the
      first wrong one.  The probability of that bit can only differ from
      2048 if lit[80] was touched by the prepare pass, and the prepare
      pass can only touch it if the chain is the CURRENT byte
      (0x41|0x100 = 0x141, whose nodes are 160, 80, 40, 20, 10, 5, 2, 1
      - exactly the 8 nodes the main loop reads).  The decoder cannot
      know the current byte before it has read the model, so either the
      main loop must read the *unprepared* model, or the decoder has to
      apply the prepare's effect while it decodes the bits.
      Making the prepare's update 64 times bigger (the scale chain
      "0x2000, node0*64, node1*64, ...") makes the FIRST literal of the
      6 byte case come out right (0x41) but the second one wrong, and
      making it 128 times bigger reproduces the whole 6 byte case exactly
      but breaks the 4 and 5 byte cases - so the scale chain is close to
      right but not exactly, and there is at least one more bug (most
      likely in the restore pass, which is what makes the NEXT symbol's
      model different).  The 6 byte case is the ideal regression test: it
      is in tiny\twoblk.dgc (with tiny\twoblk.bin and tiny\twoblk.n.dgc),
      and tiny\ab1000.dgc / tiny\abc1000.dgc are the 4 and 5 byte
      variants (their token streams must be permutations of "ABAB" and
      "ABCAB").
      More real world samples: the SFX stripped archives in the work area
      root, dgca_beta1.dgc and dgca_v100e.dgc, contain blocks from 117
      bytes up to 839680 bytes (up to 773298 literals and a 410631 byte CM
      stream).  All three tool versions (the repo's dgcac.exe, the beta and
      v100e) produce BYTE IDENTICAL streams for the same input, i.e. they
      share the same CM coder - they are extra test data, not a different
      variant.  The smallest block (117 bytes, a 77 byte CM stream) decodes
      with a re-encode match of 76 of 77 bytes - the best result so far:
      the model error is cumulative, so the bigger blocks diverge earlier
      (the 7411 byte block: 985 of 2899 bytes; the 839680 byte block:
      440 of 410631).
      What the three cases show (the token stream must be a permutation
      of the literals, the LZ stage being a pure permutation):
        twoblk  : the token stream is "AAAAAA" = ONE symbol (the literal
                  'A' with a run of 5) - the mult=128 variant decodes it
                  exactly.
        ab1000  : the token stream is a permutation of "ABAB", e.g.
                  "BBAA" = TWO symbols ('B' with a run of 1 and 'A' with
                  a run of 1).  The decoder produces four symbols with
                  the runs 0,0,0,0 - the first two literals are right
                  ('B','B') but the run symbol comes out as 0 where it
                  must be 1.
      => the run symbol's model is off by the same kind of error as the
      literal model, so the bug is in the shared model update (the
      prepare/restore passes), not in the literal coder alone.
      IMPORTANT: the tool's own decompressor round trips perfectly (the
      extraction of tiny\twoblk.dgc is byte identical to the original
      file), so the encoder and the decoder really do agree - the decoder
      is reproducible and the token stream really is a permutation of the
      literals.
      The chain of consequences (this is the whole bug in one paragraph):
      the literal's 8 bits are decoded from the stream, but with a
      probability that is slightly wrong (the prepare pass has not
      adapted the two deepest nodes of the current byte's tree), so the
      range coder's code/range state ends up slightly different - and
      therefore the NEXT symbol (the run length) is decoded from the
      wrong position and comes out as 0 instead of 5 or 1, and the symbol
      after that is off as well.  That is why the run symbol looks broken
      in the tiny cases: it is a symptom, not the cause.  The only real
      defect is that lit[80] and lit[160] (the 7th and 8th bit's nodes)
      are not prepared.
      Decoding the first literal of the 6 byte case with a CONSTANT model
      (all the probabilities 2048) gives 0x42 and never 0x41, no matter how
      the range decoder is initialised (48 variants of the skip/code/
      range/prev were tried).  So in the tool the probabilities of the
      7th and 8th bit of the first literal are NOT 2048, i.e. the prepare
      pass must have touched lit[80] and lit[160] - the two deepest nodes
      of the current byte's tree.  The prepare pass can only touch them if
      its chain is the CURRENT byte (0x41|0x100 = 0x141 has the nodes
      160, 80, 40, ...), and a decoder cannot know the current byte
      before it has read the model - which is the contradiction to
      resolve.
      The exact contradiction, in one paragraph:
        - the prepare+restore pair is the model update of the byte whose
          tree path it walks (the direction is that byte's bit at each
          level, the magnitude is scaled by the node of the previous
          level), and the main loop reads the model with that update
          already applied;
        - the tool's decoder must reproduce it, and the only way it can
          know the direction of the update for the node it is about to
          read is to have already decoded that bit - so the update must be
          applied one step later than the encoder applies it, or the
          encoder's main loop must read the *unprepared* model;
        - the scale chain makes the two orders differ: the encoder
          prepares from the deepest node up (so the scale of a level is
          the node of the level below it), while a decoder working from
          the root down would have to use the node of the level above it.
      Another very telling data point: with the scale chain
      "0x2000, node0*128, node1*128, ..." (128 = 2^7 and the block header's
      +08 = 7 for the 6 byte case!) and the initial previous byte 0xFF the
      6 byte case is decoded EXACTLY ("AAAAAA"), while the 4 and 5 byte
      cases (whose +08 is 7 as well) are not - so the multiplier is not
      simply derived from the header either, and the 6 byte case only has
      ONE symbol: the second symbol (and the run symbol) is what is still
      wrong.
      Two variants each nail ONE of the cases exactly, so the truth is
      close to both but is not in the searched space (4608 combinations of
      the prepare/restore direction, the scale chain, the chain byte, the
      pair/run model bases, the value assembly and the initial previous
      byte were searched - none of them satisfies more than one case):
        twoblk : the scale chain "0x2000, node0*128, node1*128, ..." with
                 the initial previous byte 0xFF decodes it exactly.
        ab1000 : the prepare's direction flipped (the same as the
                 restore's) with the disassembly's scale chain and the
                 initial previous byte 0 decodes it exactly ("BBAA").
      The differences between the two are the multiplier of the scale
      chain (1 vs 128), the prepare's direction (flipped vs not) and the
      initial previous byte (0 vs 0xFF) - all three are needed for one
      case and wrong for the other, so one of the three assumptions is
      still off.

      The argument lists of the two functions are NOT the same, and mixing
      them up was the cause of a whole afternoon of confusion:
        encoder sub_427970: arg_0 lit table, arg_4 &pair[prev*256],
            arg_8 &pair[cur*256], arg_C &ctx[slot], arg_10 p_lit,
            arg_14 p_pair, arg_18 p_pairb, arg_1C p_ctx,
            arg_20 = the CURRENT byte (the main loop's path),
            arg_24 = the PREVIOUS byte (the prepare/restore chain),
            arg_28 = &state
        decoder sub_427260: arg_0 lit table, arg_4 &pair[prev*256],
            arg_8 &pair[0] (the restore adds decoded*256), arg_C &ctx[slot],
            arg_10 p_lit, arg_14 p_pair, arg_18 p_pairb, arg_1C p_run,
            arg_20 = the chain (this[0x24]),
            arg_24 = &state
      => the chain of the prepare/restore passes is the PREVIOUS byte in
      both, and the main loop's path is the current byte's 9 bit tree.

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
      VERIFIED (2026-10-21): re-running the LZ77 over the plaintext of a
      stored twin reproduces the archive's stream B byte for byte and the
      number of literals equals v7 exactly, e.g.
        dgca100-normal.dgc   DATA: 7411 bytes -> 6955 literals, stream B
                             (21 bytes) reproduced exactly with
                             minlen = 1<<6, model shift = 4
        dgca-beta1-normal.dgc DATA: 9846 bytes -> 9306 literals, same
      So the pre-transform runs on the ORIGINAL data and its output
      (the literals) is what the entropy coder sees - possibly after the
      LZ stage (see 6e).

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
        path the caller passes the block header; in the normal path it
        passes the destination buffer pointer itself, which looks like a
        bug or at least an anomaly that has to be explained.
      The walk is a PURE PERMUTATION and it groups the equal byte values
      together - and indeed the decoded token stream has its values
      clustered (the 6955 bytes of the dgca100 DATA block decode into only
      1449 (literal,run) symbols, i.e. the equal values are adjacent).
      The encoder side (sub_428270) builds an index array (a permutation)
      and copies the bytes unchanged: out[j] = src[index[j]-1] (with a
      wrap around for index 0).  So the LZ stage itself is a pure
      reordering - but the token stream is NOT a permutation of the
      pre-transform's literals:
        a 1000 byte file "A"*500 + "B"*500 is stored as a 6 byte token
        stream whose first literal decodes as 0x42 while the pre-
        transform's literals are "AAAAAA" (0x41 x 6) - and the pre-
        transform's model stream is reproduced byte for byte, so the
        literals are known exactly.  0x42 is not even one of the literal
        values, so the stage (or something else on the way) transforms the
        values.  Neither the chain walk (a permutation) nor the inverse
        pre-transform (a plain LZ77 with the implicit distance, no
        accumulator) inverts such a transform, so the value transform (and
        its inverse) is still unknown.
      The open items: the exact start index of the chain walk, the value
      transform and where it is inverted.
      This is what still blocks reading the index of a compressed archive.

  6f. Solid mode uses the "column" method (flags bit 2 set, delta order in
      bits 16..31) which is a different transform - not implemented.

  6g. EMPIRICAL ORACLE for the entropy coder
      Two tests are available and they are NOT equivalent:
      (1) "re-encode" test: decode stream A, re-encode the decoded bytes and
          compare with stream A.  This only proves that the decoder and the
          encoder are mutual inverses - it does NOT prove that the decoded
          bytes are the ones the tool encoded, because a different token
          stream can be mapped to the same stream by a different encoder.
          It was used for a long time and is misleading.
      (2) "histogram" test: the LZ stage is a PURE PERMUTATION (verified in
          the disassembly of sub_428270: it builds an index array and the
          output bytes are copied from the source unchanged), so the token
          stream must have exactly the same byte histogram as the
          pre-transform's literals.  The literals are known exactly (the
          pre-transform can be re-run over the plaintext, see 6d), so this
          is a true oracle.
      (3) "end to end" test (the strongest): take the decoded token
          stream, run the chain walk (sub_428990) over every possible
          start index, then run the inverse pre-transform (the LZ77 with
          the implicit distance) on the result and compare with the
          original file.  It validates the token stream, the chain walk's
          start index and the LZ77's inverse at once, and it is the test
          that finally settles the LZ stage: with the right token stream
          the start index falls out of the brute force.  The script is
          e2e.py in the scratch dir (it also decodes the model stream B
          and rebuilds the literals from the plaintext).
      The best blocks to use as oracles (the longest stream A in the sample
      archives): t1000.bin.dgc/DATA (269 bytes), m_700.dgc/DATA (269),
      m_300_300.dgc/DATA (250), m_100_200_300.dgc/DATA (245),
      m_100_200_300.dgc/IFDT (76), m_300_300.dgc/IFDT (65),
      orc/idn.dgc/IFDT (35), c_hello.dgc/DATA (27), c_hello.dgc/IFDT (30).
      The new test pairs in the work area root are even better:
      dgca100-normal.dgc / dgca100-store.dgc (7411 bytes of data,
      6955 literals, a 2899 byte stream A), dgca110-* (7691 bytes) and
      dgca-beta1-* (9846 bytes).
      Scripts (scratch dir, "opencode\dgca"):
        pdec.py     the parameterised CM decoder (all the model variants)
        bf5.py      the matching CM encoder
        pt.py       the pre-transform (verified against stream B)
        perm3.py    the histogram oracle for one block
        joint*.py   the joint variant searches
        chain4.py   the chain variant matrix
        symwise2.py the symbol-by-symbol re-encode comparison
        walk*.py    the chain walk experiments
      Result of the search (2026-10-21): the CM decoder reproduces the
      archive's stream A byte for byte for the single symbol blocks
      (4096 x 'A' -> the token stream "AAA") and for the 21 symbol
      c_hello.dgc/DATA block, but the histogram test still fails (the token
      stream's histogram does not match the literals'), so the decoder is
      still wrong in a way the re-encode test cannot see.  The token
      stream's values are grouped (the equal values are adjacent), which is
      what the chain walk undoes.

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
