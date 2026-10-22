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
  tag 2 : COLUMNS    -> `size` = the stride, `size` tag 1 blocks follow
                        (the "column" method, see section 6.5)

  tag 1 block header (32 bytes).  NOTE: the fields below are offsets inside
  the DGCC *payload* (the payload starts with the tag and the size):
    +0x00 u32 tag (1)
    +0x04 u32 original (uncompressed) size of the whole block
    +0x08 u32 flags  bit 0: this[4], bit 1: the LZ stage (the chain walk),
                     bit 2: the pre-transform, bits 16..19: the delta order
    +0x0C u32 params : the shifts of the entropy coder, see below
    +0x10 u32 v22   (the chain walk's start index)
    +0x14 u32 v7    (size of the data fed to the entropy coder = the size of
                    the pre-transform's output, i.e. the literal bytes)
    +0x18 u32 lenA  (length of stream A)
    +0x1C u32 lenB  (length of stream B)
  VERIFIED against the decoder (sub_425A50): the decoder reads the block
  structure as {+0 tag, +4 ?, +8 ?, +0xC params, +0x10 v22, +0x14 size,
  +0x18 ?, +0x1C ?} relative to the payload start, uses +0x0C as the shift
  word, +0x10 as the chain start index, +0x14 as the size of the entropy
  output (= v7) and +0x18/+0x1C as the two stream lengths.

  params (from the class setup in sub_425A50, "this" = the coder object):
    bit 0        -> this[0x2C]  = the "first byte was 0" flag (0 or 0xFF):
                                the initial "previous byte" of the coder
    bit 1        -> this[0x14]  = the match coder (0 = the literal coder)
    bits 4-7     -> this[0x18]  = literal model shift   (p_lit)
    bits 8-11    -> this[0x1C]  = pair table shift      (p_pairb)
    bits 12-15   -> this[0x20]  = pair model shift     (p_pair)
    bits 16-19   -> this[0x24]  = context prob shift   (p_ctx)
    bits 20-23   -> this[0x28]  = run length shift     (p_run)
    bits 24-27   -> this[0x38]  = the pre-transform's min match exponent
                                (minmatch = 1 << this[14], = 6)
    bits 28-31   -> this[0x34]  = the model stream's shift (= 4)
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
  The whole codec is CRACKED and verified byte exact (see section 11).
  There are two block formats; both are used inside one DGCC payload.

  6.0  THE BLOCK FORMATS
  ----------------------
  A DGCC payload is a stream of blocks:
      tag 0 : STORE      -> `size` raw bytes
      tag 1 : COMPRESSED -> the 32 byte block header, stream A, stream B
      tag 2 : COLUMNS    -> `size` = the stride, then `size` tag 1 blocks
                             (the "column" method, see 6.5)

  The 32 byte header of a tag 1 block (offsets inside the DGCC payload,
  the payload starts with the tag and the size):
      +0x00 u32 1                  the tag
      +0x04 u32 size               the ORIGINAL (uncompressed) size
      +0x08 u32 flags              bit 0: this[4], bit 1: the LZ stage,
                                   bit 2: the pre-transform, bits 16..19:
                                   the delta order
      +0x0C u32 params             the entropy coder's parameters
      +0x10 u32 v22                the start index of the chain walk
      +0x14 u32 v7                 the size of the token buffer
                                   (= the size fed to the entropy coder)
      +0x18 u32 lenA               the length of stream A
      +0x1C u32 lenB               the length of stream B (the model stream)

  6.1  THE PIPELINE
  -----------------
  ENCODER (sub_425600, "compress one block"):
      if (this[12])  vtable+0x38(...)  the PRE-TRANSFORM runs first:
                    the source -> the literals (v7 bytes) + stream B
      if (this[3])   sub_428270(dst=Block, src=the literals, len=v7, &v22)
                    the LZ STAGE: a permutation of its input
      sub_4244E0(this, Block, v7)      re-tune the model's shifts
      vtable+0x30(this, stream, Block, v7)   the entropy coder -> stream A
  So:  [pre-transform] -> [LZ stage] -> [entropy coder]
  and the LZ stage's output is the token buffer that the entropy coder sees.

  DECODER (sub_425A50):
      vtable+0x34 (the entropy decode) -> the token buffer (v7 bytes)
      if (flags & 2) sub_428990(dest, src=the token buffer, v7, v22)
                    the chain walk: the LZ stage's inverse
      if (flags & 4) vtable+0x3C (the inverse pre-transform) -> the data
      else            the inverse delta (see 6.5)
  i.e.  stream A -> entropy -> chain walk -> (pre-transform inverse | delta)

  6.2  THE CHAIN WALK  (sub_428990) - the LZ stage's inverse
  ---------------------------------------------------------
      cnt[256] = the histogram of the token buffer
      cnt[]    = the exclusive prefix sums of the histogram
      Block[cnt[src[i]]++] = i          (the positions grouped by byte value)
      dest[k] = src[Block^k(start)]    (start = the block's v22)
  The walk is a pure permutation of the token buffer, so the token buffer
  has the same byte histogram as the pre-transform's literals.

  6.3  THE PRE-TRANSFORM  (sub_424C30 / sub_424910)
  ---------------------------------------------------
  An LZ77 with an IMPLICIT distance: a 2 byte hash table maps
  (prev byte, byte) -> the last output position; the distance is never
  transmitted, the decoder rebuilds the same table.
      key = (the byte before) << 8 | (the current byte)
      min match = 1 << this[14]   (this[14] = the params' bits 24..27 = 6)
  The model stream (stream B) carries (literal run length, match length -
  minmatch) pairs; their sum is the original block size.  The model stream
  is coded with the gamma coder (the model shift = the params' bits 28..31
  = 4) and has two separate 32 entry models (the literal runs and the match
  lengths).

  6.4  THE ENTROPY CODER  (the CM literal coder + the gamma coder)
  ----------------------------------------------------------------
  6a. GFL range coder  (sub_426F80 / sub_427110)
      state: low/code, range, pending byte, pending 0xFF count.
      encoder: low=0, range=0x80000000; emits low>>23, keeps 23 bits,
               carry handled by a pending 0xFF counter; flush = 5 bytes.
      decoder: SKIP ONE BYTE (the encoder's dummy byte - sub_4270A0
               does `inc edx; mov [eax+10h], edx` before it reads the
               code), then code = b>>1, range = 0x80; renormalise:
                 code = ((code<<1)|(prev&1))<<7 | (b>>1); range <<= 8
      VERIFIED byte exact (the encoder reproduces real stream A bytes).

  6b. Symbol coding (gamma, sub_427880 / sub_4271B0)
      The number of "small branch" decisions = the value's bit length,
      then (len-1) raw bits (MSB first).  Model = 32 entries of 12 bit
      probabilities, all initialised to 2048.
      NOTE: the encoder writes (len-1) raw bits, not len - an off by one
      here desynchronises everything after the first symbol.
      The decoder returns the LEVEL itself for the levels 0 and 1 (so the
      value 1 is coded as one "continue" bit and no raw bits).

  6c. Context mixing literal coder (sub_427970 encoder / sub_427260 decoder)
      tables (allocated in the caller sub_423C90 / sub_423950):
        lit[256]      order-1 model,  initialised to 2048
        ctx[32]       the mixing weights, initialised to 2048
        run[256*32]   the run length model, initialised to 2048
        pair[256*256] the order-2 model, initialised to 2048
      The literal is coded MSB first over a 9 bit tree:
         node   = 2*node + bit        (node starts at 1 = the root)
         value  = 2*value + bit       (value starts at 0 -> the byte)
      The main loop mixes the two models:
         pr = (w*lit[node] + (4096-w)*pair[prev*256+node]) >> 12
      with w = ctx[BSR(state)] (31 when the state is 0 - the code pre-loads
      1Fh before the BSR), and updates pair[prev*256+node] only.
      lit[] and pair[] store P(0) (the probability of the bit 0).

      The PREPARE pass walks the tree of the PREVIOUS byte from the deepest
      node up:
         chain = prev | 0x100
         for k = 1..8:
             node = chain >> 1          (= (prev|0x100) >> k)
             bit  = chain & 1            (= (prev|0x100) >> (k-1) & 1)
             saved[k] = lit[node]
             lit[node] is moved TOWARD that bit:
                 bit 1: lit += ((4096-lit) * scale) >> 13
                 bit 0: lit -= (lit * scale) >> 13
             scale = the magnitude of that update (the DELTA of this level)
             chain = node
      The first scale is 0x2000.  NOTE: the scale of the next level is the
      DELTA of this level - NOT the node value (the compiler keeps the node
      only to extract the next bit).

      The RESTORE pass walks the SAME nodes (the previous byte's tree, from
      the deepest node up) and writes
         lit[node]  = saved - (saved >> p_lit)           if the bit is 1
         lit[node]  = saved + ((4096-saved) >> p_lit)     if the bit is 0
         pair[cur*256+node] = q - (q >> p_pairb)         if the bit is 1
         pair[cur*256+node] = q + ((4096-q) >> p_pairb)   if the bit is 0
      (cur = the byte that was just coded).

      The context weight and the state:
         state = (w*v61 + (4096-w)*v60) >> 12
         v61 = the product of the lit model's probabilities of the coded bits
         v60 = the same for the pair model
         if (v61 < v60) w -= w >> p_ctx;  else if (v61 > v60) w += (4096-w) >> p_ctx
      The initial "previous byte" is 0xFF if the first byte of the block is
      0 (the params' bit 0) and 0 otherwise.

  6.5  THE COLUMN METHOD  (sub_424FE0, the tag 2 blocks)
  -------------------------------------------------------
  When the data is "column friendly" the block is split into `stride`
  (= this[17], the tag 2's size field) interleaved columns; column k = the
  bytes at the positions k, k+stride, k+2*stride, ...
  Every column is delta transformed (the order = this[16] = the flags'
  bits 16..19) and then compressed as a tag 1 block (with the pre-transform
  switched off and the LZ stage possibly off as well - every column has its
  own flags!):
      order 1: d[i] = s[i] - s[i-1]      (s[-1] = 0)
      order 2: d[i] = d1[i] - d1[i-1]    (d1 = the order 1 delta)
  The decoder: every column is decoded (entropy -> chain walk -> the
  inverse delta) and the columns are de-interleaved again:
      data[i*stride + k] = column_k[i]

  6.6  THE MODEL PARAMETERS  (the params word)
  --------------------------------------------
      bit 0        : the first byte of the block was 0 (the initial prev)
      bits 1       : this[5]  - the match coder (0 = the literal coder)
      bits 4-7     : this[6]  - p_lit    (the shift of the lit model)
      bits 8-11    : this[7]  - p_pairb  (the shift of the restore's pair)
      bits 12-15   : this[8]  - p_pair   (the shift of the main pair model)
      bits 16-19   : this[9]  - p_ctx    (the shift of the context weight)
      bits 20-23   : this[10] - p_run    (the shift of the run model)
      bits 24-27   : this[14] - the pre-transform's min match exponent (6)
      bits 28-31   : this[13] - the model stream's shift (4)
  (the shifts are re-tuned per block by sub_4244E0)

  6.7  WHAT IS STILL NOT KNOWN
  ----------------------------
  * The MATCH coder (sub_427D60 / sub_427640), used when the params' bit 1
    is set (the "column" method uses it for very uniform columns).  None
    of the sample archives uses it.
  * The exact rule that decides whether the column method is used (the
    chi-square test in sub_423F90) - not needed for decoding.
  * The encryption (-p / -k) is specified in section 8 but not implemented
    in dgcunp.c.


7. -r RECOVERY DATA
-------------------
  A "DGCR" chunk is appended after the DGCA chunk (extension .dgcr).
  DGCR payload = an INFO chunk (48 byte payload) + a DATA chunk with the
  recovery data.
  INFO payload: +0x00 = 0x43, +0x04 = recovery length, +0x10 = 256 cols,
  +0x14 = rows, +0x18 = pages, +0x28 = file offset of the DGCR chunk,
  +0x2C = checksum.
  recovery bytes = 4 * rows * (256 + pages + 1)
  rows  = max(4, ceil(archivesize / ((256>>(level-1)) * 1024)))
  pages = ceil(archivesize / (rows*1024)); if pages == 1 rows = ceil(size/1024)
  VERIFIED for levels 1,5,9 on 100 byte .. 1 MB payloads.

  7.1  WHAT THE RECOVERY DATA IS
  ------------------------------
  It is NOT only a checksum: the INFO's +0x2C is the CRC-32 (zlib) of the
  whole archive (the bytes in front of the DGCR chunk) - that is the
  integrity check the tool's "dgcac k" performs (sub_422480 compares
  crc32(data) with the stored value).

  The DATA chunk holds a PARITY table, built by the writer (the three
  buffers "v340/v339/Block"):
      the archive is seen as a matrix of  pages x rows x 256 columns
      4 byte words (the matrix is padded with zeros if the archive is
      shorter than rows*256*pages words)
      part 1 (rows*256 words): for every (row, column) the XOR of the
              words of all the pages
      part 2 (pages*rows words): for every (page, row) the XOR of the
              words of all the columns
      part 3 (rows words): the offsets of the row blocks (the tool puts
              a copy of the data into a "DGCD" chunk that it builds in
              memory, and these are the offsets in it)
  It is a RAID-4 style redundancy: it can restore a lost 4 byte word,
  and for a one page archive (the usual case for a small archive) the
  table degenerates into a full copy of the archive's data.  The
  redundancy ratio is 1/pages, which is what the -r level selects
  (level 9 = 100%).

  The recovery data is encrypted with the SecureCryptograph class (see
  section 8) with the FIXED key: the password "SecureCryptograph" and an
  8 byte block of zeros.  The three parts are encrypted one after the
  other with the same cipher object, so the key stream runs over the
  whole recovery data.

  MEASURED: two archives of the same size but different content have
  1019 of the 1032 recovery bytes different (the first 8 bytes are a
  fixed header), and two archives of different sizes have the same
  first 8 bytes - so the table is a scrambled (encrypted) function of
  the archive's content.

  (The "differential pass" that the old notes mentioned was the GUI's
  variant of the generator - the CLI's writer stores the plain table,
  encrypted.)

  7.2  THE REPAIR (what dgcunp -R does)
  --------------------------------------
  The parity table is a 2 dimensional parity code: the column parity
  (part 1) locates the damaged columns and the row parity (part 2) the
  damaged words.  For every column whose parity does not match, the
  damaged word is the parity XOR the other words of the column; the row
  parity tells which page of the column is the damaged one.  The final
  check is the CRC-32 of the archive (the INFO's +0x2C).

  7.3  WHAT THE TOOL DOES WITH IT
  -------------------------------
  Nothing.  Tested with a partly zeroed copy of dgca110-rec.dgcr:
      dgcac k   -> "Check process failed."  (it detects the damage)
      dgcac e   -> extracts the DAMAGED data (a wrong CRC), or nothing
                   at all when the index (the IARC chunk) is damaged
      neither command rewrites the file (checked byte for byte)
  So the v1.10 tool writes the recovery data but never repairs with it;
  it only uses the CRC in the INFO.  dgcunp.c does the same: it verifies
  the recovery checksum and reports "the archive is DAMAGED", and with
  -R it repairs the archive and writes "<archive>.repaired".


8. ENCRYPTION (-p password / -k keyfile)
----------------------------------------
  THE ENCRYPTION IS FULLY CRACKED (2026-10-22) and implemented in
  dgcunp.c (the SHA-512, the MT19937 variant, the PRNG, the cipher and
  the key derivation are byte exact - VERIFIED against the original
  binary, see section 8.6).  An encrypted archive can be decrypted with
  `dgcunp -p<password>` or `dgcunp -k<keyfile>`; the extracted files are
  byte identical to the ones dgcac.exe extracts.

  Cipher (sub_421C30 encrypt / sub_421C80 decrypt), a self inverse XOR
  stream with one feedback byte:
     encrypt:  in=buf[i]; k1=prng(); k2=prng();
               buf[i] = in^k1^k2 ;  fb = in^k1
     decrypt:  in=buf[i]; k1=prng(); k2=prng();
               buf[i] = in^k1^k2 ;  fb = in^k2
  The feedback byte lives at this+0x1540, the 64 byte key buffer at
  this+0x1480, a 128 byte rolling state at this+0x14C0, a 64 byte scratch
  at this+0x1500, the MT19937 pool at this+0x10 and the index/counter at
  this+8/this+12.

  8.1  THE PRNG (sub_421B70, 0xBE bytes, hand disassembled)
  ----------------------------------------------------------
      prng():
          if (index == 0 || counter < 64) {
              tmp[32] = 32 MT words (128 bytes, the raw state words)
              h = SHA-512(); h.update(tmp, 128); h.update(rolling, 128);
              keybuf = h.getState()          /* 64 bytes, NOT hex text! */
              if (counter < 64) counter++;
          }
          fb = feedback;
          ret = keybuf[index] ^ fb;
          rolling[index] = fb;  scratch[index] = fb;
          feedback = 0;
          index = (index + 1) & 0x3F;
          return ret;
      Note: the key buffer is the raw 64 byte SHA-512 state; the hex
      formatting (sub_4215A0, "%08x" per 32 bit word, 8 words = 128 chars)
      is a different method of the hash class (the vtable entry +0x10) and is
      NOT used here.  The first 64 prng calls (the first 32 data bytes)
      re-derive the key buffer for every single byte.

      TRAP: the 64 byte "scratch" buffer at this+0x1500 OVERLAPS the
      upper half of the 128 byte rolling state at this+0x14C0 (0x1500 =
      0x14C0 + 0x40)!  So the feedback bytes are stored TWICE in the
      rolling state: the bytes 0..63 and the bytes 64..127 hold the
      same values.  The hash of the rolling state therefore sees every
      feedback byte twice.  (Getting this wrong breaks the key stream
      from the 3rd prng call on - the first 32 data bytes still match.)

  8.2  THE KEY DERIVATION (sub_421CF0) - the C code is the reference
  -----------------------------------------------------------------
      void __thiscall sub_421CF0(this, a2, Block, a4..a10)
      {
          sub_4206B0(hash); sub_4200D0(hash);            /* SHA-512, init */
          sub_4214C0(hash, a9, a10);                      /* update 1 */
          p = (a8 >= 0x10) ? Block : &Block;              /* the string */
          sub_4214C0(hash, p, a7);                         /* update 2 */
          sub_420160(hash);                               /* finalize */
          sub_4201F0(hash, state);                        /* getState */
          history_dword0 = 0xFFFFFFFF;                    /* v31 */
          for (i = 0; i < 39; i++) {
              copy the state (16 dwords) to the history;    /* v32 + */
              sub_4214C0(hash, state, 0x40);
              sub_4214C0(hash, state, 0x40);
              sub_4201F0(hash, state);
          }
          sub_426E80(this + 16, &v31, 624);                /* the MT's seed */
          index = counter = feedback = 0; the rolling state = 0;
      }
      So:  SHA-512(data || string), 39 rounds, and the MT's seed =
      [0xFFFFFFFF] + the history's dwords 0..622 (623 dwords) - the
      0xFFFFFFFF is the dword in front of the history, NOT a prefix of the
      history itself.
      Note that the hash is NOT reset after the 39 rounds in the
      derivation: sub_421CF0 ends with the hash's init (the vtable
      entry +0x4 = sub_4200D0), so the PRNG's hash starts from the
      initial state again.


      The string is an MSVC std::string passed by value: a7 = its size,
      a8 = its capacity, Block = its data (or the inline buffer).

      sub_421EE0 ("setKey and verify") calls sub_421CF0 with the string
      copied from a4 and the 8 bytes at &a2 - and the caller pushes two
      zero dwords there, so the 8 hashed bytes are 4 zero bytes followed by
      the caller's return address.  That key is used for the PASSWORD
      CHECK only (the writer and the reader call it from different places,
      so the return address - and with it the key - differs; the check
      data is encrypted with it in both cases, so it works).

  8.3  THE MT19937 VARIANT (sub_426E80 / sub_426B30 / sub_426EC0)
  ---------------------------------------------------------------
      The seeding is NOT the standard init_by_array:
          for i in 0..623: state[i] = key[i % key_length]
          twist()
      The twist is the standard MT19937 twist (the MMX version
      sub_426B30 and the scalar one sub_4269E0 compute the same thing;
      the CPUID check sub_426980 picks the MMX one).  The tempering is
      NOT applied to the state: the twist copies the tempered words
      into a separate output array (the MT object + 0x9C8) and
      sub_426EC0 returns the words of that array.  The state array
      (the MT object + 4) therefore keeps the untempered values and
      the output sequence is the same as the standard MT19937's.

  8.4  THE SHA-512 (the binary's own word order)
  -----------------------------------------------
      The hash is the standard SHA-512 with ONE difference: when the
      transform loads the message, every 8 byte group is byte
      reversed (the code does a bswap32 of both dwords and swaps
      them).  The state and the K constants are the standard ones
      (the IV at this[2..17] is the standard H0..H7 with the low
      dword first) and getState (sub_4201F0) returns the 64 raw
      bytes of the state, i.e. every 64 bit word with its low dword
      first (which is the byte reversed digest).

      VERIFIED: the getState of SHA-512("abc") is
      ba7a6193a135afdd314120ae497341cca27ea9894efae6129ad3554be6ee9e0a
      a8c14f272a999221bdebfea3233cba360ee83c6423444d459fa44ca54fc99a2a
      (the same as the standard digest, byte reversed per 8 byte group).

  8.5  SCOPE (measured by diffing an encrypted and a plain archive)
  ----------------------------------------------------------------
      * the whole DGCC chunk (the 32 byte header + the payload) is encrypted
        as ONE unit - the chunk's ID and its size are encrypted too, so the
        reader must decrypt the header before it can walk the tree;
      * inside the IARC payload the bytes 0x20..0x4F are encrypted and
        the flags' bit 0 is set;
      * the chunk headers of the outer levels (DGCA / DATA / INFO / IARC /
        IFDT / IFNM) are NOT encrypted - only their CRC fields differ
        (the CRCs are computed over the CIPHERTEXT);
      * the DGCR chunk (the recovery data) is not encrypted either, but it
        covers the archive AS IT IS STORED, i.e. the encrypted bytes - so
        the recovery check has to run BEFORE the decryption.

  A test pair for this: `dgcac a plain.dgc src` vs
  `dgcac a -p secret enc.dgc src` - the two files differ only at the chunk
  header CRC fields, in the DGCC chunks and in the IARC payload.

  8.6  THE VERIFICATION OF THE CRYPTO
  -----------------------------------
      The implementation in dgcunp.c is byte exact.  It was verified
      against the original binary by calling its own functions
      (dgcac.exe has no relocations, so it has to be mapped at
      0x400000; a helper DLL was injected into a running dgcac.exe to
      do that):
        - the getState of SHA-512("abc")   (the SHA-512)
        - the MT19937's output of the seed 0..623
        - the key stream of the fixed key (the password
          "SecureCryptograph" and 8 zero bytes):
          590661c76a2ad275dd11187646cd059ede7a6c1e36db71e6a7b326b083c2b60
          3350b64663ba46dbf9f77f88b528bc9d29927441709033aad5da5cbf58030f470
      and against the real data: the recovery table of a .dgcr file
      decrypts to the archive's bytes (see section 7).

  8.7  THE TWO KEYS OF AN ENCRYPTED ARCHIVE
  ------------------------------------------
      There is NO 96 byte key material in an archive: the old note about
      it was a misinterpretation of the writer's code.  The writer
      (sub_40AE90) uses TWO different keys, both derived from the
      PASSWORD alone:

        key1 = SHA-512( 8 zero bytes | password )   stretched over 39
                rounds
        key2 = SHA-512( the 32 byte PLAINTEXT chunk header | password )
                stretched over 39 rounds

      and uses them like this:
        * the 32 byte header of every DGCC record is encrypted with
          key1 (the "verify" key of sub_421EE0 - the same derivation
          the SecureCryptograph class uses for its password check);
        * the payload of that DGCC record is encrypted with key2, i.e.
          the key depends on the PLAINTEXT header of its own chunk;
        * the 48 bytes of the IARC payload at +0x20 are encrypted with
          key1.

      The reader (sub_40A100 / sub_40FDB0) does exactly the same, so
      the writer and the reader agree - the CLI has no bug here (the
      old note claimed otherwise).

      The PASSWORD is:
        * the text after -p, used as it is;
        * with -k: the hex TEXT of the SHA-512 of the key file's
          content.  The binary formats the state word by word - the
          HIGH dword first, then the low one - which is exactly the
          standard SHA-512 digest, so the password is the usual
          128 character hex digest of the key file (MEASURED: two key
          files with the same content but different names give the same
          key stream).

      The key derivation is the one of section 8.2: the data comes
      first, then the password:
          SHA-512( data | password ) stretched over 39 rounds
      and the stretch seeds the MT19937.

      dgcunp implements this: `-p<password>` or `-k<keyfile>` decrypts
      the archive in memory, the CRCs are then recomputed (they were
      computed over the ciphertext) and the files are extracted.



9. TOOL
-------
  dgcunp.c   MSVC6, C89.  -l list, -v verbose, -R repair, -o outdir
             extract, -t the crypto's self test, -p<password> / -k<keyfile>
             decrypt an encrypted archive.
  works: container parse, CRC verify, IARC, the index (stored AND
         compressed), the name list (stored AND compressed), the data area
         (stored, compressed, solid and the column method) - every
         extracted file is verified against the CRC-32 of the index.
  The extraction uses the wide APIs with the "\\?\" prefix, so long UTF-8
  names (> MAX_PATH) work.
  works: the crypto of DGCA v1.10 (the SHA-512, the MT19937 variant, the
         PRNG, the cipher and the key derivation - byte exact, see
         section 8) and the recovery data: -R decodes the DGCR chunk,
         repairs the damaged words with the parity table and writes
         "<archive>.repaired".
  works: the encryption of the archives (-p / -k): -p<password> or
         -k<keyfile> decrypts the archive in memory (the two keys of
         section 8.7) and the extracted files are byte identical to the
         ones dgcac.exe extracts.
  open: the match coder (the params' bit 1).

  dgcpk.c   MSVC6, C89.  the PACKER (the archiver):
         dgcpk a [-n] [-f] [-i] [-r<n>] <archive> <file>...
           -n     do not compress (the blocks are stored)
           -f     one block per file (not the solid mode)
           -i     identity: do not write the time stamps
           -r<n>  append the recovery data (the parity table)
  It writes the same format as dgcac.exe and the archives it writes are
  read back by dgcac.exe ("dgcac l", "dgcac e" - the extracted files are
  byte identical) and by dgcunp.c.  The CM coder of dgcpk.c is byte
  identical to the Python reference (cm.py).

  9.1  HOW THE PACKER WORKS
  -------------------------
  * the data -> the pre-transform: an LZ77 with an implicit distance.
    The hash table (65536 entries) maps the key ((the previous byte) << 8)
    | the byte to the last position; a match is accepted when it is at
    least minmatch (= 1 << the params' bits 24..27 = 64) bytes long and
    when it does not overlap itself (the distance must be at least the
    length - the decoder copies the match forward out of the output).
    The output is the literals and the model stream (the pairs of the
    literal run length and the match length - minmatch, coded with the
    gamma symbol coder and the params' bits 28..31 = 4).
  * the token buffer (the literals) -> the CM literal coder (stream A)
    and the model stream -> stream B.
  * the block: the tag 1, the original size, the flags, the params
    (0x46453320 - the same as the tool's), v22, v7 (the token buffer's
    size), lenA, lenB and the two streams.
    The flags are 4 (the pre-transform): the packer does NOT use the
    LZ stage (the chain walk), so the decoder skips it - the archives
    are a little bigger than the tool's but they are read back by it.
  * the index: the 64 byte entries (the CRC-32, the attributes, the two
    FILETIMEs, the original size, the compressed size and the offset in
    the DATA payload) stored TRANSPOSED, compressed like any other data.
  * the name list: the pairs (the length, the name), the names are
    relative to the current directory.
  * the IARC: the flags, the version " 001", the time stamp, the number
    of the entries, the total size, the size of the index table and the
    size of the name blob.
  * the chunk header: the id, 0x20, the payload size, 0, the flags, 1,
    the CRC-32 of the payload and the CRC-32 of the 32 header bytes
    with the last field zeroed.  Every chunk is padded to 16 bytes.
  * the recovery data (-r<n>): the parity table of section 7.1 over the
    archive's bytes, encrypted with the fixed key.

10. VERIFICATION
---------------
  Every archive in the work area (and ~100 more in the scratch dir) is
  extracted by dgcunp.c and every file's CRC-32 matches the index:
      dgca100-normal.dgc  dgca110-normal.dgc  dgca-beta1-normal.dgc
      dgca_beta1.dgc  dgca_v100e.dgc  names.dgc (5981 entries!)
      every m_*.dgc / t*.dgc / c_*.dgc / n_*.dgc test archive
  The Python reference implementation (cm.py in the scratch dir) reproduces
  the same bytes.

  The crypto (section 8) is verified against the original binary: the
  getState of SHA-512("abc"), the MT19937's output and the key stream of
  the fixed key are byte exact, and the recovery data of the .dgcr files
  decrypts to the archive's bytes.

  The repair (section 7.2) is verified: a .dgcr file with three
  damaged words is repaired by "dgcunp -R" and the archive's CRC-32
  matches the one in the INFO chunk again; the repaired archive is
  extracted without a single error.

11. HOW THE CODEC WAS CRACKED (the traps)
-----------------------------------------
  * The DECODER's argument list is NOT the encoder's: in sub_427260 the
    chain of the prepare/restore passes is arg_20 (the previous byte) and
    arg_1C is p_ctx - the notes used to have them the other way round and
    that produced the "the chain must be the current byte" contradiction.
  * The prepare pass's scale chain is the DELTA of the previous level, not
    the node value (the node is only kept to extract the next bit).
  * The restore pass walks the previous byte's tree from the DEEPEST node
    up (the opposite order of the main loop).
  * The gamma decoder returns the LEVEL for the levels 0 and 1 (the value 1
    is one continue bit and no raw bits).
  * The initial "previous byte" is 0xFF if the first byte of the block is 0
    (the params' bit 0) - the opposite way round desynchronises the coder.
  * The LZ stage is a permutation, but the values it permutes are the
    DELTA TRANSFORMED bytes when the column method is used (the flags'
    bits 16..19 = the delta order).
  * The IFDT blob of a compressed archive differs from the blob of the
    stored twin (the "compressed size" and "offset" fields) - comparing
    the two is a false oracle.
  * The chain walk's start index is the block's v22 (the payload's +0x10).
  * The crypto's "scratch" buffer overlaps the upper half of the rolling
    state, so the feedback bytes are hashed twice (section 8.1).
  * The binary's SHA-512 reverses every 8 byte group of the message
    (section 8.4) - a plain SHA-512 gives a different key stream.

