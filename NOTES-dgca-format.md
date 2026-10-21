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

  tag 1 block header (32 bytes):
    +0x00 u32 tag (1)
    +0x04 u32 original (uncompressed) size
    +0x08 u32 flags : (delta_order<<16) | b0 | b1<<1 | b2<<2
                      b0 = "has pre-transform", b1 = "LZ stage on",
                      b2 = "column/delta order"
    +0x0C u32 params : bit0 = "first byte was 0"
                        bits1-3   = this[5]  (literal/match mode)
                        bits4-7   = this[6]  (literal model shift)
                        bits8-11  = this[7]  (pair table shift)
                        bits12-15 = this[8]  (pair model shift)
                        bits16-19 = this[9]  (context prob shift)
                        bits20-23 = this[10] (run length model shift)
                        bits24-27 = this[14] (min match length exponent)
                        bits28-31 = this[13] (model shift of the pre-transform)
    +0x10 u32 v22   (LZ stat / chain start index)
    +0x14 u32 v7    (size of the data fed to the entropy coder)
    +0x18 u32 lenA  (length of stream A)
    +0x1C u32 lenB  (length of stream B)

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
  encode:  [pre-transform] -> [LZ stage] -> [entropy coder]  => stream A
           the pre-transform's model               => stream B
  decode:  stream A -> entropy -> LZ inverse -> pre-transform inverse
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
      decisions, followed by (len-1) raw bits.  Model = 32 entries of
      12 bit probabilities, all initialised to 2048.

  6c. Context mixing literal coder (sub_427970 / sub_427260)
      order-1 + order-2 models mixed with a 32 slot context table, the
      context slot = BSR(state) (31 if the state is 0).
      The literal is coded MSB first over a 9 bit tree node.

  6d. Pre-transform (sub_424C30 / sub_424910)
      an LZ77 with an IMPLICIT distance: a 2 byte hash table maps
      (prev byte, byte) -> the last output position; the distance is
      never transmitted, the decoder rebuilds the same table.
      min match = 1 << this[14].  The model stream (stream B) carries
      (literal run length, match length - minlen) pairs.

  6e. LZ stage (sub_428270 / sub_428990)   *** NOT FULLY REVERSED ***
      the encoder reorders the data (a permutation); the decoder rebuilds
      a permutation table from the byte histogram and walks a chain:
        Block[cnt[src[i]]++] = i
        dest[k] = src[Block^k(start)]
      This is implemented but does not yet reproduce the original order
      for permuted data (verified only for the identity case).

  6f. Solid mode uses the "column" method (flags bit 2 set, delta order in
      bits 16..31) which is a different transform - not implemented.

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
  XOR stream cipher with one feedback byte (sub_421C30 / sub_421C80):
     k1 = prng(); k2 = prng(); out = k1^k2^in; fb = k1^in (enc) / k2^in (dec)
  keystream: SHA-512 over a 39 round stretching loop seeded into MT19937.
  scope: the whole DGCC chunk (header+payload) is encrypted; other chunks
  only have header bytes 0x18..0x1F encrypted; IARC payload +0x20..+0x4F.
  NOT reimplemented in dgcunp.c yet.

9. TOOL
-------
  dgcunp.c   MSVC6, C89.  -l list, -v verbose, -o outdir extract.
  works: container parse, CRC verify, IARC, index (stored form), names,
         stored data extraction (CRC verified), compressed data extraction
         for each-file mode (CRC verified).
  open: the compressed index (LZ inverse) and the solid "column" method.
