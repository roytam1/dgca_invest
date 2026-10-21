# AGENTS.md - DGC archiver (`dgcac.exe`) reverse engineering

Workarea for reverse engineering **DGCA / DGC Archiver v1.10** by SYN (Shin-ichi TSURUTA,
2000-2005) and writing an unpacker for the `.dgc` / `.dgcr` archives it produces.

```
dgcac.exe        the target (Win32 console, MSVC6, 2006-08-07)
dgcac.exe.lst    IDA disassembly listing (~5.3 MB)
dgcac.exe.c      Hex-Rays decompiled C (~1.0 MB, 462 functions)
NOTES-dgca-format.md   full format + codec specification
dgcunp.c         unpacker / lister written from this analysis (MSVC6, C89)
```

Everything in `NOTES-dgca-format.md` is **verified against bytes produced by the tool
itself** - not inferred from the decompiler alone.

---

## 1. Ground truth: always generate your own test archives

`dgcac.exe` runs on this machine and is the only oracle that matters. Never trust a
decompiler transcription without a byte-level cross-check.

```powershell
# create an archive
dgcac.exe a  [-n] [-f] [-i] [-e] [-d] [-u] [-w<n>] [-z<n>]
             [-p<password>] [-k<keyfile>] [-r<n>] [-x<extlist>] [-o<orderlist>]
             <archive> <file-or-folder>
# inspect
dgcac.exe l [-w<n>] <archive>          # list
dgcac.exe e [-p<pw>] <archive> <dir>    # extract
dgcac.exe k <archive>                  # check
```

Switches that matter for analysis:

| switch | effect |
|---|---|
| `-n` | no compression -> every `DGCC` block becomes `tag 0` STORE. **This is the golden path**: with `-n` the index and name blobs are stored verbatim, so you get the exact plaintext of structures that are normally compressed. |
| `-i` | identity -> all timestamps (archive *and* per-file) are zeroed. Combined with `-n` this makes the index blob **byte-for-byte deterministic**, so a `-i -n` archive and an `-i` archive of the same tree have *identical* index plaintext. That is how the codec was validated. |
| `-f` | each-file mode (one `DGCC` per file) instead of solid |
| `-p<pw>` | encryption (see `NOTES-dgca-format.md` section 8) |

Scratch area used during the analysis: `C:\Users\Roy\AppData\Local\Temp\opencode\dgca`
(sample archives, Python prototypes). It is disposable - regenerate anything you need.

---

## 2. The two files you will be reading

`dgcac.exe.lst` (5.3 MB) and `dgcac.exe.c` (1.0 MB) are far too big to read whole.

* **`.c`**: functions are delimited by `//----- (00ADDRESS) ----` markers. Grep for the
  address, then read the function body.
* **`.lst`**: address-prefixed lines like `.text:00426F80                 mov eax, [esi]`.
  The decompiler mis-renders the range coder (it looks like float code); **the disassembly is
  the truth** for `sub_426F80` / `sub_427110` / `sub_4270A0`.
* Key vtables: DGCA file class `0x437D98`, compressor `0x4389B8`, crypto `0x438944`/`0x43896C`.

---

## 3. Container format (summary - full spec in `NOTES-dgca-format.md`)

A DGC archive is a **tree of 32-byte-header chunks**:

```
struct Chunk {                 little endian
    char   id[4];              "DGCA" "DATA" "INFO" "IARC" "IFDT" "IFNM" "DGCC" "DGCR"
    uint32 hdr_size;           always 0x20
    uint32 payload_size;
    uint32 zero_0c;
    uint32 flags;              1 on DGCA / INFO / DGCR
    uint32 align;              always 0x10
    uint32 crc_payload;        CRC-32 (zlib) of the payload
    uint32 crc_header;         CRC-32 of these 32 bytes with this field zeroed
};
```

```
DGCA
|-- DATA -- DGCC x1 (solid) | xN (-f / -n)
`-- INFO
    |-- IARC                   80-byte fixed archive index
    |-- IFDT -> DGCC           64 bytes per entry, stored TRANSPOSED (column major)
    `-- IFNM -> DGCC           name list (u32 len + UTF-8 bytes, backslash paths)
```

* A container's payload is the concatenation of its child records; each child record is
  zero-padded to the next 16-byte boundary and **the padding counts** in the parent's
  `payload_size`.
* `DGCC` payload = block stream: `u32 tag, u32 size`; `tag 0` STORE, `tag 1` COMPRESSED
  (32-byte block header + stream A + stream B), `tag 2` CHAIN of `tag 1` blocks.
* Per-file index entry (64 B): `+00` CRC-32 of the file, `+04` attributes, `+08/+10` FILETIME
  create/modify, `+18` original size, `+20` "compressed" size, `+28` offset in the DATA
  payload.

---

## 4. The codec (status)

Pipeline, encoder side:

```
[pre-transform] -> [LZ stage] -> [entropy coder] -> stream A
pre-transform model                        -> stream B
```

decoder side: `stream A -> entropy -> LZ inverse -> pre-transform inverse`.

**Solved and byte-verified:**

* **Range coder** - "carryless" variant.
  * encoder: `low=0, range=0x80000000`; emits `low>>23`, keeps 23 fraction bits, carry
    handled by a pending-`0xFF` counter; flush emits 5 more bytes.
  * decoder: **skip one byte** (the encoder's dummy byte), then `code = b>>1, range = 0x80`;
    renormalise `code = ((code<<1)|(prev&1))<<7 | (b>>1); range <<= 8`.
  * *Proof*: re-encoding the pre-transform model stream of a real archive reproduces the
    real bytes exactly (`003000fbd8800000` for 4096x`A`).
* **Symbol coding** (gamma) - verified line by line against `sub_427880` (encoder) and
  `sub_4271B0` (decoder): the number of "small branch" decisions = the value's bit length,
  then `len-1` raw bits (MSB first). 32-entry, 12-bit probability models initialised to 2048.
* **CM literal coder** - order-1 (`lit[256]`) + order-2 (`pair[256*256]`) models mixed against a
  32-slot context table; the slot is `BSR(state)` and is **31 when the state is 0** (the encoder
  pre-loads `eax = 1Fh` before `bsr`). The literal is coded MSB first over a 9-bit tree:
  `node = 2*node + bit` (node starts at 1) and `value = 2*value + bit`, i.e. the first bit is the
  most significant.
  * the **prepare** pass: 8 levels, `node = chain>>1`, `chain = node`, and the *scale* of level
    k is the **node** of level k-1 (the encoder clobbers the scale register with
    `mov ecx, eax`); the first scale is `0x2000`.
  * the **restore** pass: same chain, `lit[node] = saved +/- (saved>>p_lit)` and
    `pair[cur*256+node] +/- (>>p_pairb)`.
  * the **pair** index is `prev*256+node`, the **run** index is `cur*32+value`.
  * the chain of the prepare/restore passes: the disassembly says the
    *previous* byte (the encoder passes var_484C6, the decoder the object
    field this[0x24]) - but a 6 byte test case (a 1000 byte file
    "A"*500+"B"*500, whose token stream must be "AAAAAA") shows that the
    chain has to contain the node 80 = (0x141)>>2, i.e. the chain is the
    *current* byte (0x41|0x100).  The first literal decodes as 0x42
    instead of 0x41 and the 7th bit is the first wrong one, and that bit's
    probability can only differ from 2048 if lit[80] was touched by the
    prepare pass.  Either the main loop must read the *unprepared* model
    or the decoder has to apply the prepare's effect incrementally while
    it decodes the bits - this is the last known gap in the CM coder.
  * *Open*: with the settings the disassembly prescribes the index (IFDT) blocks decode
    byte exactly but the DATA blocks do not.
* **Pre-transform** - LZ77 with an *implicit distance*: a 2-byte hash table maps
  `(prev byte, byte) -> last output position`; the distance is never transmitted, the
  decoder rebuilds the same table. `minmatch = 1 << this[14]`. Stream B carries
  `(literal run length, match length - minmatch)` pairs; their sum is the original size.
  * VERIFIED byte exact: re-running the LZ77 over the plaintext of a stored twin
    reproduces the archive's stream B byte for byte and the number of literals equals
    `v7` (3 archives: dgca100, dgca110, dgca-beta1 - `minlen = 1<<6`, model shift 4).
* **Block header** - `size` = the *original* size, `v7` = the size fed to the entropy coder
  (= the size of the pre-transform's output, the literal bytes). (Easy to mix up; `v7` is
  what the decoder must produce from stream A.)
* **Pipeline order** (from the disassembly of `sub_425600` / `sub_425A50`):
  encode = `[LZ stage] -> [pre-transform] -> [entropy]`, decode =
  `[entropy] -> [chain walk] -> [inverse pre-transform]`.
* **Chain walk** (`sub_428990`, fully known): histogram -> prefix sums ->
  `Block[cnt[src[i]]++] = i` -> `dest[k] = src[Block^k(start)]`; the start index is
  `*(u32*)arg_C` (arg_C is a *pointer*).
* **The LZ stage is a PURE PERMUTATION** (`sub_428270` builds an index array and copies
  the bytes unchanged) - so the token stream has the same byte histogram as the
  literals.  The earlier "it also applies a delta" note was WRONG.

**Still open:**

* **The entropy decoder still produces wrong bytes.**  The re-encode test
  (`encode(decode(A)) == A`) is only a self-consistency test and cannot see this; the
  real oracle is the **histogram**: the token stream must have the same byte histogram
  as the literals (which are known exactly).  It currently fails.
* **The chain walk's start index** - the normal path passes the destination buffer as
  `arg_C` (which would read uninitialised memory), the column path passes the block
  header.  The start index has to be found (v22, the block header's +0x10, is a candidate).
* **Solid mode "column" method** (method A) - flags bit 2, delta order in bits 16..31.
  Sizes come out right, content is wrong.
* **Encryption** (`-p` / `-k`) is fully specified in `NOTES-dgca-format.md` section 8 (the
  cipher, the SHA-512/MT19937 key derivation and exactly what gets encrypted) but is not
  implemented in `dgcunp.c` yet. A ready-made test pair: `dgcac a plain.dgc src` vs
  `dgcac a -p secret enc.dgc src` differ only in the chunk header CRC fields and in the
  `DGCC` chunk.

---

## 5. Build & test the unpacker

MSVC 6.0 is the only compiler installed (`C:\Program Files (x86)\Microsoft Visual Studio\VC98`).
There is no `vcvars32.bat`; use `VCVARS32.BAT`:

```powershell
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" >nul 2>&1 ^
  && cd /d <workarea> && cl /nologo /W3 /O2 dgcunp.c /Fe:dgcunp.exe ^
  && link /nologo dgcunp.obj /OUT:dgcunp.exe'
```

`cl` does not run the link step here - run `link` explicitly, or the `.exe` is not produced.
(The workarea is a UNC path, which `cmd` cannot `cd` to; build in a local directory and
copy the `.exe` back, or map a drive letter first.)

```powershell
dgcunp.exe -v archive.dgc            # dump the chunk tree + CRC status
dgcunp.exe archive.dgc                # list the entries
dgcunp.exe -o outdir archive.dgc      # extract
```

**Verification is the CRC-32 stored in the index**: every entry carries the CRC-32 of the
original file, so the unpacker can prove correctness without a reference copy.

Current state of `dgcunp.c`:

| area | status |
|---|---|
| chunk tree, both CRC-32s | working |
| `IARC`, `IFDT` (stored form), `IFNM` | working |
| extract, stored archives | working - files byte-identical to the originals |
| compressed data, each-file mode | working - decoded data area CRC matches the archive |
| compressed index | blocked on the LZ stage (section 4) |
| solid mode | sizes right, content wrong |
| encrypted archives | not implemented |

---

## 6. Method that worked - use the tool as an oracle

Static reading of this binary is slow and error-prone; the following loop is far faster.

1. **Generate a minimal, controlled archive.** One file, known bytes, known size.
2. **Get the exact plaintext of a compressed structure.** Create the *same* tree twice, once
   with `-n` (stored) and once compressed, both with `-i` so the timestamps are zeroed.
   The stored archive hands you the plaintext of the index blob; the compressed one hands
   you the ciphertext. The two are byte-identical inputs to the codec.
3. **Re-implement one stage and check it against the real bytes.** My Python prototype
   re-encoded the pre-transform model stream and matched the archive byte-for-byte; that
   single match validated the range coder, the symbol coder and the pre-transform at once.
4. **Use the per-file CRC-32 as the end-to-end test.** `dgcunp.exe` prints the CRC of the
   decoded data area; it must equal the CRC in the index.
5. **Turn the encoder into an oracle.** Once the *encoder* reproduces a real stream
   byte-for-byte, `encode(decode(real_stream)) == real_stream` becomes a cheap
   pass/fail test for the decoder, and the first differing byte localises the divergence.
   This is the sharpest tool available for the CM coder: the best test archives are the
   ones with the longest stream A - `t1000.bin.dgc` DATA (269 bytes), `m_700.dgc` DATA
   (269), `m_300_300.dgc` DATA (250), `m_100_200_300.dgc` DATA (245) and the IFDT
   blocks of the same archives (65..76 bytes). The scratch scripts are `pdec.py`
   (the parameterised CM decoder), `bf5.py` (the matching encoder), `joint2.py` (the
   joint variant search) and `chain4.py` (the chain matrix).

Three bugs that cost real time and are worth remembering:

* the CM coder's **context slot** is `BSR(state)`, and `BSR(0)` leaves the destination
  register untouched - the code pre-loads `1Fh`, so the answer is 31, not 0;
* the decompiled `sym()`/symbol decoder **loses a `break`** in one branch if you transcribe
  it carelessly, which turns a 2-level symbol into a 32-level runaway and desynchronises
  everything downstream;
* the CM coder's prepare pass **overwrites its own scale register** with the node value, so
  the scale chain is `0x2000, node0, node1, ...` and not the running product.

---

## 7. Conventions

* The analysis files are third-party generated: do not reformat `dgcac.exe.c` or
  `dgcac.exe.lst`.
* `dgcunp.c` is C89 for MSVC 6 (`__int64`, no `//` comments, declarations at the top of a
  block); it must keep building with `cl` from VC98.
* Keep new findings in `NOTES-dgca-format.md` and update section 4 of this file when a stage
  of the codec is cracked.
* Keep this file and the notes plain ASCII: the editor used here can silently introduce
  UTF-8 punctuation that makes later patches fail to match.
