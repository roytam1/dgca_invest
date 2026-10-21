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
* **Symbol coding** - gamma style: the number of "small branch" decisions = the value's bit
  length, then `len-1` raw bits. 32-entry, 12-bit probability models initialised to 2048.
* **Context-mixing literal coder** - order-1 (`lit[256]`) + order-2 (`pair[65536]`) models
  mixed against a 32-slot context table; the slot is `BSR(state)` and is **31 when the state
  is 0** (the encoder pre-loads `eax = 1Fh` before `bsr`). The literal is coded MSB first
  over a 9-bit tree: `node = 2*node + bit` (node starts at 1) and
  `value = 2*value + bit`, i.e. the first bit is the most significant.
* **Pre-transform** - LZ77 with an *implicit distance*: a 2-byte hash table maps
  `(prev byte, byte) -> last output position`; the distance is never transmitted, the
  decoder rebuilds the same table. `minmatch = 1 << this[14]`. Stream B carries
  `(literal run length, match length - minmatch)` pairs; their sum is the original size.
* **Block header** - `size` = the *original* size, `v7` = the size fed to the entropy coder
  (= the size of the pre-transform's output, the literal bytes). (Easy to mix up; `v7` is
  what the decoder must produce from stream A.)

**Still open:**

* **LZ stage permutation** (`sub_428270` / `sub_428990`). The stage is size preserving:
  the entropy stream decodes to exactly `v7` bytes, which is also the size of the
  pre-transform's output. It is *not* a plain permutation though: the histogram of the
  decoded bytes differs from the histogram of the input, so the stage transforms the values
  as well (it reorders by 2-byte context and applies a delta/order transform; the encoder
  contains a chi-square analysis that picks the delta order, and the "column" variant is
  method A). The decoder side rebuilds a permutation table from the byte histogram and
  walks a chain: `Block[cnt[src[i]]++] = i`, `dest[k] = src[Block^k(start)]`. This is
  implemented but does **not** yet reproduce the original order.
  Consequence: the *index* of a compressed archive still decodes to garbage, so the tool
  can list/extract stored archives but not read the index of compressed ones.
  The encoder side (`sub_428270`, ~440 lines of decompiled C with chi-square analysis) is
  the place to look next; the `v96[]` array it fills is the permutation.
* **The CM literal coder diverges on multi-literal data.** The range coder, the gamma symbol
  coder and the pre-transform are all byte-exact verified; the context-mixing literal coder
  is right for a single literal but its model updates over a longer run are still off (an
  archive of 390 bytes of text decodes to the right length but the wrong bytes). Start from
  the "prepare" / "restore" passes over the order-1 model and the `pair[256*prev + node]`
  indexing.
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
| compressed index | blocked on the LZ-stage permutation (section 4) |
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

Two bugs that cost real time and are worth remembering:

* the CM coder's **context slot** is `BSR(state)`, and `BSR(0)` leaves the destination
  register untouched - the code pre-loads `1Fh`, so the answer is 31, not 0;
* the decompiled `sym()`/symbol decoder **loses a `break`** in one branch if you transcribe
  it carelessly, which turns a 2-level symbol into a 32-level runaway and desynchronises
  everything downstream.

---

## 7. Conventions

* The analysis files are third-party generated: do not reformat `dgcac.exe.c` or
  `dgcac.exe.lst`.
* `dgcunp.c` is C89 for MSVC 6 (`__int64`, no `//` comments, declarations at the top of a
  block); it must keep building with `cl` from VC98.
* Keep new findings in `NOTES-dgca-format.md` and update section 4 of this file when a stage
  of the codec is cracked.
