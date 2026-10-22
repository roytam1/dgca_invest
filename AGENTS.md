# AGENTS.md - DGC archiver (`dgcac.exe`) reverse engineering

Workarea for reverse engineering **DGCA / DGC Archiver v1.10** by SYN (Shin-ichi TSURUTA,
2000-2005) and writing an unpacker for the `.dgc` / `.dgcr` archives it produces.

```
dgcac.exe        the target (Win32 console, MSVC6, 2006-08-07)
dgcac.exe.lst    IDA disassembly listing (~5.3 MB)
dgcac.exe.c      Hex-Rays decompiled C (~1.0 MB, 462 functions)
dgcunp.c         unpacker / lister / repair tool written from this analysis
                 (MSVC6, C89)
NOTES-dgca-format.md   full format + codec + crypto specification
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
  (32-byte block header + stream A + stream B), `tag 2` COLUMNS (`size` = the stride, `size`
  `tag 1` blocks follow - the "column" method).
* Per-file index entry (64 B): `+00` CRC-32 of the file, `+04` attributes, `+08/+10` FILETIME
  create/modify, `+18` original size, `+20` "compressed" size, `+28` offset in the DATA
  payload.

---

## 4. The codec (SOLVED - byte exact)

The whole compression codec is cracked and verified against every archive in
the work area.  The details are in `NOTES-dgca-format.md` section 6; this is
the summary.

Pipeline (encoder side, from the disassembly of `sub_425600`):

```
[pre-transform] -> [LZ stage] -> [entropy coder] -> stream A
pre-transform model                        -> stream B
```

decoder side: `stream A -> entropy -> chain walk -> (pre-transform inverse | delta)`.

* **Range coder** - "carryless" variant.
  * encoder: `low=0, range=0x80000000`; emits `low>>23`, keeps 23 fraction bits, carry
    handled by a pending-`0xFF` counter; flush emits 5 more bytes.
  * decoder: **skip one byte** (the encoder's dummy byte), then `code = b>>1, range = 0x80`;
    renormalise `code = ((code<<1)|(prev&1))<<7 | (b>>1); range <<= 8`.
* **Symbol coding** (gamma) - verified line by line against `sub_427880` (encoder) and
  `sub_4271B0` (decoder): the number of "small branch" decisions = the value's bit length,
  then `len-1` raw bits (MSB first). 32-entry, 12-bit probability models initialised to 2048.
  * the decoder returns the LEVEL itself for the levels 0 and 1 (so the value 1 is one
    "continue" bit and no raw bits) - getting this wrong desynchronises everything.
* **CM literal coder** - order-1 (`lit[256]`) + order-2 (`pair[256*256]`) models mixed against a
  32-slot context table; the slot is `BSR(state)` and is **31 when the state is 0** (the encoder
  pre-loads `eax = 1Fh` before `bsr`). The literal is coded MSB first over a 9-bit tree:
  `node = 2*node + bit` (node starts at 1) and `value = 2*value + bit`, i.e. the first bit is the
  most significant.
  * the **prepare** pass walks the tree of the **previous byte** from the deepest node up:
    `node_k = (prev|0x100) >> k`, `bit_k = (prev|0x100) >> (k-1) & 1`; `lit[node]` is moved
    *toward* that bit by `((4096-lit) or lit) * scale >> 13` and **the scale of the next level
    is that magnitude (the delta), not the node** - the first scale is `0x2000`.
  * the **restore** pass walks the same nodes (bottom up) and writes
    `lit[node] = saved +/- (saved>>p_lit)` and `pair[cur*256+node] +/- (>>p_pairb)`.
  * the **pair** index is `prev*256+node` in the main loop and `cur*256+node` in the restore,
    the **run** index is `cur*32+value`.
  * the initial "previous byte" is 0xFF if the first byte of the block is 0 (the params' bit 0)
    and 0 otherwise.
* **Pre-transform** - LZ77 with an *implicit distance*: a 2-byte hash table maps
  `(prev byte, byte) -> last output position`; the distance is never transmitted, the
  decoder rebuilds the same table. `minmatch = 1 << this[14]`. Stream B carries
  `(literal run length, match length - minmatch) pairs; their sum is the original size.
* **LZ stage / chain walk** - the LZ stage is a *permutation* of its input; the decoder inverts
  it with the chain walk (`sub_428990`): the histogram of the token buffer -> the exclusive
  prefix sums -> `Block[cnt[src[i]]++] = i` -> `dest[k] = src[Block^k(start)]`, where
  **`start` = the block's `v22`** (the payload's +0x10).
* **Column method** (`tag 2` blocks) - the data is split into `stride` interleaved columns
  (column k = the bytes at k, k+stride, ...), every column is delta transformed (the order =
  the flags' bits 16..19) and compressed as its own tag 1 block; the decoder inverts the delta
  and de-interleaves the columns.
* **Block header** - `size` = the *original* size, `v7` = the size fed to the entropy coder
  (= the size of the pre-transform's output, the literal bytes). (Easy to mix up; `v7` is
  what the decoder must produce from stream A.)

*Proof*: the encoder in `cm.py` (scratch dir) re-encodes the real stream A byte for byte,
and `dgcunp.c` extracts every archive in the work area with all the file CRCs matching
the index (including `names.dgc` with 5981 entries and a compressed index + name list).

The traps that cost the most time (do not repeat them):

* the decoder's argument list is NOT the encoder's: in `sub_427260` the chain of the
  prepare/restore passes is **arg_20 = the previous byte** and arg_1C is p_ctx;
* the prepare pass's scale chain is the **delta** chain, not the node chain;
* the restore pass walks the previous byte's tree **from the deepest node up**;
* the gamma decoder returns the **level** for the levels 0 and 1;
* the initial previous byte is 0xFF if the params' bit 0 is set (the opposite way round
  desynchronises the coder);
* the IFDT blob of a compressed archive differs from the blob of the stored twin (the
  "compressed size" field) - comparing the two is a false oracle.

Still open: the match coder (`sub_427D60` / `sub_427640`, the params' bit 1 - not used by
any of the sample archives) and the encryption.


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
dgcunp.exe -R archive.dgcr           # repair it with its recovery data
dgcunp.exe -t                        # the crypto's self test
```

**Verification is the CRC-32 stored in the index**: every entry carries the CRC-32 of the
original file, so the unpacker can prove correctness without a reference copy.

Current state of `dgcunp.c`:

| area | status |
|---|---|
| chunk tree, both CRC-32s | working |
| `IARC`, `IFDT` (stored **and** compressed), `IFNM` (stored **and** compressed) | working |
| extract, stored archives | working - files byte-identical to the originals |
| extract, compressed archives (all modes) | working - every file's CRC-32 matches the index |
| solid mode / the column method | working |
| long UTF-8 names (> MAX_PATH) | working - the wide APIs with the `\\?\` prefix |
| the crypto of DGCA v1.10 (SHA-512, MT19937, PRNG, cipher, key derivation) | working - byte exact, verified against the original binary |
| the recovery data (`-R`): the parity table, the repair, the archive's CRC-32 | working - a damaged `.dgcr` is repaired and extracted without errors |
| encrypted archives | the crypto is known, the key material that the writer derives is not (see `NOTES-dgca-format.md` 8.7) |
| the match coder (the params' bit 1) | not implemented (unused by the sample archives) |

The regression test: extract every archive in the work area and check that
every file's CRC-32 matches the index:

```powershell
foreach ($a in Get-ChildItem *.dgc, *.dgcr) {
    & dgcunp.exe -o out\$($a.Name) $a.FullName | Select-String 'MISMATCH|cannot create|could not be'
}
```

Nothing may be printed (the `names.dgc` archive has 5981 entries with Japanese
file names, so the extraction takes a moment).

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
* the CM coder's prepare pass **keeps the node in the scale register** (`mov ecx, eax`)
  but only uses it for the next bit - the scale of the next level is the *delta* of the
  current level (`0x2000, delta0, delta1, ...`), not the node and not the product.

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
