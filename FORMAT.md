# The DGC / DGCA archive format

Specification of the archive format written and read by **DGCA / DGC Archiver
v1.10** (SYN, Shin-ichi TSURUTA, 2000-2005), reverse engineered from
`dgcac.exe` and verified against archives produced by the tool itself.

Everything in this document was checked against real bytes: the container
layout by parsing the archives, the index and name blobs by comparing a stored
and a compressed archive of the same tree, the codec by re-encoding the real
streams byte for byte, and the crypto by decrypting real encrypted archives.
See section 9 for the verification summary.

Notation: all integers are little endian. `u8`, `u16`, `u32`, `u64` are
unsigned. `CRC-32` is the zlib CRC-32 (reflected, polynomial `0xEDB88320`,
initial value `0xFFFFFFFF`, final xor `0xFFFFFFFF`). A `FILETIME` is a Windows
64-bit count of 100 ns intervals since 1601-01-01. An offset is a byte offset
unless it says otherwise. `ceil(x)` rounds up.

---

## 1. Container: a tree of chunks

A DGC file is a tree of chunks. Every chunk starts with a 32-byte header:

| offset | size | field | value / meaning |
|---|---|---|---|
| `+0x00` | 4 | `id` | `DGCA` `DATA` `INFO` `IARC` `IFDT` `IFNM` `DGCC` `DGCR` `DGCD` `DFDT` |
| `+0x04` | 4 | `hdr_size` | always `0x20` |
| `+0x08` | 4 | `payload_size` | the number of bytes that follow the header |
| `+0x0C` | 4 | reserved | always `0` |
| `+0x10` | 4 | `flags` | `1` on `DGCA`, `DGCD`, `DGCR` and on the archive's `INFO`; `0` elsewhere |
| `+0x14` | 4 | `align` | always `0x10` |
| `+0x18` | 4 | `crc_payload` | CRC-32 of the `payload_size` payload bytes |
| `+0x1C` | 4 | `crc_header` | CRC-32 of the 32 header bytes with this field set to zero |

A chunk whose payload is itself a sequence of chunks is a *container*:

```
DGCA                       the archive
|-- DATA                   the file data
|   `-- DGCC x1..n         one data record per block (see section 3)
`-- INFO                   the metadata
    |-- IARC               80-byte fixed archive index
    |-- IFDT -> DGCC       the per-entry index table
    `-- IFNM -> DGCC       the name list
```

`IFDT` and `IFNM` each hold one `DGCC` child whose payload is the actual blob;
that child is a block stream (section 3), so the index table and the name list
may be stored or compressed like any other data.

The children of a container are concatenated back to back. Every child record
(its 32-byte header plus its payload) is zero padded to the next 16-byte
boundary, and the padding is counted in the parent's `payload_size`. The root
`DGCA`'s payload therefore reaches to the end of the file.

The `flags` field is informational; readers dispatch on the `id`. The tool sets
`flags = 1` on `DGCA`, `DGCD`, `DGCR` and on the archive's `INFO` (the one that
holds `IARC`/`IFDT`/`IFNM`); the `INFO` of a `.dgd` part and of a `DGCR` is a
leaf chunk with `flags = 0`.

### 1.1 Checksums

Both CRCs are computed over the bytes as stored, i.e. **after** encryption.
For an encrypted archive the `DGCC` header and payload are encrypted (section
6.1), so their CRCs are CRCs of the ciphertext. The `crc_header` is computed
with its own field zeroed, so it can be filled in last.

A reader should verify the payload CRC before decoding a chunk and the header
CRC before trusting the sizes. A mismatch means the file is damaged (the
recovery data of section 5 may be able to repair it).

---

## 2. The archive (`DGCA`)

### 2.1 `DATA`

The `DATA` payload is a sequence of `DGCC` records, each with a 32-byte chunk
header and a block-stream payload (section 3). Decoding every record in order
and concatenating the results yields the *data stream*: the file contents in
index order, with no separators. Directories contribute nothing.

The tool's writer produces:

* **solid mode** (the default): one `DGCC` per group of files. The groups are
  the consecutive files with the same extension (the tool sorts the entries by
  extension and name before writing, see 2.6). One record's decoded output is
  the concatenation of all files in its group.
* **each-file mode** (`-f`): one `DGCC` per file.
* **stored mode** (`-n`): one `DGCC` per file, each payload a single tag 0
  block. The solid grouping is not used.

The grouping is a writer heuristic, not part of the format: any grouping of
the files is valid as long as the concatenated data stream matches the index
order.

### 2.2 `IARC` (80 bytes)

| offset | size | field |
|---|---|---|
| `+0x00` | 4 | `flags`: bit 0 = encrypted, bit 1 = identity mode (`-i`: no timestamps) |
| `+0x04` | 4 | version, the ASCII text `" 001"` |
| `+0x08` | 8 | reserved, zero |
| `+0x10` | 8 | archive creation time (`FILETIME`, zero with `-i`) |
| `+0x18` | 8 | reserved, zero |
| `+0x20` | 8 | reserved, zero |
| `+0x28` | 8 | number of entries (files **and** directories) |
| `+0x30` | 8 | total uncompressed size (files only) |
| `+0x38` | 8 | index table size in bytes (`64 * entries`) |
| `+0x40` | 4 | length of the name blob in bytes |
| `+0x44` | 4 | reserved, zero |
| `+0x48` | 8 | reserved, zero |

In an encrypted archive the 48 bytes `+0x20..+0x4F` (the entry count, the total
size, the table size and the name length, plus the reserved fields) are
encrypted with key1 (section 6.6). The `flags` field stays in the clear.

### 2.3 `IFDT` - the index table

The `IFDT` chunk contains one `DGCC` child whose decoded payload is
`64 * entries` bytes. The entries are stored **transposed**: with `n` entries
and `c` in `0..63`, `blob[c * n + e]` is byte `c` of entry `e`. The blob is
compressed like any other data.

Entry layout (64 bytes):

| offset | size | field |
|---|---|---|
| `+0x00` | 4 | CRC-32 of the file contents (0 for a directory) |
| `+0x04` | 4 | Windows file attributes (`0x01` read-only, `0x02` hidden, `0x04` system, `0x10` directory, `0x20` archive) |
| `+0x08` | 8 | creation time (`FILETIME`, 0 with `-i`) |
| `+0x10` | 8 | last write time (`FILETIME`, 0 with `-i`) |
| `+0x18` | 8 | original size |
| `+0x20` | 8 | compressed size: the size of the file's `DGCC` record in each-file mode; the file's share of the solid record in solid mode (an estimate, see below) |
| `+0x28` | 8 | offset of the file's `DGCC` record inside the `DATA` payload |
| `+0x30` | 8 | offset of the file's data inside that record's decoded output (0 in each-file mode) |
| `+0x38` | 8 | reserved, zero |

The "compressed size" is cosmetic: in solid mode the tool apportions the
record's size over the files by their share of the block, so the value is only
an estimate. The last write time of a directory is its own timestamp. A file
of size 0 contributes no `DGCC` record at all (the `DATA` payload of an
archive of only empty files is empty) - its entry carries `coff = csize = 0`.

A reader that extracts sequentially (decode the whole `DATA` payload, then take
each entry's `original size` bytes in index order) does not need `+0x28` or
`+0x30`. A reader that extracts at random uses them: find the record at
`+0x28`, decode it, and take the data at `+0x30`. Both layouts occur in real
archives, so a random-access reader must handle a record that holds several
files.

### 2.4 `IFNM` - the name list

The `IFNM` chunk contains one `DGCC` child whose decoded payload is a sequence
of

```
u32 length, then `length` bytes of UTF-8
```

with no terminator. The names use backslashes as separators and are relative to
the directory the archive was created from. The archived root directory is the
first entry. The tool writes the names as UTF-8 regardless of the code page
(`-u` only affects the listing output).

### 2.5 Directories and attributes

Directories are ordinary entries with the attribute bit `0x10`, size 0, no
data, and a CRC of 0. They exist so the tree can be recreated. A directory's
name is the full path of the directory (e.g. `coltest\v1`), and the entry order
is the directory order (parents before children).

### 2.6 Entry order

The entries are in the order of the data stream, and the tool writes them
grouped by extension: directories first (by full path), then the files sorted
by extension (case-insensitive, no extension first) and then by the file name
(the part after the last backslash; ties keep the directory-walk order). This
is the writer's ordering, not a requirement of the format; a reader must not
assume it, only that the data stream follows the index order.

### 2.7 Identity mode

With `-i` the tool zeroes the archive timestamp and the per-file **creation**
times, keeps the per-file last-write times, and sets `IARC.flags` bit 1.
(Everything else is unchanged. Combined with `-n` this makes the index blob
byte-for-byte deterministic for an unchanged tree, which is how the index
format was verified. An earlier draft said `-i` zeroed the per-file
timestamps too - the oracles show the modification time is kept.)

---

## 3. The data records (`DGCC`)

A `DGCC` payload is a stream of blocks. Every block starts with

```
u32 tag, u32 size
```

| tag | meaning |
|---|---|
| 0 | **store**: `size` raw bytes follow |
| 1 | **compressed**: a 32-byte block header, then stream A (`lenA` bytes), then stream B (`lenB` bytes) |
| 2 | **columns**: `size` is the *stride*; `size` tag 1 blocks follow (the column method, section 4.10) |

A tag 1 block header (offsets relative to the tag, i.e. the start of the
block):

| offset | size | field |
|---|---|---|
| `+0x00` | 4 | tag = 1 |
| `+0x04` | 4 | `size`: the original (uncompressed) size of the block |
| `+0x08` | 4 | `flags` (see below) |
| `+0x0C` | 4 | `params` (see below) |
| `+0x10` | 4 | `v22`: the chain-walk start index |
| `+0x14` | 4 | `v7`: the size of the token buffer, i.e. the number of bytes the entropy coder produces |
| `+0x18` | 4 | `lenA`: the length of stream A |
| `+0x1C` | 4 | `lenB`: the length of stream B (the model stream) |

`v7` is not the original size: it is the size of the pre-transform's output
(the literal bytes) for a block with the pre-transform, and the column length
for a column block. The original size is `size`.

### 3.1 The block flags

| bits | meaning |
|---|---|
| 0 | a coder-object default the tool sets on every compressed block. The decoder loads it into the coder object but never uses it for the stream; `dgcpk` sets it too |
| 1 | the LZ stage is present: apply the chain walk to the token buffer (section 4.8) |
| 2 | the pre-transform is present: stream B describes the LZ77 matches (section 4.7) |
| 16..19 | the delta order (0, 1 or 2) of a column block (section 4.9) |

A normal block has bit 2 set (and usually bit 1 too). A column block has bit 2
clear, bits 16..19 hold its delta order, and bit 1 says whether the column's
LZ stage is present. A block with bit 2 clear and order 0 is a plain CM-coded
block (no pre-transform, no delta).

The tool sets bit 0 on every block it writes (it is the coder object's
"compressed" marker, `this[4]`); `dgcpk` sets it as well.

### 3.2 The block parameters

The `params` word configures the entropy coder:

| bits | meaning |
|---|---|
| 0 | the initial "previous byte" is `0xFF` when set, `0` otherwise (must match how stream A was coded). The tool sets it when the first byte of the **staged** token buffer is 0 (after the LZ stage, if any - see the trap in section 9) |
| 1 | 1 = the match coder, 0 = the literal coder (section 4.5) |
| 4..7 | `p_lit`: the shift of the literal model |
| 8..11 | `p_pairb`: the shift of the restore pass's pair model |
| 12..15 | `p_pair`: the shift of the main pair model |
| 16..19 | `p_ctx`: the shift of the context weight |
| 20..23 | `p_run`: the shift of the run model |
| 24..27 | the pre-transform's minimum match exponent: `minmatch = 1 << value` |
| 28..31 | the model stream's shift (`p_lzsh`) |

The tool re-tunes the shifts per block from the staged token's byte statistics
(sub_4244E0, called after the LZ stage in sub_425600 - see 4.11), and always
writes `minmatch = 64` and `p_lzsh = 4`. The common words are
`0x46453320` (literal coder, the `r > 0.6` row) and `0x46557760` (the
default row) for normal blocks; column sub-blocks use the second tuning set
(`0x46443320` / `0x46443322` for the very uniform columns).

### 3.3 Decoding a payload

```
data = empty
o = 0
while o + 8 <= payload_size:
    tag  = u32 at o
    size = u32 at o + 4
    if tag == 0:
        append payload[o+8 .. o+8+size]
        o += 8 + size
    elif tag == 1:
        decode_block(payload + o, size) -> bytes
        append bytes
        o += 32 + lenA + lenB
    elif tag == 2:
        cols = []
        oo = o + 8
        for k in 0 .. size-1:
            cols[k] = decode_block(payload + oo, its size)
            oo += 32 + its lenA + its lenB
        total = sum of the column lengths
        out = zeroed buffer of total bytes
        for k in 0 .. stride-1:
            for i in 0 .. len(cols[k])-1:
                out[i * stride + k] = cols[k][i]
        append out
        o = oo
    else:
        error
```

`decode_block` is

```
token = entropy_decode(params, A, lenA, v7)        # v7 bytes
if flags & 2:  token = chain_walk(token, v7, v22)  # section 4.8
if flags & 4:  out = pretransform_inverse(token, B)  # section 4.7
else:          out = inverse_delta(token, order)     # section 4.9
```

and the result is `size` bytes (the pre-transform's inverse produces `size`
bytes; a plain block copies `v7` bytes, which equals `size`).

### 3.4 Limits a reader must enforce

The format has no explicit limits, but a decoder must reject, without reading
out of bounds:

* a chunk payload size larger than the bytes left in the file;
* a `lenA`/`lenB` that does not fit in the block;
* a `v7` larger than `size` (the token buffer cannot exceed the block);
* a column stride of 0 or larger than the block payload can hold.

`dgcunp.c` implements these checks; the crafted cases are in the scratch area
(`colwork/fuzz`).

---

## 4. The compression codec

The codec is fully specified below; the reference implementation is
`dgcunp.c` (decoder) and `dgcpk.c` (encoder). The encoder reproduces real
streams byte for byte.

### 4.1 Pipeline

Encoder (sub_425600):

```
[pre-transform] -> [LZ stage] -> [entropy coder] -> stream A
pre-transform model                              -> stream B
```

Decoder (sub_425A50):

```
stream A -> entropy decode -> chain walk -> (pre-transform inverse | delta)
```

The pre-transform (LZ77 with an implicit distance) turns the data into the
literals (`v7` bytes) and the model stream B. The LZ stage is a permutation of
the literals. The entropy coder codes the permuted literals into stream A.

### 4.2 The range coder

A "carryless" range coder. The encoder (sub_426F80) and decoder (sub_427110)
are exact inverses; the first byte of stream A is a dummy byte.

Decoder state: `code`, `range`, `prev` (the last byte read).

```
init(buf, len):
    pos = 1                       # skip the encoder's dummy byte
    b = buf[pos++]                # or 0 past the end
    prev = b
    code = b >> 1
    range = 0x80

renorm():
    while range <= 0x800000:
        code = ((code << 1) | (prev & 1)) << 7
        b = next_byte()
        prev = b
        code |= b >> 1
        range <<= 8
        if range == 0: range = 0x800000   # the binary's guard

raw_bit():
    renorm()
    half = range >> 1
    if code < half: range = half; return 0
    else:           code -= half; range -= half; return 1
```

Encoder state: `low`, `range`, `byte`, `pending`.

```
init: low = 0, range = 0x80000000, byte = 0, pending = 0

emit():
    v = low
    if v >= 0x7F800000:
        if v >= 0x80000000:                 # carry
            out(byte + 1); out 0x00 pending times; pending = 0
            byte = v >> 23
        else:                               # a run of 0xFF bytes
            pending++
    else:
        out(byte); out 0xFF pending times; pending = 0
        byte = v >> 23
    low = (v & 0x7FFFFF) << 8

renorm():
    while range <= 0x800000: emit(); range <<= 8

flush():
    renorm(); emit 5 times
```

The encoder writes the dummy byte through the first `emit` (its `byte` starts
at 0), which is why the decoder skips one byte.

### 4.3 The symbol coder

Values are coded "gamma style" with 32-entry, 12-bit probability models
initialised to 2048. `probs[base + v]` is P(bit 0) for level `v`; the value's
bit length is the number of "continue" decisions.

Decoder (`rng_sym(probs, base, count, shift)`):

```
v = 0
loop:
    renorm()
    p = probs[base + v]
    bound = p * (range >> 12)
    if code < bound:                  # bit 0: "continue"
        range = bound
        probs[base + v] += (4096 - probs[base + v]) >> shift
        v++
        if v >= count: break
    else:                             # bit 1: "stop"
        range -= bound; code -= bound
        probs[base + v] -= probs[base + v] >> shift
        break
if v <= 1: return v                   # the levels 0 and 1 are the value itself
return (1 << (v - 1)) + raw_bits(v - 1)
```

The `raw_bits(n)` are `n` raw bits, most significant first. Note that a value
of 1 is one "continue" decision and no raw bits; the decoder returns the level
itself for levels 0 and 1. Getting this wrong desynchronises everything after
the first symbol.

Encoder (`gamma_put`): for `i = 0, 1, ...` code a "continue" while
`value >> i != 0`, then a "stop", then the `i - 1` low bits of `value` (most
significant first). The probability updates are the same as the decoder's.

### 4.4 The literal coder (the context-mixing coder)

Tables (allocated per block, all initialised to 2048):

| table | size | meaning |
|---|---|---|
| `lit[256]` | 256 | order-1 model: P(0) for the node of the current byte's tree |
| `ctx[32]` | 32 | the mixing weights, one per context slot |
| `pair[256*256]` | 65536 | order-2 model: `pair[prev*256 + node]` |
| `run[32*256]` | 8192 | the run-length model, `run[byte*32 + level]` |

The literal is coded MSB first over a 9-node binary tree:

```
node = 1
for bit_index in 7 .. 0:
    pr = (w * lit[node] + pair[prev*256 + node] * (4096 - w)) >> 12
    code the bit with pr (the range coder)
    node = 2*node + bit
```

where `w = ctx[bsr(state)]` and `bsr(state)` is the index of the highest set
bit of `state`, **31 when state is 0** (the binary pre-loads `0x1F` before the
`BSR` instruction, which leaves the register untouched for a zero input).

The state is a 32-bit confidence product, updated after every literal:

```
v58 = product of lit[node]  (or 4096-lit[node]) over the coded bits
v57 = the same for pair[prev*256+node]
state = (w*v58 + (4096-w)*v57) >> 12
if v58 < v57:  ctx[slot] -= ctx[slot] >> p_ctx
if v58 > v57:  ctx[slot] += (4096 - ctx[slot]) >> p_ctx
```

The pair model is updated in the main loop with `p_pair`:

```
bit 0: pair[...] += (4096 - pair[...]) >> p_pair
bit 1: pair[...] -= pair[...] >> p_pair
```

The literal model is **not** updated in the main loop; it is handled by the
prepare and restore passes:

**Prepare** (before the bits), walks the tree of the *previous* byte from the
deepest node up:

```
chain = prev | 0x100
scale = 0x2000
for k = 0 .. 7:
    node = chain >> 1
    bit  = chain & 1
    saved[k] = lit[node]
    if bit: d = ((4096 - lit[node]) * scale) >> 13; lit[node] += d
    else:   d = (lit[node] * scale) >> 13;          lit[node] -= d
    scale = d
    chain = node
```

The scale of the next level is the *magnitude of this level's update* (the
delta), not the node value and not the product.

**Restore** (after the bits), walks the same nodes and writes them back:

```
chain = prev | 0x100
for k = 0 .. 7:
    node = chain >> 1
    bit  = chain & 1
    p = saved[k]
    if bit:
        lit[node] = p - (p >> p_lit)
        pair[cur*256 + node] -= pair[cur*256 + node] >> p_pairb
    else:
        lit[node] = p + ((4096 - p) >> p_lit)
        pair[cur*256 + node] += (4096 - pair[cur*256 + node]) >> p_pairb
    chain = node
```

`cur` is the byte that was just coded. Note the restore pass uses
`pair[cur*256 + node]`, while the main loop uses `pair[prev*256 + node]`.

**Run model**: after each literal byte, the coder codes a run length with the
run model at `run[byte*32 + level]`, shift `p_run`, 32 levels, and the byte is
repeated `run + 1` times (the literal itself plus the run). The run is only
used by the literal coder, not by the match coder.

**Initial previous byte**: `prev = 0xFF` if `params` bit 0 is set, else `0`.

### 4.5 The match coder

`params` bit 1 selects a second literal coder (sub_427D60 / sub_427640): the
same 9-node tree and the same `lit`/`pair`/`ctx` tables, but without the
prepare and restore passes and without the run model. Each bit:

```
pr = (w * lit[node] + pair[prev*256 + node] * (4096 - w)) >> 12
code the bit
if bit 0: lit[node] += (4096 - lit[node]) >> p_lit;  pair[...] += (4096 - pair[...]) >> p_pair
if bit 1: lit[node] -= lit[node] >> p_lit;            pair[...] -= pair[...] >> p_pair
v58/v57 products as in 4.4, state and ctx updated as in 4.4
```

The tool uses it for uniform data (the `spread(delta1) < 5` case of 4.10);
main blocks never set it in the reference archives (the pre-transform path
always uses the literal coder).

### 4.6 Stream A / the token buffer

The entropy coder's output is the token buffer (`v7` bytes): the literal coder
produces one byte per literal plus its run, the match coder one byte per
literal. The token buffer is what the LZ stage permutes and what the
pre-transform's inverse consumes.

Note the direction in the ENCODER (sub_425600): the pre-transform runs
FIRST (vtable+56, producing the literals and stream B), then the LZ stage
permutes the literals (sub_428270), then the tuning (sub_4244E0) and the
entropy coder run on the permuted literals. The per-block byte statistics
are therefore taken from the STAGED token, not from the raw data.

### 4.7 The pre-transform (LZ77 with an implicit distance)

The encoder (sub_424C30 / sub_424910) turns the data into the literal bytes and
the model stream B. The match distance is never transmitted: both sides keep a
65536-entry table keyed by the two-byte sequence

```
key = (the previous byte << 8) | the current byte
```

The table starts at `0xFFFFFFFF` (no position). The minimum match length is
`minmatch = 1 << ((params >> 24) & 0xF)`, which the tool always writes as 64.

Encoder (per position):

```
key = (prev_byte << 8) | data[pos]
cand = table[key]
if cand != -1 and cand < pos and data[cand] == data[pos]:
    distance = pos - cand
    length = 1
    while pos + length < size and length < distance and
          data[cand + length] == data[pos + length]:
        length++
    if length >= minmatch:
        emit a literal run of `runlen`, then (length - minmatch)
        advance pos by length, updating the table for every byte
        runlen = 0
        continue
emit data[pos] as a literal; runlen++; advance pos, updating the table
```

The match length is **not** capped by the distance (an earlier draft said it
was - that is wrong).  The extension loop of sub_424C30 only bounds on the
block end: it runs while `data[cand + l] == data[pos + l]`, up to
`pos + l == size`.  A distance-1 match therefore chases the write position,
and the decoder's forward copy (`src++` per byte) handles it - each byte it
reads was written by the previous iteration (`c_A4096.dgc`: 3 literals and
one match of 4093 with distance 1).  The candidate is always a previous
position (`tbl[key]` is written only after the read), so `cand < pos`.
At the end the remaining literal run is emitted (even when it is 0), so stream
B always ends with a literal-run symbol.

The table is updated for every output byte:

```
table[key] = position
key = ((key & 0xFF) << 8) | byte
```

Stream B is coded with its own range coder and two 32-entry symbol models
(literal runs and match lengths), both with shift `p_lzsh`; the match length is
coded as `length - minmatch`.

Decoder (sub_424910): the inverse; see `pretransform_inverse` in `dgcunp.c`:

```
while out < size:
    run = sym(model1)
    write run literal bytes from the token buffer, updating the table
    if out >= size: break
    len = minmatch + sym(model2)
    src = table[key]
    if src != -1:
        copy len bytes from out[src], updating the table
```

The copy is forward (`src++` per byte), so overlapping matches would decode
too; the tool's encoder never writes them.

### 4.8 The LZ stage (the chain walk)

The LZ stage is a permutation of the token buffer. The decoder inverts it with
the *chain walk* (sub_428990):

```
cnt[256] = histogram of the token buffer
cnt[]    = the exclusive prefix sums
Block[cnt[src[i]]++] = i        # the positions grouped by byte value
dest[k] = src[Block^start]      # start = the block's v22
```

where `^` is function application: `a = start; for k: a = Block[a]; dest[k] =
src[a]`.

The encoder (sub_428270) computes the token buffer as the fixed point of this
iteration:

```
rank[i] = the stable rank of data[i] by value
repeat:
    a[k] = rank[(k + 1) mod n]
    for every value group, order its members by a[] and give them the ranks
    base[value] .. base[value] + cnt[value] - 1
until nothing changes
token[a[k]] = data[k]
start = rank[0]
```

The binary computes the same ranks with an LSD radix sort over the 2-byte
context plus a cycle merge; the token is the BWT column of the literal
buffer and `start` is its primary index.  `dgcpk` reproduces it with the
suffix-array **doubling** algorithm on the cyclic rotations (exact, stable
on ties - equal rotations order by position, which puts rotation 0 first
among its ties and fixes `start` - and always convergent, O(n log^2 n)).

The LZ stage is **not** optional and is never weighed against the plain
stream: every pre-transform block of the tool carries flags bit 1 (the
`v22` may be 0 when the permutation is the identity, e.g. the 3-byte token
`AAA` of `c_A4096.dgc`).  A writer that cannot compute the fixed point may
omit the stage (bit 1 clear, plain stream) - the decoder accepts both - but
that output is not byte-compatible with the tool.

### 4.9 The delta transform (column blocks)

A column block stores its column delta transformed before compression. The
order is in the flags' bits 16..19:

```
order 1: d[i] = s[i] - s[i-1]        (s[-1] = 0)
order 2: d[i] = d1[i] - d1[i-1]      (d1 = the order-1 delta)
```

The inverse (the decoder) adds back:

```
order 1: s[i] = s[i-1] + d[i]
order 2: apply the order-1 inverse twice
```

All arithmetic is modulo 256.

### 4.10 The column method (tag 2)

When the data is "column friendly" the tool splits the block into `stride`
interleaved columns and compresses each one separately:

```
column k = the bytes at the positions k, k + stride, k + 2*stride, ...
```

Every column is delta transformed (4.9), optionally LZ staged, and compressed
as its own tag 1 block. The columns may have different flags and parameters.
The decoder decodes every column and de-interleaves:

```
data[i * stride + k] = column_k[i]
```

When the size is not a multiple of the stride the last row is short, so the
columns have different lengths (the tool writes e.g. stride 12 for a 131072
byte block: eight columns of 10923 bytes and four of 10922). A decoder must use
each column's own length, not `total / stride`.

The writer's heuristics (verified against sub_423F90 and sub_424FE0; the
packer reproduces all of them byte for byte):

* **the lag test** (sub_423F90, blocks of at least 0x400 bytes): the mean
  `|data[i] - data[i-d]|` for every lag `d = 1..16`; `best` = the argmin
  lag, `avg` = the mean of the 16 means.  When `best > 1` the **chain
  test** runs first: for every phase offset `s` in `[best, 2*best)` the
  mean of the chain `|data[s+k*best] - data[s+(k-1)*best]|` is computed,
  and `worst*2 > best*3` sets the column flag.  The best chain mean then
  **replaces** the plain lag mean, and the flag is set by `best*4 < avg`
  and cleared again by `2*best >= avg`.  (pcm16.bin of the `all.dgc`
  oracle: the plain mean 38.2 fails both tests, the best chain mean 4.7
  passes both - the replacement is what makes the columns fire.)
* **stride**: the argmin lag (1..16).  The columns are used when the flag
  is set - the column block is **never** compared with the plain block
  (repeat.txt: the tool writes 3 columns of 128 bytes where a plain block
  would have been 56).
* **delta order** of every column, from the "spread" of its byte histogram:
  `spread(x) = sqrt(sum_v (cnt_v*256/n - 1)^2 / 255)`;
  order 0 if `spread(col) * 1.2 > spread(delta1)`;
  else 1, and 2 when `spread(delta2) > 1.1 * spread(delta1)` and
  `spread(delta2) * spread(col) * 1.8 > spread(delta1)^2`.
* **LZ stage**: on for order 0 and 1 when `spread(delta1) >= 1`, off for
  order 2 and when `spread(delta1) < 1`.
* **match coder**: on when `spread(delta1) < 5` (the uniform PCM columns).
* **store fallback**: applies to the column block as well - the coded size
  (`lenA + lenB + 32` of the whole record) is compared with `size + 8`.

### 4.11 Block parameters the tool writes

The tool re-tunes the shifts per block with sub_4244E0 **after the LZ
stage**, from the "same byte" ratio `r` of the STAGED TOKEN buffer (the
first byte counts when it is 0 - the binary's comparison byte starts at 0).
This is why a text block whose raw bytes almost never repeat still gets the
`r > 0.6` row: the BWT clusters the bytes into runs.  The compressor
object's constructor starts at `p_lit 2, p_pairb 4, p_pair 3, p_ctx 6,
p_run 4`, and the tuning overrides them in this order:

```
default:            p_lit 6, p_pairb 7, p_pair 7, p_ctx 5, p_run 5
r > 0.03:           p_lit 5, p_pairb 6, p_pair 6, p_run 5
r > 0.05:           p_lit 4, p_pairb 5, p_pair 5, p_run 5
r > 0.2:            p_lit 3, p_pairb 5, p_pair 4, p_run 4
r > 0.4:            p_lit 2, p_pairb 4, p_pair 4, p_run 4
r > 0.6:            p_lit 2, p_pairb 3, p_pair 3, p_run 4
```

When the coder's `this[15]` flag is set - the **column sub-blocks** - a
second set applies: `p_run 4` and `p_ctx 5`, then

```
r > 0.05:           p_lit 4, p_pairb 5, p_pair 5, p_ctx 5, p_run 4
r > 0.6:            p_lit 3, p_pairb 4, p_pair 4, p_ctx 4, p_run 4
r > 0.9:            p_lit 2, p_pairb 3, p_pair 3, p_ctx 4, p_run 4
```

The common result is `0x46453320`: `p_lit 2, p_pairb 3, p_pair 3, p_ctx 5,
p_run 4, minmatch 6, p_lzsh 4`. These are tuning values, not format
requirements: any shifts work as long as the encoder and the params agree.

---

## 5. Recovery data (`DGCR`)

A `DGCR` chunk may be appended to an archive (extension `.dgcr`) or to a
spanning file part (`.dgdr`). It holds a 2-dimensional parity table over the
bytes in front of it, encrypted with a fixed key.

### 5.1 Structure

```
DGCR  (flags = 1)
|-- INFO  (48 bytes)   the parameters
`-- DATA              the parity table
```

`INFO` payload:

| offset | size | field |
|---|---|---|
| `+0x00` | 4 | magic, `0x43` |
| `+0x04` | 4 | length of the parity table in bytes |
| `+0x08` | 8 | reserved, zero |
| `+0x10` | 4 | `cols` (always 256) |
| `+0x14` | 4 | `rows` |
| `+0x18` | 4 | `pages` |
| `+0x1C` | 4 | reserved, zero |
| `+0x20` | 8 | reserved, zero |
| `+0x28` | 4 | the file offset of the `DGCR` chunk |
| `+0x2C` | 4 | CRC-32 of the file bytes in front of the `DGCR` chunk |

The parity table's length is

```
4 * rows * (cols + pages + 1)
```

with `cols = 256`. The parameters for a payload of `size` bytes at recovery
level `n` (1..9, the `-rn` switch) are

```
rows  = max(4, ceil(size / ((cols >> (n-1)) * 1024)))
pages = ceil(size / (rows * 1024))
if pages == 1: rows = ceil(size / 1024)
```

The redundancy is about `1 / pages`.

### 5.2 The parity table

The covered bytes (the archive, or the part's bytes) are seen as a matrix of
`pages x rows x cols` 4-byte little-endian words, zero padded to
`rows * cols * pages` words. Three parts follow each other:

* **part 1** (`rows * cols` words): for every (row, column), the XOR of that
  word over all the pages.
* **part 2** (`pages * rows` words): for every (page, row), the XOR of the
  words of all the columns of that row.
* **part 3** (`rows` words): for every row, a CRC-32 over the row's words in
  page 0, then page 1, ..., page `pages-1` (the same row index in every page),
  each word serialised little endian, i.e. the bytes of the row as they appear
  in the file. The CRC is a single running CRC-32 over the concatenation of
  those rows.

The table is encrypted with the fixed key of section 6.5 (the password
`SecureCryptograph` and 8 zero bytes), one cipher over the whole table.

### 5.3 Repair

Parts 1 and 2 are a two-dimensional parity code: a damaged word makes its
column parity (part 1) and its row parity (part 2) mismatch. The column parity
gives the word (`parity XOR the other pages' words`), and the row parity says
which page of the column was damaged. The final check is the CRC-32 in the
`INFO` chunk. A decoder can repair up to one damaged word per row and column
region; more damage makes the choice ambiguous.

The v1.10 tool itself **never repairs**: it writes the recovery data, and
`dgcac k` only compares the CRC. `dgcunp -R` implements the repair and writes
`<file>.repaired`.

---

## 6. Encryption

The tool encrypts archives (`-p<password>` / `-k<keyfile>`) and spanning files.
The cipher, the PRNG, the SHA-512 variant and the key schedule below are
implemented in `dgcunp.c` and verified byte for byte against the original
binary.

### 6.1 Scope

For an archive:

* every `DGCC` chunk (the 32-byte header **and** the payload) is encrypted as
  one unit: the header with key1, the payload with key2. The chunk's id and
  size are encrypted too, so a reader must decrypt a `DGCC` header before it
  can walk the tree;
* the `IARC` payload's 48 bytes at `+0x20` are encrypted with key1, and
  `IARC.flags` bit 0 is set;
* the outer chunk headers (`DGCA`, `DATA`, `INFO`, `IARC`, `IFDT`, `IFNM`) are
  not encrypted; their CRCs are computed over the ciphertext;
* the `DGCR` chunk is not encrypted, but it covers the archive as stored (the
  encrypted bytes), so the recovery check runs before decryption.

For a `.dgd` part, key1 encrypts the 92 bytes of the `INFO` material at `+4`
(the flags at `+0` stay clear), and key2 encrypts the name area (`+0x60` to
the end of the `INFO` payload), the `DFDT` payload and the `DATA` payload.

### 6.2 The cipher

A self-inverse XOR stream with one feedback byte:

```
encrypt:  in = buf[i]; k1 = prng(); k2 = prng()
          buf[i] = in ^ k1 ^ k2;  feedback = in ^ k1
decrypt:  in = buf[i]; k1 = prng(); k2 = prng()
          buf[i] = in ^ k1 ^ k2;  feedback = in ^ k2
```

The feedback byte is consumed by the next `prng()` call.

### 6.3 The PRNG

```
prng():
    if index == 0 or counter < 64:
        tmp[128] = 32 raw MT19937 output words (little endian)
        keybuf = state of SHA-512 after absorbing tmp, then the rolling
                 state (128 bytes), read WITHOUT finalising
        if counter < 64: counter++
    fb  = feedback
    ret = keybuf[index] ^ fb
    rolling[index]      = fb
    rolling[64 + index] = fb      # the binary's scratch buffer overlaps
    feedback = 0
    index = (index + 1) & 0x3F
    return ret
```

The hash object is not reset between derivations: each one absorbs another
256 bytes into the same running hash.

The rolling state is 128 bytes and the feedback byte is written to *two*
places: `rolling[index]` and `rolling[64+index]` (the binary's "scratch"
buffer is the upper half of the rolling state). The hash therefore sees every
feedback byte twice. This is essential; getting it wrong breaks the stream
from the third `prng()` call.

The first 64 calls re-derive the key buffer on every call (the first 32 data
bytes); after that the key buffer is re-derived every 64 calls (when `index`
wraps to 0).

The MT19937 is seeded directly (`state[i] = key[i % keylen]` for
`i = 0..623`), twisted with the standard twist, and the tempered words are
copied to a separate output array (the state keeps the untempered values, so
the output sequence is the standard MT19937's).

### 6.4 SHA-512

The hash is standard SHA-512 over the message bytes, with one difference in
the output: the 64-byte state is taken as the digest with every 8-byte group
reversed (equivalently, each 64-bit state word serialised little endian).

```
state of SHA-512("abc") =
    ba7a6193a135afdd 314120ae497341cc a27ea9894efae612 9ad3554be6ee9e0a
    a8c14f272a999221 bdebfea3233cba36 0ee83c6423444d45 9fa44ca54fc99a2a
```

The hash object can be read at any time (the state, without padding) and can
continue absorbing after a finalised digest; the key schedule relies on both.

### 6.5 The key schedule

For a material `M` and a password `P`:

```
H0 = SHA-512(M | P)                     # finalised
hist = empty
for i = 0 .. 38:
    s = state(H_i)                      # 64 bytes, little endian per word
    hist += s
    H_{i+1} = state of the running hash after absorbing s twice, starting
              from state H_i (no padding, no finalise)
seed[0] = 0xFFFFFFFF
seed[1..623] = the first 623 little-endian dwords of hist
MT19937 seeded with `seed`
```

The hash object is not reset during the 39 rounds (the updates accumulate); it
is reset at the end so the PRNG's hash starts from the initial state.

The fixed key of the recovery data uses `M` = 8 zero bytes and
`P` = `"SecureCryptograph"`. Its first 64 keystream bytes (the encryption of 64
zero bytes) are

```
590661c76a2ad275dd11187646cd059ede7a6c1e36db71e6a7b326b083c2b603350b64663ba46dbf9f77f88b528bc9d29927441709033aad5da5cbf58030f470
```

which `dgcunp -t` prints as a self test.

### 6.6 The two archive keys

An encrypted archive has no key material of its own; both keys derive from the
password alone:

```
key1 = the key schedule with M = 8 zero bytes, P = password
key2 = the key schedule with M = the 32-byte PLAINTEXT header of the DGCC
       record, P = password
```

The writer encrypts each `DGCC` header with key1 and its payload with key2, so
key2 depends on the plaintext header of the record it protects. The `IARC`'s
48 bytes at `+0x20` use key1.

### 6.7 The spanning-file keys

```
key1 = the key schedule with M = 8 zero bytes, P = password
       -> the 92 bytes of the INFO material at +4
key2 = the key schedule with M = the PLAINTEXT 96-byte material (INFO +0..+0x5F),
       P = password
       -> the name area (INFO +0x60), the DFDT payload and the DATA payload
```

Each of those three is encrypted with its own cipher object (its own key
stream). The material used for key2 is the plaintext one: the reader decrypts
the material with key1 first, then derives key2.

### 6.8 Key files

With `-k<file>` the password is the 128-character lowercase hex text of the
standard SHA-512 digest of the key file's content:

```
P = hex(SHA-512(file contents))     # 128 ASCII characters
```

Two key files with the same content but different names produce the same key.

---

## 7. Spanning files (`.dgd` / `.dgdr`)

A file too big for one part is split into parts named

```
<base>%04d.dgd
```

Every part is a chunk tree of its own:

```
DGCD  (flags = 1)
|-- INFO  (116 bytes)   the material and the name
|-- DFDT  (32 bytes)    the CRC-32 and the time stamp of the whole file
`-- DATA               this part's raw bytes (not compressed)
```

### 7.1 `INFO` (116 bytes)

| offset | size | field |
|---|---|---|
| `+0x00` | 4 | `flags`: bit 0 = encrypted |
| `+0x04` | 4 | the index of this part (0-based) |
| `+0x08` | 4 | the number of parts |
| `+0x0C` | 4 | reserved, zero |
| `+0x10` | 4 | the size of this part's `DATA` payload |
| `+0x14` | 4 | reserved, zero |
| `+0x18` | 4 | the size of the whole file |
| `+0x1C` | 4 | reserved, zero |
| `+0x20` | 64 | the SHA-512 of the whole file (the state byte order of 6.4) |
| `+0x60` | 4 | the length of the name |
| `+0x64` | ... | the name (UTF-8) |

The 96 bytes `+0x00..+0x5F` are the "material"; the first 92 bytes after the
flags are encrypted with key1 in an encrypted part.

### 7.2 `DFDT` (32 bytes)

| offset | size | field |
|---|---|---|
| `+0x00` | 4 | CRC-32 of the whole file |
| `+0x04` | 4 | `0x20` (the size of this structure) |
| `+0x08` | 8 | reserved, zero |
| `+0x10` | 8 | the `FILETIME` of the file |
| `+0x18` | 8 | reserved, zero |

Every part carries the same `DFDT`.

### 7.3 Reassembly

The parts of one file are recognised by the SHA-512 at `INFO+0x20` and the
number of parts; a directory may contain several sets (e.g. `.dgd` and
`.dgdr`) with different part boundaries. The file is the concatenation of the
parts' `DATA` payloads in part-index order; its size must equal `INFO+0x18`
and its SHA-512 must match `INFO+0x20`. The name is `INFO+0x64`.

### 7.4 The `.dgdr` variant

A `.dgdr` has the same structure but the `DATA` chunk is shorter (the part is
cut short to make room for the recovery data) and a `DGCR` chunk follows the
`DGCD`:

```
DGCR  (flags = 1)
|-- INFO  (48 bytes)   the parameters of section 5.1
`-- DATA              the parity table
```

The parity covers the bytes of the `.dgdr` in front of the `DGCR` chunk;
`INFO+0x28` is the offset of the `DGCR` chunk in the file and `INFO+0x2C` is
the CRC-32 of those covered bytes (for a `.dgcr` the covered bytes are the whole
archive).

A set of `.dgd` files and a set of `.dgdr` files hold the same file with
different part boundaries: a `.dgdr` part carries less data because its
recovery data takes the rest of the part, so the two sets can have different
part counts (in the work area's sample both have two parts, but the `.dgdr`
parts hold less data).

### 7.5 The writer

`dgcpk s [-S<n>] [-p<password>|-k<keyfile>] [-r<n>] <base> <file>` writes the
parts. The part size defaults to the whole file. With `-r` it also writes the
`.dgdr` set (whose first part is shorter, because the recovery data of each
part is appended). With the same input file the output is byte identical to
the original tool's.

---

## 8. Fields that are not specified

These fields exist but do not affect decoding:

* **Block flags bit 0**: a coder-object default the tool sets on every
  compressed block; the decoded bytes do not depend on it. `dgcpk` writes 0.
* **`IARC` reserved fields** (`+0x08`, `+0x18`, `+0x20`, `+0x44`, `+0x48`):
  zero in every archive produced by the CLI. The GUI may store an archive name
  there.
* **The index entry's compressed size** in solid mode: an apportioned
  estimate, not an exact record size.
* **The tool's solid grouping and entry ordering** (section 2.6): a writer
  heuristic. Readers must handle any grouping and order that keeps the data
  stream in index order.
* **The column chooser's secondary test** (the variance branch of sub_423F90):
  `dgcpk` uses the main lag test and then compares the column block with the
  plain one, which is stricter.

---

## 9. Verification

The specification was validated against the tool:

* **Container, index, names**: the stored twin of every test archive
  (`-n -i`) hands over the exact plaintext of the `IARC`, `IFDT` and `IFNM`
  blobs; the compressed twin decodes to the same bytes.
* **Codec**: the Python prototype re-encoded real stream A byte for byte
  (range coder, symbol coder, CM coder and pre-transform at once), and the
  encoder in `dgcpk.c` reproduces the original's streams (e.g. the `text.txt`
  block: `start = 50856`, stream A = 19649 bytes; the uniform PCM columns with
  the match coder; the column method with the delta orders).
* **Packer**: `dgcpk a` reproduces 27 reference archives of the work area
  byte for byte in every DATA / IFDT / IFNM block - the stored twins
  (`n_*`), the compressed ones (`c_*`, `t*`), the solid / each-file trees
  (`solid`, `each`, `all`, `all_solid`, `m_*`), empty files, the uniform
  runs and the column-friendly data. The only field that differs is the
  IARC archive-creation time (the wall clock). `dgcac k` passes on the
  packer's archives, and `dgcac e` extracts them byte identically.
* **Extraction**: every archive in the work area (including `names.dgc` with
  5981 entries and compressed index and names) is extracted by `dgcunp.c` and
  every file's CRC-32 matches the index. The tool (`dgcac e`) extracts the
  archives written by `dgcpk.c` byte identically, and `dgcac k` passes.
* **Crypto**: SHA-512("abc"), the MT19937 output, the fixed key's keystream
  and the recovery table of real `.dgcr` files are byte exact; encrypted
  archives decrypt to byte-identical files.
* **Recovery**: a `.dgcr` with three damaged words is repaired by `dgcunp -R`
  and the archive's CRC matches the `INFO` chunk again; the repaired archive
  extracts without errors. The parity parts were checked against the writer
  (part 3 is the per-row CRC-32, section 5.2).
* **Spanning files**: the parts of the work area's `.dgd`/`.dgdr` sets are
  reassembled, the SHA-512 matches, and the output is byte identical to the
  source file; `dgcpk s` writes byte-identical parts.

---

## 10. References

* `dgcac.exe` - DGCA / DGC Archiver v1.10 (SYN, 2000-2005), the reference
  implementation. The decompiled sources used for the analysis are
  `dgcac.exe.c` (Hex-Rays) and `dgcac.exe.lst` (IDA).
* `dgcunp.c` - the unpacker, lister and repair tool; the decoder reference.
* `dgcpk.c` - the packer; the encoder reference.
* `AGENTS.md` - the working notes and the status of the reimplementation.
