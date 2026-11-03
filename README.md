# DGCA / DGC Archiver - reverse engineering and reimplementation

This repository is a reverse-engineering effort for **DGCA / DGC Archiver v1.10**
(SYN, Shin-ichi TSURUTA, 2000-2005) and a set of C tools written from the
analysis. Two independent implementations live here:

| file | what it is |
|---|---|
| `dgcunp.c` | **Unpacker / lister / repair tool.** Reads `.dgc` (and `.dgcr`) archives and `.dgd` / `.dgdr` spanning files, lists their contents, extracts them, and can repair an archive whose data is damaged. |
| `dgcpk.c` | **Packer.** Writes `.dgc` archives and `.dgd` / `.dgdr` spanning files. The archives it writes are read back byte-identically by both the original tool and `dgcunp`. |
| `FORMAT.md` | **The format specification** - the container, the index, the codec, the crypto, the recovery data and the spanning files, verified against the original tool. |
| `dgcac.exe.c`, `dgcac.exe.lst` | the decompiled / disassembled sources of the original binary, used as the reference (third-party generated, do not reformat) |
| `dgcac.exe` | the original binary, needed as the ground truth oracle |
| `AGENTS.md` | the working notes: status, method, build/test instructions |

Everything in `FORMAT.md` was checked against real files produced by the
original tool - not inferred from the decompiler alone.

## Building

The tools are C89 and are meant for **MSVC 6.0** (`cl`). There is no
`vcvars32.bat` shipped with the analysis; use `VCVARS32.BAT`:

```powershell
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" >nul 2>&1 ^
  && cd /d <workarea> && cl /nologo /W3 /O2 dgcunp.c /Fe:dgcunp.exe ^
  && link /nologo dgcunp.obj /OUT:dgcunp.exe'
```

Note that `cl` does not run the link step here, so run `link` explicitly.
The workarea is a UNC path, which `cmd` cannot `cd` into - build in a local
directory and copy the `.exe` back (or map a drive letter first). The same
recipe builds `dgcpk.exe`.

## Using dgcunp

```powershell
dgcunp -v archive.dgc            # chunk tree + CRC status
dgcunp archive.dgc               # list the entries
dgcunp -o outdir archive.dgc     # extract
dgcunp -psecret archive.dgc      # extract an encrypted archive
dgcunp -kmykey.key archive.dgc   # ... with a key file
dgcunp -R archive.dgcr           # repair with the recovery data (writes <file>.repaired)
dgcunp -o outdir file.dgd        # a spanning file: reassemble and write it
dgcunp -psecret -o outdir f.dgd  # ... an encrypted one
dgcunp -t                        # the crypto self test
```

Files with CRC-32 mismatches are reported as `MISMATCH`; a damaged archive can
be repaired with `-R` before extraction. The repair covers the bytes the
recovery data covers, and the final check is the CRC-32 stored in the `INFO`
chunk. Multi-part recovery data is handled as well (the `.dgdr` set).

Extraction is sequential: the decoded `DATA` payload is taken in index order,
so long UTF-8 names (longer than `MAX_PATH`) are written with the wide APIs.

## Using dgcpk

```powershell
dgcpk a [-n] [-f] [-i] [-r<n>] <archive> <file-or-folder>...
dgcpk s [-S<n>] [-p<password>|-k<keyfile>] [-r<n>] <base> <file>
```

* `-n` no compression (every block is a tag 0 STORE)
* `-f` one block per file (otherwise the tool groups files by extension into
  solid blocks)
* `-i` identity mode: no timestamps are written
* `-r<n>` append the recovery data (`-r1` ... `-r9`, ~0.8 % ... 100 % redundancy)
* `-S<n>` the size of a spanning-file part
* `s` writes the `<base>0000.dgd` (and with `-r`, the `.dgdr`) parts

`dgcpk` does not write encrypted archives yet; `dgcpk a` refuses `-p`/`-k`
instead of silently writing a plain one.

## Verification

Every entry carries the CRC-32 of the original file, so the unpacker can prove
correctness without a reference copy. Extracting every archive in the work
area and checking that every file's CRC matches the index is the regression
test:

```powershell
foreach ($a in Get-ChildItem *.dgc, *.dgcr) {
    & dgcunp.exe -o out\$($a.Name) $a.FullName | Select-String 'MISMATCH|cannot create|could not be'
}
```

Nothing should be printed. The archives written by `dgcpk.c` are additionally
read back with `dgcac.exe` itself (`dgcac.exe e` extracts them byte-identically
and `dgcac.exe k` passes).

## Status

| area | status |
|---|---|
| chunk tree, both CRC-32s | working |
| index / name list (stored and compressed) | working |
| solid and each-file mode, column method | working |
| extract - every archive in the work area, incl. the 5981-entry `names.dgc` | every file's CRC-32 matches |
| the v1.10 crypto (SHA-512, MT19937, key schedule, cipher) | byte exact |
| recovery data (`-R`) | a three-word-damaged `.dgcr` is repaired and extracts |
| spanning files (`.dgd` / `.dgdr`, reassembly, SHA-512 check) | working |
| packer: archives, solid mode, column method, LZ stage, match coder | `dgcac.exe` reads its archives back byte-identically |
| packer: encrypted archives | not written yet |
| the tool's solid grouping / entry ordering | reverse engineered (by extension groups), not implemented in `dgcpk` |

## Notes and limitations

* The original binary is the ground truth; every claim in `FORMAT.md` comes
  from comparing bytes, not from reading the decompiler.
* Some fields are intentionally not specified - see `FORMAT.md` section 8.
* The GUI of the original tool is not analysed; the CLI and the archives are.
* The repository is for study and interoperability. It is not affiliated with
  the author of DGCA, and it does not grant any rights to the original program.
* Build artifacts and sample archives are not tracked (see `.gitignore`).
