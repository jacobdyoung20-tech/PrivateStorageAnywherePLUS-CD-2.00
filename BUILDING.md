# Reproducing the Crimson Desert 2.00 build

The release is deterministic: the same pristine input ASI and the same Crimson Desert executable produce the same output bytes.

## Requirements

- Python 3.11 or newer
- Packages in `requirements.txt`: `capstone`, `pefile`, and `py7zr`
- A legally obtained pristine Private Storage Anywhere v1.5.10 ASI
  - SHA-256: `4F514298B2BC5DB7E804B0166AD2269BAE97A414F7DAE425A0F736CDA7F56F3E`
- Crimson Desert 2.00 `bin64\CrimsonDesert.exe`
  - Expected `SizeOfImage`: `0x16499000`

The original ASI and game executable are not distributed in this repository.

## Layout

Place the pristine input at:

```text
original/PrivateStorageAnywhere.asi
```

Create an output directory named `patched`.

## Build

```powershell
python tools/patch_private_storage_1182_modestate.py `
  original/PrivateStorageAnywhere.asi `
  patched/PrivateStorageAnywhere-2.00.AX-modeoffset.asi `
  "<game>\bin64\CrimsonDesert.exe"
```

Expected result:

```text
derived  CampWareHouse=0x501C6B8 NameToKey=0x1E37F50
         ResolveActor=0x75BF90 ModeSwitch=0x530E20
derived  ingame-mode=4 store-sub=5
layout   mode=0x28 sub=0x29 flags=0x31 subtypes=0x38 dirty=0x5B
output_sha256=c2b9848f33a3822532c563c31965f4dff74b0d02a369ae7626d3e43056c49840
```

The build stops if any anchor is missing, ambiguous, or internally inconsistent.

## Validate

```powershell
python tools/validate_aw.py `
  patched/PrivateStorageAnywhere-2.00.AX-modeoffset.asi `
  "<game>\bin64\CrimsonDesert.exe" `
  --pristine original/PrivateStorageAnywhere.asi
```

Optional flags:

- `--listing` prints a full disassembly of the appended code section.
- `--vs <earlier.asi>` lists every byte changed inside the original 256 KB.

The validator name is historical. It validates the complete AT-through-AX lineage and the final release.

## Re-derive the mode-state layout

```powershell
python tools/derive_modestate.py "<game>\bin64\CrimsonDesert.exe"
```

This prints the UI mode-tag pool, jump tables, located ModeSwitch, five field offsets, and spacing checks.

## Release output

The final ASI must match:

```text
C2B9848F33A3822532C563C31965F4DFF74B0D02A369AE7626D3E43056C49840
```

Do not call a rebuild “the tested release” unless its hash matches exactly.
