# Reproducing the Crimson Desert 2.01.00 build

The release is deterministic: the same pristine input ASI and the same Crimson Desert executable produce the same output bytes.

## Requirements

- Python 3.11 or newer
- Packages in `requirements.txt`: `capstone`, `pefile`, and `py7zr`
- A legally obtained pristine Private Storage Anywhere v1.5.10 ASI
  - SHA-256: `4F514298B2BC5DB7E804B0166AD2269BAE97A414F7DAE425A0F736CDA7F56F3E`
- Crimson Desert 2.01.00 `bin64\CrimsonDesert.exe` (1.0.0.2760)
  - Expected `SizeOfImage`: `0x16F1F000`

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
derived  CampWareHouse=0x57A0208 NameToKey=0x20BFF60 ResolveActor=0x1EC1430 ModeSwitch=0x5CF2B0
derived  modeObj=menuMgr+0x1178
derived  mainchar-scan disp8=0x10 window=0xD00..0xDFF -> global=0x6C29788
derived  InventoryInfo manager global=0x6C2A038 (getter game+0x8752A40, via [InventoryInfo]); NameToKey site manager=0x6C2C078; _defaultSlotCount at rec+0x48
derived  ingame-mode=4 store-sub=5
layout   mode=0x28 sub=0x29 flags=0x31 subtypes=0x38 dirty=0x5B
output_sha256=0b426795a5c55f505acf03444af54bda645a1b9bb86e73d514128016f6dc818b
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
0B426795A5C55F505ACF03444AF54BDA645A1B9BB86E73D514128016F6DC818B
```

Do not call a rebuild “the tested release” unless its hash matches exactly.
