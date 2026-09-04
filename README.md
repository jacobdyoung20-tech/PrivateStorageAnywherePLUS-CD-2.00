# PrivateStorageAnywherePLUS — Crimson Desert 2.01.00

An unofficial community compatibility and feature build of **PrivateStorageAnywherePLUS** for **Crimson Desert 2.01.00**.

Open Private Storage and all five housing storage panels from normal gameplay. The five housing chests are expanded to 1,000 slots each in memory, as in earlier versions. The `PrivateStorageSlots` setting is inactive on 2.01.00 and must stay at 0.

> [!IMPORTANT]
> This build is matched to Crimson Desert 2.01.00 (`CrimsonDesert.exe` 1.0.0.2760) and has been tested only on that version. It will not work on 2.00 or earlier.

## Download

Download the latest release ZIP from this repository's **Releases** page (until a 2.01.00 release is cut, build the ASI as described in `BUILDING.md` and check it against the 2.01.00 value under [Verified release hashes](#verified-release-hashes)). The GitHub source archive is not the installable mod package.

The released ASI is byte-for-byte identical to the build tested in game.

## Features

| Key | Panel | Capacity behavior |
| --- | --- | --- |
| F4 | Private Storage | Game default on 2.01.00 (`PrivateStorageSlots` is inactive, keep it at 0) |
| F5 | Gatherables Chest | Fixed at 1,000 slots |
| F6 | Dresser | Fixed at 1,000 slots |
| F7 | Refrigerator | Fixed at 1,000 slots |
| F8 | Symbol Storage | Fixed at 1,000 slots |
| F9 | Collecting Storage | Fixed at 1,000 slots |
| F11 | Reload INI | Reloads settings without restarting the game |

- Uses the game's native storage interface.
- Each panel supports configurable keyboard and controller bindings.
- Blocks unsafe opens instead of forcing the UI during loading, cutscenes, or other unsafe states.
- Writes a diagnostic log that can identify most future compatibility failures.
- Makes no permanent save-file changes; runtime changes disappear when the game closes.

## Compatibility

- Game: Crimson Desert 2.01.00
- Executable: `bin64\CrimsonDesert.exe` (1.0.0.2760)
- Expected PE `SizeOfImage`: `0x16F1F000`
- ASI loader: required for manual installation

A later game update may move internal functions again. If the mod stops working after an update, preserve `bin64\PrivateStorageAnywhere.log` before launching the game again and open a bug report.

## Installation

### DMM (recommended)

1. Download the latest release ZIP from Releases, or build the ASI yourself (see `BUILDING.md`).
2. Import that ZIP into DMM.
3. Disable or remove every other Private Storage Anywhere entry. Only one copy may be active.
4. Enable this release and launch the game. Nothing else is needed. The ASI is the whole mod.

### Manual

1. Extract `PrivateStorageAnywhere.asi` and `PrivateStorageAnywhere.ini` from the release ZIP.
2. Copy both files into `<Crimson Desert>\bin64\`.
3. Confirm that no second `PrivateStorageAnywhere.asi` is active.
4. Launch through your normal ASI-loader setup.

To uninstall, disable the DMM entry or remove `PrivateStorageAnywhere.asi`. The INI and log can also be removed.

## Capacity settings

The two capacity features are independent.

### F5–F9 housing chests

The five housing chests are always expanded to 1,000 slots. The game loads chest capacity from its InventoryInfo table, where each record keeps `default_slot_count` at +0x48 and `max_slot_count` at +0x4A. The chests ship as `10 / 1000`, and a panel shows the default plus any purchased expansions. A few seconds after start, before any chest panel exists, the mod walks that table and rewrites every default of 10 to 1,000. The panels read the value when they open.

The first 2.01.00 build walked a different table (the 1,119-record one behind the NameToKey call site) and so changed nothing. The build now takes the InventoryInfo manager from the game's own `[InventoryInfo]` error path and refuses to build if the deserializer stops placing `_defaultSlotCount` at +0x48.

### F4 Private Storage

On 2.01.00 this setting is inactive and must stay at `0`. The lookup it relies on has not been re-derived for this version. The rest of this section describes earlier versions.

Set `PrivateStorageSlots` under `[Settings]`:

```ini
PrivateStorageSlots=0
```

`0` is the safe default. It leaves Private Storage at the game's intended capacity and restores the normal value if this process previously changed it.

```ini
PrivateStorageSlots=1000
```

This makes the total exactly 1,000, including purchased expansions. The setting is re-read whenever a panel opens; close and reopen the panel after editing the INI. F11 also reloads the configuration.

Leave `PrivateStorageExpansions=-1` unless automatic expansion detection is wrong.

## Verified release hashes

```text
PrivateStorageAnywhere.asi (Crimson Desert 2.01.00 build, exe 1.0.0.2760)
0B426795A5C55F505ACF03444AF54BDA645A1B9BB86E73D514128016F6DC818B

PrivateStorageAnywherePLUS-CD-2.00-FINAL.zip
6EDE4EB366C46F56B32FABFCBD4CEBDD29F0E819C4DD984F9EA92D33E4BDC66F

PrivateStorageAnywhere.asi (Crimson Desert 2.00 release)
C2B9848F33A3822532C563C31965F4DFF74B0D02A369AE7626D3E43056C49840

PrivateStorageAnywhere.ini
9A949FD3FCD3845C1FD8FB93247620F0D8DADB17C8DCC2DB5F3DDE4AF4EC8FCD

PrivateStorageAnywherePLUS-CD-2.00-FINAL-source.zip
7211B5430F2959C780315012C7FCD446C98697819DFFDCD5D822DC1BD738412F
```

## Security scan and false positives

The exact install ZIP identified by the SHA-256 above has a public [VirusTotal report](https://www.virustotal.com/gui/file/6ede4eb366c46f56b32fabfcbd4cebdd29f0e819c4dd984f9ea92d33e4bdc66f). At the time of the documented scan, 2 of 67 vendors returned generic heuristic/ML detections, while the other 65 reported it undetected.

This release contains an unsigned Windows ASI module that legitimately pattern-scans, hooks game functions, and changes game memory at runtime. Those techniques are normal for this mod but can resemble injector or cheat behavior to automated scanners. A small number of generic detections should not be treated as proof of either safety or malware; verify the hash, review the public source and build documentation, and make your own informed decision.

The tested binary has not been repacked, obfuscated, or altered to chase a zero-detection score. Changing it would invalidate the tested hash and require a new release and test cycle.

## Known non-blocking warnings

The following log messages have working fallbacks and do not prevent the release from functioning:

- `SetDonationFaction: FAIL` followed by `DonationOff: FALLBACK`
- `SetTitleDir: FAIL`
- `Type resolver: DISABLED`
- `Gatherables panel-id lookup FAILED` followed by INI fallback behavior

The inherited startup banner may say “Press F6” for Private Storage. The correct default is **F4**. The tested binary was kept unchanged for release integrity.

## Building from source

See [BUILDING.md](BUILDING.md). The original v1.5.10 ASI and the game executable are intentionally not included. You must supply legally obtained copies with the exact expected hashes/version.

## Credits and status

This is an **unofficial, independent compatibility release**, not an official Stevi release and not affiliated with Pearl Abyss.

It is derived from **PrivateStorageAnywherePLUS v1.5.10 by Stevi (Stevi2195)** and is distributed with permission. The 2.00 compatibility work, capacity behavior, diagnostics, validation, packaging, and documentation were developed separately for this release. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the complete attribution and scope.

Technical history is preserved in [docs/FINDINGS-2.00.md](docs/FINDINGS-2.00.md).
