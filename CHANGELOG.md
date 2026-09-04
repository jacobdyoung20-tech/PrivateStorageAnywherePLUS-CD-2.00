# Changelog

## Crimson Desert 2.01.00 compatibility

Tested on Crimson Desert 2.01.00 (exe 1.0.0.2760): all six panels opened and closed, and the five housing chests opened at 1,000 slots with nothing but the ASI installed. Setting a chest record back to its stock 10 in the running game had the mod restore 1,000 within three seconds.

### Fixed

- Re-derived every game-side anchor that 2.01.00 moved: ModeSwitch, the mode object's field in the menu manager (`+0x1178`), CampWareHouse, ResolveActor, NameToKey and the inventory-manager global. The mode-state layout is unchanged.
- Retuned two signature scans inside the original v1.5.10 ASI whose literals had aged: the MainCharGlobal singleton scan (`[rax+0x10]`, window `0xD00`) and the inventory-manager scan, whose target was outlined out of SetInventory and is now supplied directly.
- The ModeSwitch capture hook no longer gives up when no page is free within reach at boot. It retries once a second from the worker for up to ten minutes. Failure codes 31/32/33/36 replace the single stage 3.
- The validator checks the derived targets and treats every earlier version's addresses as stale.
- The housing-chest expansion walked the wrong table on 2.01.00: the manager taken from the NameToKey call site holds 1,119 records of another table, so the slot loop found nothing and the chests opened at 10. The InventoryInfo manager is now derived from the game's `[InventoryInfo]` error path, and the build checks that the deserializer still puts `_defaultSlotCount` at record +0x48. Chests open at 1,000 slots again.

### Changed

- `PrivateStorageSlots` is inactive on 2.01.00 and must stay at 0.

## Crimson Desert 2.00 compatibility release

Tested on Crimson Desert 2.00: all six panels opened and closed, both capacity behaviors were confirmed, and no crash or freeze occurred.

### Fixed

- Replaced three stale game addresses that caused the 1.18.2 build to crash on 2.00.
- Restored the early exit that makes `PrivateStorageSlots=0` safe while still allowing a previously changed value to be restored.
- Updated the mode-state layout for Crimson Desert 2.00.
- Corrected mode and sub-mode detection to use offsets `+0x28` and `+0x29`.
- Changed the patcher to derive game-side targets from executable structure rather than typed addresses.

### Added

- Deterministic build output for the tested 2.00 executable.
- Independent layout derivation and validation tools.
- Build-time ambiguity checks that stop instead of emitting an unsafe ASI.
- A guarded diagnostic probe for refused storage opens.
- Validation of hook bytes, section layout, exception data, stack arithmetic, field offsets, vararg marshalling, stale addresses, and memory writes.

### Capacity behavior

- F5–F9 housing chests remain fixed at 1,000 slots.
- F4 Private Storage is separately configurable with `PrivateStorageSlots`.
- `PrivateStorageSlots=0` restores/defaults to normal game capacity.
- `PrivateStorageSlots=1000` sets the total to exactly 1,000, including purchased expansions.

### Diagnostic build history

- **AT:** resolved moved addresses but read the wrong mode offset, producing safe `BLOCKED` results.
- **AU:** attempted a broad pointer search; it was unsafe, withdrawn, and never reused.
- **AV:** used guarded fixed candidates safely, but its secondary log labels were incorrect; retracted as diagnostic evidence.
- **AW:** captured the exact mode object passed by the game and proved the object route was already correct.
- **AX:** corrected the mode/sub-mode offsets. Five bytes differed from AW; this became the tested final release.

See [docs/FINDINGS-2.00.md](docs/FINDINGS-2.00.md) for the full evidence trail.
