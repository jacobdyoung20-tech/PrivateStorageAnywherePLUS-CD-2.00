# Support and bug reports

Before reporting a problem:

1. Confirm the game version is Crimson Desert 2.00.
2. Disable every other Private Storage Anywhere installation.
3. Reproduce from normal gameplay with no menu open.
4. Copy `bin64\PrivateStorageAnywhere.log` **before launching the game again**. The file is overwritten on the next launch.

Include:

- What key/controller binding you pressed.
- What appeared, if anything.
- Whether the game froze, crashed, stuttered, or remained responsive.
- Whether the panel had worked earlier in the same session.
- Your edited INI, if the issue involves bindings or capacity.
- The complete log as a file attachment.

Do not post save files, account credentials, API keys, or unrelated personal paths.

Useful log indicators:

- `=== READY!` means the mod loaded and completed initialization.
- `Warehouse opened (mode=0x04 ...)` confirms a panel opened.
- `BLOCKED: unsafe state` means the mod refused to open rather than writing during an unsafe game state.
