# Crimson Desert 2.00 findings

> **CURRENT TARGET: Crimson Desert 2.00 — RESOLVED AND RELEASED (§76).**
>
> This is the authoritative technical record for current work. It was created
> from sections 57 onward of the complete historical findings document. For the
> proven 1.18.2 fix and earlier investigation, see
> `history/1.18.2/FINDINGS-1.18.2-MODESTATE.md`.
>
> **Read §73–§76 before anything else.** They retract the diagnosis that
> §59–§70 were built on: the route to the mode object was correct from AT
> onward, and the actual fault was a two-byte offset error (§74). The
> intermediate sections are kept because the wrong turns are the useful part of
> the record, but their framing is superseded.

Last reorganized: 2026-08-27 (America/Chicago)

## 57. Crimson Desert 2.00 — three breakages, one visible

The 1.18.2 final build (AS) crashes on 2.00. The log reaches `READY!` with every
runtime resolver reporting OK, then stops — so the mod's own discovery layer is
fine and the fault is in constants baked into the patch.

### What moved

```text
NAME_TO_KEY       0x1E141D0 -> 0x1E37F50
RESOLVE_ACTOR     0x751D20  -> 0x75BF90
CAMP_NAME         0x4FC0560 -> 0x501C6B8
MAINCHAR_GLOBAL   0x62C1500 -> 0x6330A78
mode/submode      0x18/0x19 -> 0x50/0x51
flags/subtypes    0x21/0x28 -> 0x31/0x38
dirty             0x4B      -> 0x5B
```

The flags/subtypes/dirty block shifted uniformly by +0x10; mode/submode moved
+0x38. `subtypes == flags + 7` still holds.

### Verified unchanged (checked, not assumed)

`MODE_OBJ_IN_MENUMGR = 0x1158` (`mov rcx,[rcx+0x1158]` at `game+0x94919A`, the
single ModeSwitch call site); `menuMgr = [root+0x90]`; inventory manager `+0x08`
count, `+0x58` array A, `+0x68` bucket count, `+0x6c` guard, `+0x78` buckets,
`+0x80` array B; `InventoryInfo +0x48/+0x4a`; container `+0x10` index, `+0x14`
total, `+0x16`/`+0x1a` expansions; owner `+0x18`/`+0x20`; the owner accessor
`[[actor+0x68]+0xb8]` (`GetInventoryOwner` now `game+0x1DF5A60`); in-game mode 4
and store sub-mode 5. `GetInventoryInfo` moved to `game+0x3AEC00` but is
byte-for-byte the same shape, and `add r11,[r10+0x78]` still compiles as `add`,
so the `0xA583` resolver fix stands.

### The crash

`0x1E141D0` no longer decodes as code on 2.00 and `0x751D20` lands
mid-instruction. Both are unconditional `call rax` targets.

The startup crash is `NAME_TO_KEY`, on the background pass ~1 s after `READY!`.
Critically it fires **even with `PrivateStorageSlots=0`**: AS removed the
early-out on 0 (§56) so that 0 could restore capacity, which left a disabled
feature still walking to a stale game address. That is the whole failure.

`RESOLVE_ACTOR` is the same fault on the panel-open path, and the moved
mode-state fields are a third breakage that would have surfaced next.

## 58. Build AT — derive instead of retyping

1. **Build-time derivation.** The patcher now takes the game executable as a
   third argument and derives every game-side target, failing loudly if an
   anchor is missing:
   - `NAME_TO_KEY` — the bucket idiom `shl r11,8 ; add r11,[r10+0x78]` is
     generic (190 sites on 2.00), so the anchor is the call shape feeding it:
     `lea rdx,[rsp+N] ; mov rcx,[rax] ; call`. Three sites match, two agree;
     majority vote, and ≥2 votes required.
   - `RESOLVE_ACTOR` — the prologue `mov [rsp+0x10],rdx ; push rbx ;
     sub rsp,0x30 ; mov rbx,rdx` plus `[rcx+0x50]` and `mov rcx,rbx` in the body.
   - `CAMP_NAME` — two copies of the literal ship; keep the one with `lea` xrefs.
   - Mode layout — `derive_modestate.py`, extended with a stronger dirty rule:
     the offset stored with an immediate 1 at least twice **and** compared
     against zero. The old proximity heuristic returned NOT FOUND on 2.00.

2. **`MAINCHAR_GLOBAL` deleted.** Replaced by `mov rax,[ASI 0x3D518]` /
   `mov rax,[rax]` — the mod already resolves and logs that global. One fewer
   address to age.

3. **"Off" means off again.** Restored the early-out, gated on a `PS_DIRTY`
   dword in `.psdata` so 0 still restores after the feature was used:

```text
cmp dword[rsp+0x38],0 ; jne armed
mov eax,[PS_DIRTY] ; test eax,eax ; je done
```

```text
output  DB9C08FEB9742094D08300196AFA3273C6191513D3CBF0DF10CFBD0B49C1AE69
zip     30CCEAE7D066CC09093F7C3C2D8341B66091CDF6FB34031ED9F68927E34292C5
```

Verified: no stale 1.18.2 target survives as an immediate; all three 2.00
targets present; the four layout immediates in the mode stub and both
`mov byte [r9+0x5B],1` dirty writes updated; inside the original 256 KB the only
diffs from AS are those constants and the tag; landmine NOPs, housing path and
spinlocks byte-identical to AI; 589 exception entries; no new pefile warnings.

Untested in game.

## 59. Build AT result — right offsets, wrong object

AT loads and runs on 2.00; every open is refused by the mod's own safe-state
check with `BLOCKED: unsafe state (mode=0x00 sub=0x00)`.

**Which message it is settles the diagnosis.** The check at ASI `0xB440`:

```text
0xB447  call get_mode_obj          ; ASI 0x14C0
0xB452  mov  rsi, rax
0xB45A  jne  0xB477                ; non-null -> continue
0xB45C  lea  rcx, "NOT READY: mainChar"
```

The log shows `BLOCKED`, not `NOT READY: mainChar`, so `get_mode_obj` returned a
pointer that passed its `> 0x10000` guard and `byte[obj+0x50]` / `[obj+0x51]`
really did read `00/00`. Valid memory, wrong object.

The offsets are not in doubt: they come from ModeSwitch operating on the object
it is handed, `subtypes == flags + 7`, dirty is stored as `1` twice and tested
against zero, and the expected values (in-game 4, store 5) match 2.00's own jump
tables.

`get_mode_obj` walks `root -> +0x90 -> +0x1158`. The game's own route, at its
single ModeSwitch call site:

```text
game+0x50ACAE  mov rcx,[rdi+0x28]     ; -> mode tick fn 0x948C00
game+0x949196  mov rcx,[rcx+0x28]
game+0x94919A  mov rcx,[rcx+0x1158]   ; the real mode object
game+0x9491A1  call ModeSwitch
```

Both end in `+0x1158`; the parent differs. `+0x1158` is loaded from 25 sites
image-wide and the game's chain needs two more hops to reach a global, so this
is measured rather than inferred.

## 60. Build AU — the mode-object probe

Read-only diagnostic, hooked at ASI `0xB5F3` where the block message is built.
The 10 bytes of `mov r8d,ecx` + `lea rcx,[BLOCKED fmt]` become
`call PSDIAG` + 5 NOPs; the probe restores every volatile and re-issues those
two instructions before returning, so `jmp 0xB85F` at `0xB5FD` is untouched and
the safety check is unaltered.

Signature searched: an object with `byte[+0x50] == 4` and `byte[+0x51]` in
`{15, 16}`.

```text
root    = [[ASI 0x3D518]]
menuMgr = [root + 0x90]

head   log root, menuMgr, [menuMgr+0x1158] and its first six dwords
tag 4  for D in 0x000..0x400 step 8: test [root + D]
tag 2  for D in 0x000..0x400 step 8: test [[root + D] + 0x1158]
tag 3  for D in 0x1000..0x1400 step 8: test [menuMgr + D]
```

Tag 2 is the likely hit: it keeps the `+0x1158` step and asks only which field
replaced `+0x90`. Output capped at 8 hits via a counter at `PD_RVA + 12`.

Every dereference carries the `> 0x10000` plus high-bits-clear guard. Verified
instruction by instruction: the probe makes **no** write to game memory — the
only memory destinations are `[rsp+...]` and the hit counter in `.psdata`.

```text
output  F093DE593211A0EA2E6C9386260E882CB69FE72046AFFFCEC25B71878598EEC5
zip     7AC791BC1A8E262D2C9C7436C47937740DB878500AEFB56B83E256F3D8ABAF48
.pstext used 0x9E3 of 0x1000
```

Inside the original image the only diff from AT is the 10 bytes at `0xB5F3`
plus the tag; sections, 589 exception entries and pefile warnings unchanged.

## 61. Build AU froze the game — unvalidated dereference

The log stops immediately after the `cur+0` line, which is the last instruction
before the search loop. The loop body:

```text
0x46905  mov rcx,[rsp+0x38]     ; root (valid — the game stores it)
0x4690A  mov rcx,[rcx+rax]      ; p = [root+D]  <- ARBITRARY qword
0x4691D  call tst               ; tst: movzx eax, byte [rcx+0x50]
0x46941  mov rcx,[rcx+0x1158]   ; same arbitrary qword, followed again
```

`tst`'s guard only tests the *shape* of a value (`> 0x10000`, high 17 bits
clear). That is sound for a value read from a field the game itself
dereferences — how the rest of the patch uses it — and worthless for arbitrary
data: packed floats, counts, handles and embedded structs all pass.

~390 such candidates were tried, so reading unmapped memory was near-certain.
The access violation went into the game's crashpad handler, which explains the
multi-minute hang and self-termination rather than a prompt crash.

AU's own head/`cur+0` reads were safe for the same reason the rest of the patch
is: `root`, `[root+0x90]` and `[menuMgr+0x1158]` are pointers the game stores
and follows itself.

## 62. Why the mode-object parent is not statically derivable

```text
game+0x9491A1  call ModeSwitch      rcx = [[X+0x28]+0x28]+0x1158
game+0x50ACAE  mov rcx,[rdi+0x28]   -> tick fn 0x948C00
game+0x386FAD6 mov rcx,rdi ; call 0x50ABA0
game+0x386FA30 <- ZERO direct callers (virtual dispatch from a task list)
```

Every other consumer — `BuildModeTagList`'s 11 callers, `0x52F070`,
`0x52F250`, `0x63C670` — receives the object as a parameter. The xref chain
terminates with no global to anchor on. The field offsets, derived from
ModeSwitch itself, remain sound; only the route changed. Structural hint: the
game uses `+0x28` twice then `+0x1158`, the mod uses `+0x90` then `+0x1158` —
so the first hop is the likely difference.

## 63. Build AV — fixed candidates, validated by VirtualQuery

`VirtualQuery` is not imported, but `LoadLibraryA` (IAT `0x280F8`) and
`GetProcAddress` (IAT `0x280F0`) are. Resolve once into `PD_RVA + 16`; if it
fails the probe logs one line and does nothing.

`rdbl(rcx)` returns true only when `VirtualQuery` reports
`State == MEM_COMMIT` and `Protect` is neither `PAGE_NOACCESS` nor
`PAGE_GUARD`. Every pointer at every step of every chain passes through it
before being followed — 18 guarded dereferences in total.

Twelve straight-line candidates, no loop of any kind (verified: not one backward
branch in the emitted probe):

```text
 1 [menuMgr+0x1158]   2 +0x1150   3 +0x1160   4 +0x11A0
 5 +0x11A8            6 +0x11B0   7 +0x11B8   8 [[menuMgr+0x28]+0x1158]
 9 [[root+0x28]+0x1158]           10 [[[root+0x28]+0x28]+0x1158]
11 [root+0x1158]                  12 [[root+0x98]+0x1158]
```

Candidate 10 mirrors the game's own shape. Each surviving candidate logs
`c%u ptr m s f t d` for `+0x50/+0x51/+0x31/+0x38/+0x5B`; the real object reads
`m=04`, `s=0F` or `0F`/`10`.

### A build-time bug caught in review

The first AV emit used `48 83 EC A0` for the `0xA0` frame. `83 /x ib` is
sign-extended imm8, so `0xA0` assembles as **`sub rsp,-0x60`** — the prologue
would have *raised* rsp into the caller's frame and the epilogue would have
mismatched. Every earlier frame was `<= 0x7F` so this never bit before. Fixed to
the imm32 forms `48 81 EC A0 00 00 00` / `48 81 C4 A0 00 00 00`, confirmed as
`sub rsp,0xa0` / `add rsp,0xa0` in the built file.

```text
output  423A47A027C13B807EAAED8927752069A2291716359773BA5764E9CDA8FF91CD
zip     F70C0B78BFA9017EE35BA44B84849EA370ED205031ADB488F0018D6B30666502
.pstext used 0xD82 of 0x1000
```

Verified: no loops, no writes outside `[rsp+...]`, epilogue restores every
volatile and re-issues `mov r8d,ecx` + `lea rcx,[BLOCKED fmt]`; inside the
original image the only diff from AT is the 10 bytes at `0xB5F3` plus the tag;
8 sections, 589 exception entries, no new pefile warnings.

## 64. Build AV result — tested in game

Tested 2026-08-27. Load a save, normal gameplay, one F4 press. No panel and no
other UI appeared; the game did not freeze or crash and stayed playable.

### Provenance

The deployed ASI is byte-identical to the AV artifact:

```text
bin64\PrivateStorageAnywhere.asi    423A47A027C13B807EAAED8927752069A2291716359773BA5764E9CDA8FF91CD
patched/PrivateStorageAnywhere-2.00.AV-modeprobe.asi   (same)
patched/av-package/PrivateStorageAnywhere.asi          (same)
```

The log banner reads `Private Storage Anywhere v1.5.10 (CD 2.00.AV)`, its
`Size: 0x16499000` equals `SizeOfImage` of the live `bin64\CrimsonDesert.exe`,
and `MainCharGlobal: OK base+0x6330A78` matches §57's 2.00 value. `[MODE]` lines
are emitted only by AV. `HOTKEY Private (vk=0x73) -> OPEN` appears exactly once.

Retained (untracked) at `logs/2.00-AV/PrivateStorageAnywhere-AV-2026-08-27.log`,
SHA-256 `A990E1BBB10E016F436F197D400B3051215698C22677C4BE183391A471BD3AEC`.

### The probe output, verbatim

```text
HOTKEY Private (vk=0x73) -> OPEN
  [MODE] root=2402052C000 menuMgr=2401BF02800
  [MODE] c1 ptr=240235697E0 m=00 s=00 f=01 t=235697E0 d=01
  [MODE] c2 ptr=24023833FA0 m=01 s=00 f=67 t=23833FA0 d=02
  [MODE] c3 ptr=24020578640 m=00 s=00 f=00 t=20578640 d=03
  [MODE] c4 ptr=24020584C80 m=00 s=00 f=C8 t=20584C80 d=04
  [MODE] c5 ptr=2401BCDB2C0 m=00 s=00 f=01 t=1BCDB2C0 d=05
  [MODE] c7 ptr=24024C6C9C0 m=00 s=00 f=00 t=24C6C9C0 d=07
BLOCKED: unsafe state (mode=0x00 sub=0x00)
```

`VirtualQuery` resolved (no `probe skipped` line). Candidates **6, 8, 9, 10, 11
and 12 are absent** — each was abandoned because some address in its chain was
not committed and readable.

## 65. Retraction — AV's field labels are wrong

Three of the five logged fields are mislabelled and the pass signature AV was
designed around could never have been produced.

`fin` in `tools/patch_private_storage_1182_modestate.py` emits the format
`c%u ptr=%llX m=%02X s=%02X f=%02X t=%02X d=%02X`. Under the Win64 calling
convention that puts `s` at `[rsp+0x20]`, `f` at `[rsp+0x28]`, `t` at
`[rsp+0x30]` and `d` at `[rsp+0x38]`. The emitted code stores:

```text
mov [rsp+0x30], rcx     ; the candidate pointer  -> lands in the t slot
mov [rsp+0x38], edx     ; the candidate index    -> lands in the d slot
mov [rsp+0x28], rax     ; byte[obj+0x5B]         -> lands in the f slot
mov [rsp+0x20], rax     ; byte[obj+0x38]         -> lands in the s slot
mov [rsp+0x88], rax     ; byte[obj+0x31]         -> never printed
mov [rsp+0x80], rax     ; byte[obj+0x51]         -> never printed
```

So the correct reading of every `[MODE] cN` line is:

| printed | actually is |
| --- | --- |
| `m` | `byte[obj+0x50]` — mode. **Correct.** |
| `s` | `byte[obj+0x38]` — subtypes[0] |
| `f` | `byte[obj+0x5B]` — dirty |
| `t` | low 32 bits of the candidate pointer |
| `d` | the candidate index |

Confirmed by the data itself: every `t` equals the low dword of its own `ptr`
(`240235697E0` -> `235697E0`), and `d` runs 1,2,3,4,5,7.

**Sub-mode (`+0x51`) and flags (`+0x31`) were never logged.** AV's README told
the user to look for `m=04` with `s=0F` or `s=10`; the `s` column was never
sub-mode, so that signature was unreachable by construction.

The probe stayed memory-safe. `fin`'s frame is `0x48` and it is called from
`diag`, whose frame is `0xA0`, so the two stray stores land at `diag+0x30` and
`diag+0x38` — scratch that `diag` never reads. `root`, `menuMgr` and the
candidate scratch live at `diag+0x70/+0x78/+0x80` and are untouched.

Corollary: `f=67` (c2) and `f=C8` (c4) are `byte[+0x5B]`, a field ModeSwitch
stores as `1` and tests against zero. Neither candidate is a mode object.

## 66. What AV proves, rules out, and leaves open

### Proves

- **AV is safe as built.** 18 `VirtualQuery`-guarded dereferences, six chains
  abandoned mid-walk, no access violation, no freeze, game playable afterwards.
  AU's failure mode (§61) is fixed and the guard design works.
- **Everything up to the open is healthy on 2.00.** Every resolver OK, three
  hooks installed, `READY!`, the slot patch applied, F4 routed to the Private
  panel, one clean exit. The §58 address fixes hold; there is no startup crash.
- **AT's object is readable but wrong.** Candidate 1 is exactly what AT uses
  (`[menuMgr+0x1158]`); it reports mode `0x00`, matching the `BLOCKED` line's
  `mode=0x00`. §59's diagnosis is confirmed from a second, independent read.

### Rules out

- The mode object is not at `menuMgr + 0x1150`, `+0x1158`, `+0x1160`, `+0x11A0`,
  `+0x11A8` or `+0x11B8` — all six read mode `0x00` or `0x01`.
- `[menuMgr+0x11B0]` is not a live pointer (c6 abandoned).
- **Every candidate that changed the first hop was rejected as unreadable**:
  `[menuMgr+0x28]` (c8), `[root+0x28]` (c9, c10), `root+0x1158` (c11) and
  `[root+0x98]` (c12). In particular **candidate 10 — the chain that mirrored
  the game's own `+0x28,+0x28,+0x1158` shape — is disproven**; `[root+0x28]`
  is not a pointer, so `root` is not the object the game's chain starts from.

### Leaves open

- Sub-mode and flags for all six reporting candidates, because of §65.
- Whether the true first hop is another field of `root`, or whether `menuMgr`
  is simply not the object that owns `+0x1158` on 2.00.
- **Unexplained observation.** The probe read `root = 0x2402052C000` while the
  mod logged `mainChar: 0x2402061D200` at init. Both come from the same global
  (`base+0x6330A78`). The likeliest explanation is that loading a save replaced
  the object between init and the hotkey press, but that is untested; recorded
  as an observation, not a conclusion.

### Not concluded from the absent UI

AV always reports `BLOCKED` by design and its README said so. "Nothing
appeared" is consistent with the diagnosis but is not evidence for it. The
`BLOCKED` log line and the candidate bytes are the evidence.

## 67. Corrections to §59 and §62

Re-derived from the live 2.00 `bin64\CrimsonDesert.exe` with capstone.

**§59's instruction at `game+0x949196` is wrong.** It is
`mov rcx,[r15+0x28]`, not `mov rcx,[rcx+0x28]`:

```text
9490E5  mov  r15, [rsp+0xE0]      ; spilled parameter, reloaded
...
949196  mov  rcx, [r15+0x28]
94919A  mov  rcx, [rcx+0x1158]
9491A1  call 0x140530E20          ; ModeSwitch
```

The chain origin is a spilled parameter of a large function, so §62's
conclusion — no global to anchor on — stands, but its stated register chain
`[[X+0x28]+0x28]+0x1158` should read `[[r15]+0x28]+0x1158` with `r15` itself a
parameter.

**ModeSwitch is `game+0x530E20` and has exactly one direct `call`**, at
`game+0x9491A1`. Verified by scanning every `E8` in `.xpdata` for that target.

**The §57 field layout is re-confirmed independently.** Within its first
`0x600` bytes ModeSwitch, operating on `rbx = rcx` from entry, touches
`+0x38` 14 times, `+0x50` 8 times, `+0x5B` 4 times, and `+0x51` and `+0x31`
once each — including the indexed subtypes read
`cmp byte [rdx+rbx+0x38], r9b` at `game+0x530EAF`. **The offsets are not the
problem.** Its prologue is three clean 5-byte stores:

```text
530E20  mov [rsp+0x08], rbx
530E25  mov [rsp+0x10], rsi
530E2A  mov [rsp+0x18], rdi
530E2F  push rbp
...
530E47  mov rbx, rcx              ; rcx at entry IS the mode object
```

## 68. Static survey of 2.00 — the route is not derivable, the field is real

**`+0x1158` consumers.** 21 REX.W `mov r64,[r64+0x1158]` sites image-wide.
Every genuine mode-object consumer loads its base from `[this+0x28]`:

```text
944AB5  mov rcx,[r14+0x28]   -> 944AB9
945C13  mov rcx,[rdi+0x28]   -> 945C3B
946EEA  mov rsi,[rdi+0x28]   -> 946F03
9478C2  mov rbp,[rdi+0x28]   -> 9478E7
949196  mov rcx,[r15+0x28]   -> 94919A
```

The remaining sites resolve to `lea rbp,[rsp-0x11xx]` — large stack frames, not
this object. **No site takes its base from a global**, so there is no static
anchor to follow.

**What the game reads off the mainChar global.** 886 well-formed
`mov r64,[rip -> base+0x6330A78]` sites; the first offset dereferenced off the
loaded value:

```text
+0x00  273    +0xB0  173    +0x50  135    +0xA0   91
+0x90   64    +0x98   32    +0x48   15    +0xB8   15
+0xA8   13    +0x30   12    +0xC0   11    +0x28    1
```

Two conclusions. `[root+0x90]` is a real, heavily used 2.00 field, so the mod's
first hop is not nonsense and `menuMgr` is a genuine object. And `[root+0x28]`
is used exactly once image-wide, which is consistent with AV rejecting
candidates 9 and 10 outright.

## 69. Why the next build must capture instead of guess

Three independent lines now agree that the field offsets are right and only the
route is wrong: ModeSwitch's own code (§67), AT's behaviour (§59), and AV's
candidate bytes (§66). Route-guessing has been tried twice — AU by searching
(froze the game) and AV by enumerating twelve fixed chains (all disproven) —
and §62 plus §68 show the parent is not statically derivable.

The game computes the pointer itself, every frame, at a single site:
`game+0x9491A1 call game+0x530E20` with the mode object in `rcx`. Taking it
from there removes the route from the problem entirely and cannot age with the
next patch the way a hard-coded chain does.

### The exhaustive negative

Every rip-relative qword load of a global in the 2.00 image was enumerated —
**54657** of them, restricted to targets in the uninitialised data range where
globals live — and each was followed forward up to 30 instructions, tracking
every `mov r64,[reg+disp]` chain rooted at the loaded value. **Not one reaches
`+0x1158`.** The walker is not vacuous: on the mainChar global alone it finds
971 two-step paths.

Two further results fall out of the same survey and both matter.

`[glob]+0x90` — the mod's `menuMgr` — **is** a real object of the right family.
The game reads `+0x10C8`, `+0x10F0`, `+0x11A0`, `+0x11A8`, `+0x11B8` and
`+0x11F8` off it. It never reads `+0x1158` off it. Meanwhile the object that
does own `+0x1158`, reached as `[this+0x28]`, is read at `+0x10C8`, `+0x10D0`,
`+0x10E0`, `+0x1118`, `+0x1138`, `+0x1148` and `+0x1158`. The shared `+0x10C8`
suggests the same class with two live instances, and the mod is holding the
wrong one — which is exactly the shape of AT's symptom and is not fixable by
changing an offset.

Of the offsets AV probed off `menuMgr`, the three the game itself uses are
`+0x11A0`, `+0x11A8` and `+0x11B8` — candidates 4, 5 and 7. All three reported
mode `0x00`.

## 70. Build AW — the capture hook

`ModeSwitch = game+0x530E20`, derived at build time and never typed in. The
anchor is the call shape: a `mov r64,[r64+0x1158]` immediately followed by
`call rel32`. Four sites match on 2.00; exactly one calls a function whose
first fifteen bytes are three 5-byte register spills, and that one has exactly
one direct caller image-wide. All three conditions are asserted, and the
address is required to be 8-byte aligned.

```text
530E20  48 89 5C 24 08   mov [rsp+0x08],rbx
530E25  48 89 74 24 10   mov [rsp+0x10],rsi
530E2A  48 89 7C 24 18   mov [rsp+0x18],rdi
530E2F  55               push rbp            <- the stub returns here
...
530E47  48 89 CB         mov rbx,rcx         <- rcx at entry IS the mode object
```

### The patch is eight bytes, and that is the whole point

ModeSwitch runs every frame. A 15-byte trampoline copy into live code has a
window in which the entry decodes as garbage, and **there is no ordering of
those bytes that closes it** — write the tail first and a thread that has just
executed the head falls into rubble; write the head first and the head itself
is rubble; write the middle first and the second instruction's SIB/disp become
imm64 bytes, turning `mov [rsp+0x10],rsi` into a store to an arbitrary
stack offset.

So the patch is a single **8-byte store to an 8-byte-aligned address**, which
x86-64 performs atomically. Every thread sees either the whole original qword
or the whole replacement, and both decode to one complete instruction at
`530E20`. Eight bytes only reaches ±2GB and the ASI is further than that, so
the store is `E9 rel32` + three `nop` into a one-page trampoline allocated near
the game image, which then does `mov rax,imm64 ; jmp rax` into `.pstext`.

Bytes `530E28..530E2E` are left as they were. Nothing jumps into them: the
stub re-issues all three spills verbatim and rejoins at `530E2F`.

### Failure is silent and total

`PS_HOOKED` is set to 2 *before* anything is attempted, so a failure never
retries. Each stage logs its number and returns with the game untouched:

```text
1  LoadLibraryA / GetProcAddress for VirtualProtect and VirtualAlloc
2  all fifteen prologue bytes still match, checked as two overlapping qwords
3  VirtualAlloc within reach — 16 tries, 16 MB apart, starting 1 MB below
   the image; then VirtualProtect the page to PAGE_EXECUTE_READ
4  the rel32 survives a movsxd round-trip
5  VirtualProtect, the store, VirtualProtect back
```

The page is allocated `PAGE_READWRITE`, filled, and only then made executable —
nothing is ever writable and executable at once, the same reasoning as the two
appended sections rather than one RWX section.

### What consumes it

`get_mode_obj` (ASI `0x14C0`) is now a 5-byte jump into `.pstext`; the body
returns `PS_MODEOBJ` when it passes the `> 0x10000` guard and otherwise falls
back to AT's `root -> +0x90 -> +0x1158` walk. It is still a leaf — no call, no
push, no stack write — which is what allowed it to live in the dead resolver's
`.pdata` range in the first place. The capture stub is a leaf by the same
standard: it writes only to the caller's own shadow space, exactly as the
instructions it replaced did.

**The safe-state check at ASI `0xB440` is unchanged.** It is the gate: a
captured object that does not read mode `0x04` still refuses the open and still
writes nothing to game memory.

### §65 cannot recur

`fin`'s frame grew from `0x48` to `0x58` and the saved pointer and index moved
to `+0x40`/`+0x48`, above the argument block instead of inside it. The field to
vararg-slot map is now asserted at build time by `tools/validate_aw.py`, which
disassembles the built file and fails if it is not exactly
`+0x5B -> +0x38`, `+0x38 -> +0x30`, `+0x31 -> +0x28`, `+0x51 -> +0x20`, with
mode in `r9d`. A third `rdbl` guard was added on `+0x31`, which the AV build
read without validating.

The captured object logs through the same guarded reader as candidate **0**.

```text
output  D1103D64C10D23978053EABC1375501817DE3108D0DE5812CE39B51433B7E6C9
zip     AF90C0D0C78BFFFBFB0530B080302BC597C5BFB60FC9BE5110A1ABE0A3B2EC8D
.pstext used 0x8E4 of its second page; PS_SIZE 0x1000 -> 0x2000, PD_RVA -> 0x48000
```

## 71. AW offline validation

`tools/validate_aw.py` disassembles the built ASI and checks it rather than
trusting the emitter. Result on the shipped artifact: all checks passed.

- Sections, characteristics, `SizeOfImage`, **589** exception entries, and no
  `pefile` warning beyond the two chained-unwind warnings the **pristine
  v1.5.10 input already carries** (that baseline is the correct comparison —
  requiring zero would fail on the unmodified mod).
- No `sub`/`add rsp` with a negative immediate anywhere in the block. This is
  the §63 `sub rsp,-0x60` class of bug, now a standing check.
- The capture stub makes no `push`/`pop`/`call`, re-issues the three spills
  byte-for-byte, and returns to `ModeSwitch+0xF`.
- The `fin` marshalling map, asserted exactly.
- The two runtime guard qwords together cover all fifteen prologue bytes, and
  the live executable still matches them.
- No stale 1.18.2 immediate survives; all four 2.00 targets are present.
- The only non-stack, non-`.psdata` stores in the whole block are four: three
  filling the freshly allocated trampoline, and the single atomic
  `mov [rcx], rdx` that is the hook.

Inside the original 256 KB the diff from AT is **8 runs, 81 bytes**: five
section-header fields, the 64-byte helper replaced by a jump plus `int3`
filler, the 10-byte diagnostic hook at `0xB5F3` that AV already had, and one
byte of build tag. Everything else lives in the appended sections.

## 72. Residual risks in AW

- **First hook this patcher installs into game code.** The pristine mod already
  installs three, but those are its own. The atomicity argument above is why
  this one is believed safe; it has not yet been observed running.
- If `VirtualAlloc` cannot find a page within ±2GB after 16 tries the hook does
  not arm and the mod falls back to AT's behaviour. Expected to be rare.
- The trampoline page is never freed. One page, once, for the process lifetime.
- Untested in game.

## 73. Build AW result — the object was always right

Tested 2026-08-27, one F4 press from normal gameplay. Nothing opened; no
freeze, no crash, no reported stutter. Deployed ASI `D1103D64…B7E6C9`, the AW
artifact; banner `CD 2.00.AW`. Retained log:
`logs/2.00-AW/PrivateStorageAnywhere-AW-2026-08-27.log`,
SHA-256 `996A57CA0A746A4E18163B010AC25D565DDE87BD47D7E6F11381434289DB0AF4`.

```text
  [MODE] capture hook armed at 140530E20 -> 13FF00000
HOTKEY Private (vk=0x73) -> OPEN
  [MODE] root=2775C0CDF00 menuMgr=2775C195000 capture=2775D2A4F60
  [MODE] c0 ptr=2775D2A4F60 m=00 s=00 f=00 t=00 d=01
  [MODE] c1 ptr=2775D2A4F60 m=00 s=00 f=00 t=00 d=01
  [MODE] c2 ptr=2775F833FA0 m=01 s=00 f=03 t=00 d=67
BLOCKED: unsafe state (mode=0x00 sub=0x00)
```

The hook armed: the target is game base + `0x530E20`, the trampoline sits at
base − `0x100000` (the first `VirtualAlloc` hint), and reaching that line means
stage 5 completed — so the fifteen-byte prologue guard passed and the atomic
store landed.

**`c0` and `c1` are the same pointer.** `c0` is what ModeSwitch itself was
handed; `c1` is `[menuMgr+0x1158]`, exactly what AT uses. `menuMgr` is
recomputed live from the global at hotkey time, so this is not two stale values
agreeing — the live walk independently arrives at the object the game uses.
Stale capture cannot explain it either, for the same reason.

The §65 marshalling fix is cross-validated by the two runs agreeing on every
stable field: for c2, AV's corrected reading `+0x50=01 +0x38=00 +0x5B=67`
matches AW's `m=01 t=00 d=67`; for c1, `+0x50=00 +0x38=00 +0x5B=01` matches.

### Retractions

- **§59 is backwards.** "Right offsets, wrong object" should read *right
  object, wrong mode/sub-mode offsets*. The route `root -> +0x90 -> +0x1158`
  was correct from AT onward.
- **§69 over-read its own result.** The survey established that no *short
  static path from a global* reaches `+0x1158`, which is true and unremarkable:
  `menuMgr` is passed around as a parameter rather than re-derived near each
  use. It does **not** show that `menuMgr` is the wrong instance, and the
  "same class, two live instances" reading is withdrawn.
- **§67's layout re-confirmation was worthless.** Observing that ModeSwitch
  "touches all five offsets" cannot distinguish a field from a shadow copy of a
  different field. It gave false confidence in the very value that was wrong.
- §60–§63 and §66's candidate work answered a question that did not need
  asking. The measurements stand; the framing does not.

## 74. The mode is at +0x28, not +0x50

`game+0x531129..0x53119D` is a 17-byte block copy inside ModeSwitch:

```text
531129  movzx eax,[rbx+0x38] ; mov [rbx+0x49],al
...
53115A  movzx eax,[rbx+0x3F] ; mov [rbx+0x50],al     <- taken for "mode"
531161  movzx eax,[rbx+0x40] ; mov [rbx+0x51],al     <- taken for "sub-mode"
...
531199  movzx eax,[rbx+0x48] ; mov [rbx+0x59],al
```

`+0x50` and `+0x51` are **shadow_subtypes[7] and [8]** — elements of the
previous-frame copy of the subtypes array at `+0x49`. The mod has been reading
one of those and calling it the mode. It is zero, which is the entire reason
every open since AT was refused with `mode=0x00`.

The real fields are at **`+0x28`** and **`+0x29`**, established three ways from
the game's own code:

```text
53147B  movzx edx, byte [rbx+0x28]   ; mode     -> BuildModeTagList arg dl
53148D  movzx r8d, byte [rbx+0x29]   ; sub-mode -> BuildModeTagList arg r8b
531492  call  BuildModeTagList
5314B4  mov byte [rbx+0x28], r12b    ; commit new mode
5314B8  mov byte [rbx+0x29], sil     ; commit new sub-mode
530EA9  test byte [rbx+0x28], 0xFB ; jne    ; proceed only when mode is 0 or 4
```

`rbx = rcx` from entry, so all three are on the object itself.

### The corrected layout — one uniform +0x10

```text
              1.18.2   2.00
mode           0x18     0x28
submode        0x19     0x29
flags[7]       0x21     0x31
subtypes[17]   0x28     0x38
shadow[17]     0x39     0x49
dirty          0x4B     0x5B
```

Nothing moved oddly. §57's "mode/submode moved +0x38" was only ever the
derivation defect below.

### The derivation defect

`derive_from_modeswitch` looked for two adjacent byte stores through the same
base register, with the offset also present in a `compared` set — a guard whose
own comment named the shadow-copy trap it was meant to defeat. The guard
accepted **any** `cmp byte ptr [<any reg> + disp], <anything>`. On 2.00,
`cmp byte ptr [rdi + 0x50], 0` at `game+0x531322` — a different object, an
immediate, nothing to do with the mode — put `0x50` into the set. The scan runs
in address order, the shadow copy supplies sixteen adjacent pairs, and
`0x50/0x51` at `game+0x53115E` won. The correct pair at `game+0x5314B4` was
never reached.

Fixed with three independent constraints, any one of which suffices here:

1. the compare's source must be a **register** — this is `cmp [obj+mode],
   newMode`, never a compare against 0;
2. the compare and the stores must share a **base register**;
3. a pair whose source was just `movzx`-loaded from the same object at a lower
   displacement is copy traffic, not a field write.

Plus a positive anchor preferred over the store pattern: the two bytes loaded
into `edx`/`r8d` immediately before `call BuildModeTagList`. Both the anchor
and the tightened store rule independently return `0x28/0x29` on 2.00.

`derive()` now also enforces the block's internal spacing as **cross-checks
that fail the build, never as a source of values**: `submode == mode+1`,
`flags == mode+9`, `subtypes == flags+7`, `dirty == subtypes+0x23`. The defect
violated `flags == mode+9` by 0x28 and would have been caught immediately.

`_derive`'s `say()` helper called itself instead of `print`, so the tool could
never run standalone. Fixed.

**No control binary is available.** `baseline/CrimsonDesert.exe` is not 1.18.2 —
its `SizeOfImage` is `0x15E90000` and its tag pool has no `store` entry, so the
derivation cannot run on it. The 1.18.2 column above is from the historical
record, not re-measured.

## 75. Build AX — the corrected offsets

Five bytes differ from AW inside the original image:

```text
rva 0x0146D  50 -> 28    MODE_OFF immediate in the layout stub
rva 0x01477  51 -> 29    SUB_OFF immediate
rva 0x0B5F4  e3 bd -> 77 be   the diagnostic hook's rel32 (the block grew)
rva 0x2D117  57 -> 58    build tag AW -> AX
```

The capture hook is kept. It is now empirically safe — it armed and ran through
a full session with no adverse effect — its fallback is AT's walk, and it makes
the object identity self-verifying in every future log, which is the evidence
that would have shortened this investigation by two rounds.

Two probe changes, both aimed at the failure mode rather than the failure:

- **The probe no longer carries its own copy of the offsets.** `fin` emitted
  literal `+0x50/+0x51/+0x31/+0x38/+0x5B` while the patch used the derived
  `L_*`. Two sources of truth meant the probe agreed with the bug instead of
  exposing it. It now emits the derived values.
- **The discarded pair is logged.** The format gained `x=%02X%02X` carrying
  `+0x50/+0x51`, so any future divergence between the derived mode and the
  shadow array is visible in the log. `fin`'s frame grew to `0x68` with the
  saved pointer and index at `+0x50/+0x58`, above the nine-argument block.
- Every byte the probe reads is now individually `rdbl`-guarded; AV and AW
  guarded only three of them.

```text
output  C2B9848F33A3822532C563C31965F4DFF74B0D02A369AE7626D3E43056C49840
zip     A2F5526AD5EF502611CCC8446B7093AB4B6836748345E8013906ECE5C78165AF
```

`tools/validate_aw.py` passes all 35 checks, now including that the probe's
emitted offsets equal the derived layout and that every read offset is guarded.
Prior builds AT, AU, AV and AW are untouched and match their recorded hashes.

### Residual risk

If the check now passes, the mod writes flags/subtypes/dirty and drives a mode
transition **for the first time on 2.00**. That path has never executed on this
game version. Stop conditions for the test must cover a stuck or wrong UI mode,
not only crashes.

Untested in game.

## 76. Build AX result — working. Crimson Desert 2.00 is fixed.

Tested 2026-08-27. All six panels opened and closed; both capacity behaviours
confirmed; no freeze, crash or visual anomaly. Deployed ASI
`C2B9848F…C49840`, banner `CD 2.00.AX`, `Size: 0x16499000`. Retained log
`logs/2.00-AX/PrivateStorageAnywhere-AX-2026-08-27.log`, SHA-256
`A1D7349009FE06C771DAA2C15D6C3647F2AB80F398696663DEBF2016E1474E7D`; the INI as
tested is beside it and is byte-identical to the released one.

### The line that closes the investigation

```text
  [MODE] capture hook armed at 140530E20 -> 13FF00000
HOTKEY Private (vk=0x73) -> OPEN
=== OPENING WAREHOUSE (Private) ===
  Warehouse opened (mode=0x04 sub=0x10)
  Warehouse opened (mode=0x04 sub=0x05)
```

`mode=0x04` is the byte at `+0x28` — the field §74 identified. Every open in the
log reports it. **There is no `BLOCKED` line anywhere in this log**, and
therefore no `[MODE] cN` probe lines either: the probe is hooked on the refusal
path only, so its silence is the pass signal.

All six panels show a matched `OPENING`/`CLOSING` pair ending
`Warehouse closed (mode=0x04 sub=0x05)`, with `activePanel` walking 0→5. VK
`0x73..0x78` map to F4..F9; Private opened and closed twice, the other five
once each. All three hooks installed `OK`.

### Capacity — two features, and the evidence for each

**F4, configurable.** With `PrivateStorageSlots=1000`:

```text
  [PRIV] base=240 max=1000 exp=200 owner=5AF351B2300 n=18
  [PRIV] exp=200 (0x16=200 tot=440) base 240 -> 800
  [PRIV] container total 440 -> 1000
```

240 base + 200 bought expansions = 440 natural total; the requested total of
1000 gives base 1000 − 200 = 800, and the container total is written as exactly
1000. `max` is `word[info+0x4A]`, the entry's own ceiling — **not** the INI
value, which is why it still reads 1000 after the setting is returned to 0.

On close the base was restored (`base 800 -> 240`), and the next open with the
setting at 0 logged `container total 1000 -> 440` — the game's own 240 + 200 —
with no base write, because the `tfix` shortcut skips a write that is already
correct.

**F5–F9, fixed.** `InventoryInfo slot patch: 5 entries default 10 -> 1000`
appears once, at startup, and no later line writes those entries.

**Their independence is structural, not observed.** The log never prints F5–F9
slot counts, so it cannot prove the decoupling on its own. The proof is in the
wrapper's ordering:

```text
865  call AW_HOOKINST          ; capture hook, one-shot
866  call SLOT_PATCHER         ; F5-F9 1000-slot patch   <-- UNCONDITIONAL
867  mov [rsp+0x30], eax       ; return value preserved, returned at `done`
869  ... GetPrivateProfileIntA "PrivateStorageSlots"     <-- read AFTER
889  cmp dword [rsp+0x38], 0
890  jne armed
891  mov eax,[PS_DIRTY] ; test eax,eax ; je done         <-- the only early-out
```

The housing patch runs before the setting is read, and the sole early-out is
downstream of it. `PrivateStorageSlots` cannot reach it at any value. The F4
restore path reads `BASE_ORIG` — the game's own base, captured before any write
— and does nothing at all if it was never captured, so a save that never had
the option enabled is never touched.

### What the log does not show, stated plainly

- **No F11 / INI-reload event line exists.** Both capacity settings are re-read
  with `GetPrivateProfileIntA` on *every* panel open, so the two Private opens
  directly exhibit the two INI states. `ReloadKey=7A` (F11) rebinds hotkeys.
  The user's reload observation is user evidence; the log corroborates the
  effect, not the mechanism.
- **No F5–F9 capacity readout.** See above.

### Non-blocking warnings carried into release

Each has a working fallback and matches the shipped 1.18.2 behaviour:
`SetDonationFaction: FAIL` → `DonationOff: FALLBACK offset=0x330`;
`SetTitleDir: FAIL`; `Type resolver: DISABLED` → INI fallback;
`Gatherables panel-id lookup FAILED` → `PanelValue override … source=INI
fallback`, expected on the first housing panel of a session. Cosmetic only:
messages naming `1.06` / `Apr-23 1.0.4.1` / `1.13+ layout` are inherited
strings and version-gated workarounds, and the `READY!` banner says "Press F6"
while Private is F4.

### Release

Shipped as the **exact tested binary** — no rebuild, no cleanup pass. The
diagnostic probe is deliberately retained: it is inert unless an open is
refused, it is what identified the 2.00 problem, and it makes future breakage
self-diagnosing from a log alone. Removing it would change the binary and void
the test that justifies shipping.

```text
release ZIP     6EDE4EB366C46F56B32FABFCBD4CEBDD29F0E819C4DD984F9EA92D33E4BDC66F
  ASI           C2B9848F33A3822532C563C31965F4DFF74B0D02A369AE7626D3E43056C49840
  INI           9A949FD3FCD3845C1FD8FB93247620F0D8DADB17C8DCC2DB5F3DDE4AF4EC8FCD
```

Verified before release: a clean rebuild from the pristine input and the 2.00
executable reproduces `C2B9848F…` bit for bit; the ZIP member, the AX artifact,
the staged package and the file the user actually ran are one identical byte
stream; the ZIP passes `testzip()`; the PE read straight out of the archive has
8 sections, 589 exception entries and no `pefile` warning beyond the pristine
input's two; and the packaged INI ships `PrivateStorageSlots=0` — the existing
documented default, byte-identical to the 1.18.2 release INI, not a new choice.

`tools/validate_aw.py` passes every check on the released binary.

**No further manual test is necessary.** The released artifact is the binary
that produced this log.
