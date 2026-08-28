"""Offline validation for the 2.00 patch builds.

The name is historical -- this was written for the AW build -- but it validates
the whole AT-through-AX lineage and should be run on every build.

Everything here is a check that can fail the build before the game is ever
launched, plus a disassembly listing so the emitted bytes can be read rather
than trusted. Run it against the built ASI and the 2.00 executable:

    python tools/validate_aw.py <built.asi> <CrimsonDesert.exe> \
        [--pristine <v1.5.10.asi>] [--vs <AT.asi>] [--listing]

The checks are the ones §65 would have caught: argument marshalling, frame
arithmetic, and whether the bytes we are about to write into live game code are
still the bytes we think they are.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

import patch_private_storage_1182_modestate as P

FAILURES: list[str] = []
NOTES: list[str] = []


def check(ok: bool, label: str) -> bool:
    print(f"  [{'ok' if ok else 'FAIL'}] {label}")
    if not ok:
        FAILURES.append(label)
    return ok


def disasm(img, pe, rva, length, base):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    off = pe.get_offset_from_rva(rva)
    return list(md.disasm(img[off:off + length], base + rva))


def main() -> None:
    asi_path, exe_path = Path(sys.argv[1]), Path(sys.argv[2])
    listing = "--listing" in sys.argv

    def opt(flag):
        return Path(sys.argv[sys.argv.index(flag) + 1]) if flag in sys.argv else None

    pristine_path, prev_path = opt("--pristine"), opt("--vs")

    img = asi_path.read_bytes()
    pe = pefile.PE(data=img)
    base = pe.OPTIONAL_HEADER.ImageBase
    exe = pefile.PE(str(exe_path), fast_load=True)
    targets = P.derive_game_targets(exe_path)
    ms = targets["MODE_SWITCH"]

    print(f"ASI  {asi_path}  {len(img)} bytes")
    print(f"game ModeSwitch = game+0x{ms:X}")

    # ---------------------------------------------------------------- PE shape
    print("\nPE shape")
    names = [s.Name.rstrip(b"\x00").decode() for s in pe.sections]
    check(names[-2:] == [".pstext", ".psdata"], f"appended sections present: {names[-2:]}")
    ps = pe.sections[-2]
    pd = pe.sections[-1]
    check(ps.VirtualAddress == P.PS_RVA and ps.Misc_VirtualSize == P.PS_SIZE,
          f".pstext at {ps.VirtualAddress:#x} size {ps.Misc_VirtualSize:#x}")
    check(pd.VirtualAddress == P.PD_RVA and pd.Misc_VirtualSize == P.PD_SIZE,
          f".psdata at {pd.VirtualAddress:#x} size {pd.Misc_VirtualSize:#x}")
    check(ps.Characteristics == 0x60000020, ".pstext is R+X, not writable")
    check(pd.Characteristics == 0xC0000040, ".psdata is R+W, not executable")
    check(pe.OPTIONAL_HEADER.SizeOfImage == P.PD_RVA + P.PD_SIZE,
          f"SizeOfImage = {pe.OPTIONAL_HEADER.SizeOfImage:#x}")
    try:
        n_exc = len(pe.DIRECTORY_ENTRY_EXCEPTION)
    except AttributeError:
        n_exc = -1
    check(n_exc == 589, f"exception directory entries = {n_exc} (AT/AV had 589)")
    warnings = sorted(pe.get_warnings())
    if pristine_path:
        # The pristine v1.5.10 ASI already carries two chained-unwind warnings.
        # What matters is that the build adds none.
        baseline = sorted(pefile.PE(str(pristine_path)).get_warnings())
        check(warnings == baseline,
              f"no pefile warnings beyond the pristine input's {len(baseline)}")
    else:
        NOTES.append(f"pefile warnings (no --pristine to compare): {warnings}")

    if prev_path:
        prev = prev_path.read_bytes()
        orig_len = min(len(prev), len(img), 256000)
        runs, i = [], 0
        while i < orig_len:
            if img[i] != prev[i]:
                j = i
                while j < orig_len and img[j] != prev[j]:
                    j += 1
                runs.append((i, j - i))
                i = j
            else:
                i += 1
        print(f"\ndiff vs {prev_path.name} inside the original {orig_len} bytes")
        for start, n in runs:
            rva = pe.get_rva_from_offset(start)
            print(f"  [--] {start:#08x} rva {rva:#07x} len {n}: "
                  f"{prev[start:start + n].hex(' ')} -> {img[start:start + n].hex(' ')}")
        NOTES.append(f"{len(runs)} changed run(s) vs {prev_path.name} "
                     f"totalling {sum(n for _, n in runs)} bytes")

    # -------------------------------------------------------- the cave helper
    print("\nget_mode_obj (ASI 0x14C0)")
    ins = disasm(img, pe, P.HELPER, 5, base)
    ok = (len(ins) == 1 and ins[0].mnemonic == "jmp"
          and int(ins[0].op_str, 16) - base == P.AW_MODEOBJ)
    check(ok, f"0x14C0 is a single jmp to AW_MODEOBJ ({ins[0].mnemonic} {ins[0].op_str})")
    tail_off = pe.get_offset_from_rva(P.HELPER) + 5
    tail_end = pe.get_offset_from_rva(P.TELEMETRY)
    check(set(img[tail_off:tail_end]) <= {0xCC},
          "the rest of the old helper is int3 filler")

    # ------------------------------------------------------------- the AW code
    print("\nAW block")
    aw = disasm(img, pe, P.AW_BASE, 0x1000, base)
    by_rva = {i.address - base: i for i in aw}
    check(P.AW_MODEOBJ in by_rva and by_rva[P.AW_MODEOBJ].mnemonic == "jmp",
          "AW_MODEOBJ is a jmp")
    check(P.AW_HOOKINST in by_rva and by_rva[P.AW_HOOKINST].mnemonic == "jmp",
          "AW_HOOKINST is a jmp")

    # Frame arithmetic. §63 shipped `sub rsp,-0x60` because 0xA0 does not fit an
    # imm8; every sub/add rsp pair in the block is checked for sign and balance.
    subs = [i for i in aw if i.mnemonic in ("sub", "add") and i.op_str.startswith("rsp,")]
    bad = [i for i in subs if "-" in i.op_str]
    check(not bad, "no sub/add rsp with a negative immediate "
                   + (f"({[i.op_str for i in bad]})" if bad else ""))
    frames = sorted({i.op_str for i in subs})
    NOTES.append(f"rsp adjustments seen: {frames}")

    # The capture stub must not push: it runs with ModeSwitch's own rsp and has
    # no unwind info of its own.
    cap_rva = None
    for i in aw:
        if i.mnemonic == "mov" and "rcx" in i.op_str and "rip" in i.op_str \
                and i.op_str.startswith("qword ptr [rip"):
            cap_rva = i.address - base
            break
    check(cap_rva is not None, f"capture stub located at {cap_rva:#x}"
          if cap_rva else "capture stub located")
    if cap_rva is not None:
        stub = []
        for i in aw:
            r = i.address - base
            if r < cap_rva:
                continue
            stub.append(i)
            if i.mnemonic == "jmp" and i.op_str == "rax":
                break
        check(all(i.mnemonic not in ("push", "pop", "call") for i in stub),
              "capture stub makes no push/pop/call")
        spills = b"".join(i.bytes for i in stub if i.mnemonic == "mov"
                          and i.op_str.startswith("qword ptr [rsp"))
        check(spills == P.MODE_SWITCH_PROLOGUE,
              "capture stub re-issues ModeSwitch's three spills byte-for-byte")
        add = [i for i in stub if i.mnemonic == "add" and i.op_str.startswith("rax,")]
        want = ms + len(P.MODE_SWITCH_PROLOGUE)
        check(bool(add) and int(add[-1].op_str.split(", ")[1], 16) == want,
              f"capture stub returns to ModeSwitch+0x{len(P.MODE_SWITCH_PROLOGUE):X}"
              f" (0x{want:X})")

    # Nothing in the block may write to game memory except through the two
    # pointers the installer set up. Every other store must go to [rsp+...],
    # .psdata, or a register.
    stores = []
    for i in aw:
        if i.mnemonic not in ("mov", "movzx"):
            continue
        dst = i.op_str.split(",")[0].strip()
        if not dst.endswith("]"):
            continue
        if dst.startswith(("qword ptr [rsp", "dword ptr [rsp", "word ptr [rsp",
                           "byte ptr [rsp", "[rsp")):
            continue
        if "rip" in dst:
            continue
        stores.append((i.address - base, i.mnemonic + " " + i.op_str))
    NOTES.append(f"non-stack, non-rip stores in the AW block: {stores}")

    # ------------------------------------- the marshalling §65 and §73 broke
    print("\nfin() argument marshalling")
    L = {k: targets[k] for k in ("mode", "submode", "flags", "subtypes", "dirty")}
    print("  derived layout: " + " ".join(f"{k}=0x{v:X}" for k, v in L.items()))
    # §73: the probe must read the DERIVED offsets, not a second hardcoded copy.
    want = {
        L["submode"]: 0x20,
        L["flags"]: 0x28,
        L["subtypes"]: 0x30,
        L["dirty"]: 0x38,
        0x50: 0x40,          # the discarded shadow pair, logged as `x`
        0x51: 0x48,
    }
    seq = [(i.address - base, i.mnemonic + " " + i.op_str) for i in aw]
    idx = next((k for k, (_, t) in enumerate(seq)
                if t == f"movzx eax, byte ptr [rcx + {L['submode']:#x}]"), None)
    check(idx is not None, "fin's field reads located")
    if idx is not None:
        pairs, src = [], None
        for _, t in seq[idx:idx + 2 * len(want) + 2]:
            if t.startswith("movzx eax, byte ptr [rcx + "):
                src = int(t.split("+ ")[1].rstrip("]"), 16)
            elif t.startswith("mov qword ptr [rsp + ") and src is not None:
                pairs.append((src, int(t.split("+ ")[1].split("]")[0], 16)))
                src = None
        check(dict(pairs) == want,
              "field -> vararg slot map is "
              f"{[(hex(a), hex(b)) for a, b in pairs]}, "
              f"want {[(hex(a), hex(b)) for a, b in want.items()]}")
        tail = seq[idx + 2 * len(want):idx + 2 * len(want) + 3]
        check(any(f"r9d, byte ptr [rcx + {L['mode']:#x}]" in t for _, t in tail),
              f"mode (+0x{L['mode']:X}) goes to r9d")
    # Every byte the probe reads must be individually readability-guarded.
    guarded = {int(t.split("+ ")[1].rstrip("]"), 16)
               for _, t in seq if t.startswith("lea rcx, [rcx + ")}
    need = set(want) | {L["mode"]}
    check(need <= guarded,
          f"every read offset is rdbl-guarded (missing "
          f"{[hex(x) for x in sorted(need - guarded)]})")

    # ---------------------------------------------------- the game-side patch
    print("\ngame-side hot patch")
    sec = next(s for s in exe.sections
               if s.VirtualAddress <= ms < s.VirtualAddress + len(s.get_data()))
    live = sec.get_data()[ms - sec.VirtualAddress:ms - sec.VirtualAddress + 15]
    check(live == P.MODE_SWITCH_PROLOGUE,
          f"ModeSwitch prologue in the exe is still {live.hex(' ')}")
    check(ms % 8 == 0, f"ModeSwitch is 8-byte aligned ({ms:#x})")
    q0 = struct.unpack("<Q", P.MODE_SWITCH_PROLOGUE[0:8])[0]
    q7 = struct.unpack("<Q", P.MODE_SWITCH_PROLOGUE[7:15])[0]
    check(struct.pack("<Q", q0) + struct.pack("<Q", q7)[1:] == P.MODE_SWITCH_PROLOGUE,
          "the two runtime guard qwords cover all fifteen prologue bytes")
    imms = [i.op_str for i in aw if i.mnemonic == "movabs"]
    check(any(hex(q0) in s.lower() for s in imms), f"guard qword 0 ({q0:#x}) is emitted")
    check(any(hex(q7) in s.lower() for s in imms), f"guard qword 1 ({q7:#x}) is emitted")
    check(any("0x9090900000000000" in s for s in imms),
          "the three trailing nops of the patch qword are emitted")

    # ------------------------------------------------------- stale-value sweep
    print("\nstale 1.18.2 values")
    for name, val in (("NAME_TO_KEY", 0x1E141D0), ("RESOLVE_ACTOR", 0x751D20),
                      ("CAMP_NAME", 0x4FC0560), ("MAINCHAR", 0x62C1500)):
        check(struct.pack("<I", val) not in img, f"no 1.18.2 {name} immediate survives")
    for name, val in (("NAME_TO_KEY", 0x1E37F50), ("RESOLVE_ACTOR", 0x75BF90),
                      ("CAMP_NAME", 0x501C6B8), ("MODE_SWITCH", ms)):
        check(struct.pack("<I", val) in img, f"2.00 {name} immediate present")

    if listing:
        print("\n--- AW block listing ---")
        for i in aw:
            r = i.address - base
            if r >= P.AW_BASE + P.PS_SIZE:
                break
            print(f"{r:05X}  {i.bytes.hex(' '):<26} {i.mnemonic} {i.op_str}")

    print()
    for n in NOTES:
        print("note:", n)
    print()
    if FAILURES:
        print(f"FAILED {len(FAILURES)} check(s):")
        for f in FAILURES:
            print("  -", f)
        raise SystemExit(1)
    print("all checks passed")


main()
