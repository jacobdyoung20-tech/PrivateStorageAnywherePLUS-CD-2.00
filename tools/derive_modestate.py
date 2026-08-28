"""Re-derive the game's mode-state layout from the executable itself.

This is the replacement for the mod's original layout resolver, which only
scanned for struct offsets in a hardcoded 0xC00-0xCFF window (see
`compare_modeswitch.py`) and therefore reported "no fields" on 1.18.2, when in
fact the fields had merely moved to small displacements.

The derivation is anchored on data the game cannot rename without changing
behaviour -- the UI mode-tag strings -- rather than on any absolute address:

  1. find the tag strings ("store", "ingame-global", ...) in the data sections
  2. find BuildModeTagList: the function that LEAs the "global" tag and then
     switches on two jump tables
  3. read the jump tables to learn which mode emits `ingame-global` and which
     sub-mode emits `store`
  4. find ModeSwitch: the caller that commits two adjacent bytes after building
     an old and a new tag list
  5. read the request-array offsets out of ModeSwitch's two scan loops

Usage:
    python tools/derive_modestate.py <CrimsonDesert.exe>
"""
from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

import capstone
import pefile

TAGS = (
    b"hud-info", b"ingame-global", b"global", b"subtitle", b"quickslot",
    b"interaction", b"hud-play", b"gimmick", b"cinema", b"store", b"fadeout",
)


def code_sections(pe):
    return [s for s in pe.sections if s.Characteristics & 0x20000000]


def find_tag_pool(pe, data):
    """Locate the contiguous tag-name pool and return {va: name}."""
    base = pe.OPTIONAL_HEADER.ImageBase
    anchor = data.find(b"\x00ingame-global\x00")
    if anchor < 0:
        raise SystemExit("tag pool not found: 'ingame-global' is absent")
    anchor += 1
    lo, hi = max(0, anchor - 0x40), anchor + 0x180
    out = {}
    for tag in TAGS:
        at = data.find(b"\x00" + tag + b"\x00", lo, hi)
        if at < 0:
            continue
        off = at + 1
        try:
            out[base + pe.get_rva_from_offset(off)] = tag.decode()
        except pefile.PEFormatError:
            pass
    if b"store" not in {v.encode() for v in out.values()}:
        raise SystemExit("tag pool found but 'store' is missing from it")
    return out


def find_tag_builder(pe, data, tag_vas):
    """The function that LEAs a tag string; returns (func_rva, lea_rva)."""
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in code_sections(pe):
        raw = section.get_data()
        sva = base + section.VirtualAddress
        for i in range(len(raw) - 7):
            if raw[i] != 0x48 or raw[i + 1] != 0x8D or raw[i + 2] & 0xC7 != 0x05:
                continue
            target = sva + i + 7 + struct.unpack_from("<i", raw, i + 3)[0]
            if target not in tag_vas:
                continue
            rva = section.VirtualAddress + i
            owner = owning_function(pe, rva)
            if owner:
                return owner, rva
    raise SystemExit("no code reference to any tag string")


def owning_function(pe, rva):
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        s = entry.struct
        if s.BeginAddress <= rva < s.EndAddress:
            return (s.BeginAddress, s.EndAddress)
    return None


def disasm(pe, va, nbytes):
    base = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return list(md.disasm(pe.get_data(va - base, nbytes), va))


def read_jump_tables(pe, func, tag_vas):
    """Find `cmp r,N / ja / mov r,[base+idx*4+TBL]` dispatches in the builder."""
    base = pe.OPTIONAL_HEADER.ImageBase
    lo, hi = func
    tables = []
    insns = disasm(pe, base + lo, hi - lo)
    for ins in insns:
        if ins.mnemonic != "mov":
            continue
        for op in ins.operands:
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            if op.mem.index == 0 or op.mem.scale != 4 or op.mem.disp <= 0x1000:
                continue
            tables.append(op.mem.disp)
    resolved = []
    # The mode table has 7 entries and the sub-mode table 17; reading past the
    # end of the first one just re-reads the second, so bound each table by the
    # `cmp reg, N / ja` immediately preceding its dispatch.
    bounds = []
    for ins in insns:
        if ins.mnemonic == "cmp" and len(ins.operands) == 2:
            a, b_ = ins.operands
            if a.type == capstone.x86.X86_OP_REG and b_.type == capstone.x86.X86_OP_IMM:
                if 0 < b_.imm <= 0x40:
                    bounds.append(b_.imm + 1)
    for idx, tbl in enumerate(dict.fromkeys(tables)):
        count = bounds[idx] if idx < len(bounds) else 0x11
        entries = []
        try:
            raw = pe.get_data(tbl, count * 4)
        except Exception:
            continue
        for i in range(count):
            rel = struct.unpack_from("<i", raw, i * 4)[0]
            target = base + rel
            entries.append((i, target, tags_emitted(pe, target, tag_vas)))
        resolved.append((tbl, entries))
    return resolved


def tags_emitted(pe, va, tag_vas, limit=40):
    out = []
    try:
        insns = disasm(pe, va, 320)
    except Exception:
        return out
    for ins in insns[:limit]:
        if ins.mnemonic == "lea":
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    if t in tag_vas:
                        out.append(tag_vas[t])
        if ins.mnemonic in ("jmp", "ret"):
            break
    return out


def callers_of(pe, target_va):
    base = pe.OPTIONAL_HEADER.ImageBase
    hits = []
    for section in code_sections(pe):
        raw = section.get_data()
        sva = base + section.VirtualAddress
        pos = 0
        while True:
            i = raw.find(b"\xE8", pos)
            if i < 0 or i + 5 > len(raw):
                break
            pos = i + 1
            rel = struct.unpack_from("<i", raw, i + 1)[0]
            if sva + i + 5 + rel == target_va:
                hits.append(sva + i)
    return hits


def derive_from_modeswitch(pe, func, builder_va=None):
    """Read mode/submode/flags/subtypes/dirty offsets out of ModeSwitch."""
    base = pe.OPTIONAL_HEADER.ImageBase
    lo, hi = func
    insns = disasm(pe, base + lo, hi - lo)

    # mode/submode: two adjacent byte stores of a register into the same base.
    #
    # Careful: ModeSwitch also copies the whole subtypes array byte-by-byte into
    # a shadow slot (0x28+i -> 0x39+i on 1.18.2, 0x38+i -> 0x49+i on 2.00). That
    # copy produces sixteen consecutive "adjacent store pairs" that look exactly
    # like the real thing, so the disambiguation has to be airtight.
    #
    # It was not, and 2.00 walked straight into it: the guard below used to
    # accept ANY `cmp byte ptr [<any reg>+disp], <anything>`. On 2.00
    # `cmp byte ptr [rdi+0x50], 0` at game+0x531322 -- a different object and an
    # immediate, nothing to do with the mode -- put 0x50 in the set, the
    # address-ordered scan reached the shadow pair 0x50/0x51 first, and the mod
    # spent two test rounds reading shadow_subtypes[7] as the mode. See
    # FINDINGS-2.00.md §73.
    #
    # Three constraints now, any one of which would have caught it:
    #   1. the compare's source must be a REGISTER -- this is the "has the mode
    #      changed" test, `cmp [obj+mode], newMode`, never a compare with 0;
    #   2. the compare and the stores must share a base register, so a probe of
    #      some unrelated object cannot vote;
    #   3. the pair must not be part of a shadow-copy run.
    compared = set()
    for ins in insns:
        if ins.mnemonic != "cmp" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if src.type != capstone.x86.X86_OP_REG:
            continue
        if (dst.type == capstone.x86.X86_OP_MEM and dst.mem.index == 0
                and 0 < dst.mem.disp < 0x100 and "byte ptr" in ins.op_str):
            compared.add((dst.mem.base, dst.mem.disp))

    # A store is part of the shadow copy if its source register was loaded, in
    # the instruction immediately before, from the same object at a fixed
    # negative delta. Collect those deltas and treat any store matching the
    # dominant one as copy traffic rather than a field write.
    shadow = set()
    for prev, ins in zip(insns, insns[1:]):
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if dst.type != capstone.x86.X86_OP_MEM or src.type != capstone.x86.X86_OP_REG:
            continue
        if prev.mnemonic != "movzx" or len(prev.operands) != 2:
            continue
        pdst, psrc = prev.operands
        if psrc.type != capstone.x86.X86_OP_MEM or psrc.mem.index != 0:
            continue
        if psrc.mem.base != dst.mem.base or dst.mem.index != 0:
            continue
        if psrc.mem.disp < dst.mem.disp:
            shadow.add((dst.mem.base, dst.mem.disp))

    stores = []
    for ins in insns:
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if dst.type != capstone.x86.X86_OP_MEM or src.type != capstone.x86.X86_OP_REG:
            continue
        if ins.op_str.startswith("byte ptr") and dst.mem.index == 0 and 0 < dst.mem.disp < 0x100:
            stores.append((dst.mem.base, dst.mem.disp))

    # The positive anchor, preferred over the store pattern: the two bytes
    # ModeSwitch hands BuildModeTagList as its mode and sub-mode arguments.
    # That is what the fields ARE, rather than what they look like.
    #     movzx edx,  byte [obj+d]      -> arg 2 (dl)
    #     movzx r8d,  byte [obj+d+1]    -> arg 3 (r8b)
    #     call  BuildModeTagList
    mode = submode = None
    if builder_va is not None:
        loads = {}
        for ins in insns:
            if ins.mnemonic == "movzx" and len(ins.operands) == 2:
                dst, src = ins.operands
                if (src.type == capstone.x86.X86_OP_MEM and src.mem.index == 0
                        and 0 < src.mem.disp < 0x100 and src.mem.base):
                    loads[ins.reg_name(dst.reg)] = (src.mem.base, src.mem.disp)
            elif ins.mnemonic == "call":
                try:
                    target = int(ins.op_str, 16)
                except ValueError:
                    target = None
                if target == builder_va:
                    m, s = loads.get("edx"), loads.get("r8d")
                    if (m and s and m[0] == s[0] and s[1] == m[1] + 1
                            and (m[0], m[1]) not in shadow):
                        mode, submode = m[1], s[1]
                        break
                loads.clear()

    if mode is None:
        for reg, disp in stores:
            if (reg, disp + 1) not in stores:
                continue
            if (reg, disp) in shadow or (reg, disp + 1) in shadow:
                continue
            if (reg, disp) in compared:
                mode, submode = disp, disp + 1
                break

    # flags/subtypes: indexed byte compares inside the two scan loops.
    indexed = []
    for ins in insns:
        if ins.mnemonic != "cmp":
            continue
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.index and 0 < op.mem.disp < 0x100:
                indexed.append(op.mem.disp)
    # plus the `lea r,[base+disp]` walker form used by the sub-mode loop
    for ins in insns:
        if ins.mnemonic == "lea":
            for op in ins.operands:
                if (op.type == capstone.x86.X86_OP_MEM and op.mem.base
                        and op.mem.base != capstone.x86.X86_REG_RIP
                        and op.mem.index == 0 and 0 < op.mem.disp < 0x100):
                    indexed.append(op.mem.disp)
    candidates = sorted(set(indexed))
    flags = subtypes = None
    for value in candidates:
        if value + 7 in candidates:
            flags, subtypes = value, value + 7
            break

    # dirty: the flag ModeSwitch raises the moment it sees the tag list change.
    #
    # 2.00 broke the original heuristic (a compare sitting near the mode
    # compare), so match on what the flag actually does instead: it is stored
    # with an immediate 1 more than once -- once per "something changed" branch
    # -- and is read back with a compare against zero. On 2.00 that is +0x5B;
    # on 1.18.2 it was +0x4B.
    dirty = None
    set_once = collections.Counter()
    zero_tested = set()
    for ins in insns:
        ops = ins.operands
        if (ins.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == capstone.x86.X86_OP_MEM
                and ops[1].type == capstone.x86.X86_OP_IMM and ops[1].imm == 1
                and ops[0].mem.index == 0 and 0 < ops[0].mem.disp < 0x100
                and "byte ptr" in ins.op_str):
            set_once[ops[0].mem.disp] += 1
        if (ins.mnemonic == "cmp" and len(ops) == 2
                and ops[0].type == capstone.x86.X86_OP_MEM
                and ops[1].type == capstone.x86.X86_OP_IMM and ops[1].imm == 0
                and ops[0].mem.index == 0 and 0 < ops[0].mem.disp < 0x100
                and "byte ptr" in ins.op_str):
            zero_tested.add(ops[0].mem.disp)
    for disp, n in set_once.most_common():
        if n >= 2 and disp in zero_tested and disp not in (mode, submode):
            dirty = disp
            break

    # fall back to the pre-2.00 heuristic if that found nothing
    if dirty is None:
        dirty = _dirty_by_proximity(insns, mode)
    return mode, submode, flags, subtypes, dirty


def _dirty_by_proximity(insns, mode):
    dirty = None
    for i, ins in enumerate(insns):
        if ins.mnemonic != "cmp" or mode is None:
            continue
        ops = ins.operands
        if (ops and ops[0].type == capstone.x86.X86_OP_MEM
                and ops[0].mem.disp == mode and ops[0].mem.index == 0):
            for follow in insns[i:i + 6]:
                if follow.mnemonic == "cmp":
                    fops = follow.operands
                    if (fops and fops[0].type == capstone.x86.X86_OP_MEM
                            and fops[0].mem.index == 0
                            and 0 < fops[0].mem.disp < 0x100
                            and fops[0].mem.disp != mode):
                        dirty = fops[0].mem.disp
                        break
            if dirty:
                break
    return dirty


# The struct is one contiguous block and every field kept its position relative
# to the others between 1.18.2 and 2.00 -- the whole block simply moved +0x10:
#
#              1.18.2   2.00
#   mode        0x18     0x28
#   submode     0x19     0x29
#   flags[7]    0x21     0x31
#   subtypes[]  0x28     0x38
#   shadow[]    0x39     0x49
#   dirty       0x4B     0x5B
#
# These relationships are CROSS-CHECKS, never a source of values: every offset
# is still derived from the code independently, and a disagreement means the
# derivation is wrong and the build must stop. The 2.00 mode/sub-mode defect
# (§73) violated `flags == mode + 9` by 0x28 and would have been caught here.
INVARIANTS = (
    ("submode == mode + 1", lambda d: d["submode"] == d["mode"] + 1),
    ("flags == mode + 9", lambda d: d["flags"] == d["mode"] + 9),
    ("subtypes == flags + 7", lambda d: d["subtypes"] == d["flags"] + 7),
    ("dirty == subtypes + 0x23", lambda d: d["dirty"] == d["subtypes"] + 0x23),
)


def derive(exe_path, verbose=True):
    """Derive the mode-state layout. Returns a dict; raises if anything fails."""
    out = _derive(Path(exe_path), verbose)
    missing = [k for k, v in out.items() if v is None]
    if missing:
        raise RuntimeError("mode-state derivation failed for: " + ", ".join(missing))
    broken = [name for name, ok in INVARIANTS if not ok(out)]
    if broken:
        raise RuntimeError(
            "mode-state sanity failed: " + "; ".join(broken)
            + f"  (mode=0x{out['mode']:X} submode=0x{out['submode']:X} "
              f"flags=0x{out['flags']:X} subtypes=0x{out['subtypes']:X} "
              f"dirty=0x{out['dirty']:X})")
    return out


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    _derive(Path(sys.argv[1]), True)


def _derive(path, verbose):
    def say(*a):
        if verbose:
            print(*a)
    data = path.read_bytes()
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase

    tag_vas = find_tag_pool(pe, data)
    say(f"tag pool: {len(tag_vas)} names, "
          f"'store' at 0x{[k for k, v in tag_vas.items() if v == 'store'][0]:X}")

    builder, lea = find_tag_builder(pe, data, tag_vas)
    say(f"BuildModeTagList: game+0x{builder[0]:X}..0x{builder[1]:X} "
          f"(tag lea at game+0x{lea:X})")

    ingame_mode = store_sub = None
    for tbl, entries in read_jump_tables(pe, builder, tag_vas):
        labelled = [(i, t) for i, _, t in entries if t]
        if not labelled:
            continue
        say(f"  jump table game+0x{tbl:X}:")
        for i, tags in labelled:
            say(f"    [{i:2d}] {', '.join(tags)}")
        for i, tags in labelled:
            if "ingame-global" in tags and ingame_mode is None:
                ingame_mode = i
            if "store" in tags:
                store_sub = i

    callers = callers_of(pe, base + builder[0])
    say(f"callers of BuildModeTagList: {len(callers)}")

    best = None
    for va in callers:
        func = owning_function(pe, va - base)
        if not func or func == builder:
            continue
        derived = derive_from_modeswitch(pe, func, base + builder[0])
        if derived[0] is not None and derived[2] is not None:
            best = (func, derived)
            break
    if not best:
        raise SystemExit("could not identify ModeSwitch among the callers")
    func, (mode, submode, flags, subtypes, dirty) = best

    say(f"ModeSwitch: game+0x{func[0]:X}..0x{func[1]:X}")
    say()
    say("DERIVED LAYOUT")
    say(f"  mode        modeObj + 0x{mode:X}")
    say(f"  submode     modeObj + 0x{submode:X}")
    say(f"  flags[]     modeObj + 0x{flags:X}")
    say(f"  subtypes[]  modeObj + 0x{subtypes:X}")
    say(f"  dirty       modeObj + 0x{dirty:X}" if dirty else "  dirty       NOT FOUND")
    say(f"  in-game mode value   = {ingame_mode}")
    say(f"  store sub-mode value = {store_sub}")
    say()
    got = {"mode": mode, "submode": submode, "flags": flags,
           "subtypes": subtypes, "dirty": dirty}
    for name, ok in INVARIANTS:
        try:
            state = "OK" if ok(got) else "MISMATCH"
        except TypeError:
            state = "n/a"
        say(f"  sanity: {name:<26} -> {state}")
    return {"mode": mode, "submode": submode, "flags": flags,
            "subtypes": subtypes, "dirty": dirty,
            "ingame_mode": ingame_mode, "store_sub": store_sub}


if __name__ == "__main__":
    main()
