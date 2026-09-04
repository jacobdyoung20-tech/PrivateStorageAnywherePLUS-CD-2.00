"""CD 1.18.2 'W' modestate patch.

Rebased directly on the pristine Nexus v1.5.10 ASI. Restores the original open
mechanism -- drive the game's mode state machine into the `store` sub-mode so
the panel-manager mounts the warehouse view -- using the 1.18.2 field layout.

See FINDINGS-1.18.2-MODESTATE.md for the derivation of every constant here.

Game side (RVAs on 0x140000000):
    modeObj = *(menuMgr + MODE_OBJ_IN_MENUMGR)   # 0x1158 on 2.00, 0x1178 on 2.01.00
    modeObj + 0x18  mode        (4 == in-game)
    modeObj + 0x19  submode     (5 == dialog/store, 15/16 == gameplay)
    modeObj + 0x21  flags[7]        mode request, first non-zero index wins
    modeObj + 0x28  subtypes[17]    submode request, first non-zero index wins
    modeObj + 0x4B  dirty       must be set or ModeSwitch skips the transition
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

import pefile

EXPECTED_SHA256 = "4f514298b2bc5db7e804b0166ad2269bae97a414f7dae425a0f736cda7f56f3e"

# --- ASI globals -----------------------------------------------------------
MODE_OFF = 0x3C01C
SUB_OFF = 0x3C020
FLAGS_OFF = 0x3C024
SUBTYPES_OFF = 0x3C028
STORE_SUB_INDEX = 0x3C02C
MODE_ANCHOR = 0x3D4B0
SAVED_FLAGS = 0x4061C      # 7 bytes
SAVED_SUBTYPES = 0x40628   # 15 bytes

# --- ASI code --------------------------------------------------------------
GET_MENU_MGR = 0xAA30      # kept for reference; helper inlines its guards
GAME_GLOBAL_SLOT = 0x3D518 # holds the address of the game's global object slot
CAVE = 0x1460              # dead legacy layout resolver, 0x1460..0x15A9
CAVE_END = 0x15A9
HELPER = 0x14C0            # get_mode_obj lives here, inside the same cave
TELEMETRY = 0x1500         # W2 mode/sub-mode probe, same cave
DISARM = 0x1570            # Z disarm-then-init stub, same cave
ARM_FLAG = 0x408F4         # input thread arms this and re-posts 0x65B
INIT_PANEL = 0x4730        # InitWarehousePanel
CAPTURED_HANDLER = 0x3D528 # the mod's captured Warehouse2 controller
UI_CHILD_VEC = 0x168       # controller+0x168: the child vector the game walks
LOGGER = 0x6DE0            # the mod's printf-style log sink
FMT_OPENED = 0x2B1D8       # "  Warehouse opened (mode=0x%02X sub=0x%02X)"
FMT_DEFERRED = 0x2BF00     # "  Deferred init: handler captured, initializing panel"
FMT_BLOCKING = 0x29488     # repurposed by AA into the packet-type trace line
FMT_SLOTPATCH = 0x2D058    # "InventoryInfo slot patch: %d entries default 10 -> 1000"
INVMGR_PTR = 0x3D598       # holds the address of the game's inventory-manager global
SLOT_PATCHER = 0x8720      # the InventoryInfo slot patcher
SECTION_STR = 0x29020      # "Settings"
INI_PATH = 0x3D3A0         # the mod's MAX_PATH INI path buffer
GPP_INT = 0x28100          # IAT: GetPrivateProfileIntA
GAME_BASE = 0x3D350        # game image base
GAME_SIZE = 0x3D358        # and its SizeOfImage, stored beside it
# Game-side targets. Every one of these moved between 1.18.2 and 2.00, so
# they are derived from the executable at build time -- see
# derive_game_targets() -- rather than carried as constants.
CAMP_NAME = NAME_TO_KEY = RESOLVE_ACTOR = MODE_SWITCH = None
PS_RVA = 0x46000           # .pstext: appended code section
PS_RAW = 0x3E800           # its file offset (the image ends here)
PS_SIZE = 0x2000           # AW needs a second page: installer + capture stub
AW_BASE = PS_RVA + 0x1000  # the AW block starts here, at a FIXED rva, so the
                           # AO wrapper can call into it before it is emitted
AW_MODEOBJ = AW_BASE       # jmp -> the mode-object reader (get_mode_obj body)
AW_HOOKINST = AW_BASE + 5  # jmp -> the one-shot capture-hook installer
PD_RVA = 0x48000           # .psdata: its read/write companion
PD_RAW = 0x40800
PD_SIZE = 0x1000
EXP_CACHE = PD_RVA         # dword: cached expansion count, -1 = unknown
BASE_ORIG = PD_RVA + 4     # dword: the game's own base, captured untouched
PS_DIRTY = PD_RVA + 8      # dword: non-zero once this process has written
VQ_PTR = PD_RVA + 16       # qword: cached VirtualQuery, resolved once
VP_PTR = PD_RVA + 24       # qword: cached VirtualProtect
VA_PTR = PD_RVA + 32       # qword: cached VirtualAlloc
PS_MODEOBJ = PD_RVA + 40   # qword: the mode object, as ModeSwitch received it
PS_HOOKED = PD_RVA + 48    # dword: 0 untried, 1 installed, 2 gave up
PS_DIAG_CURSOR = PD_RVA + 56  # qword: stage-3 walk cursor at the moment it gave up
PS_DIAG_PAGE = PD_RVA + 64    # qword: the page stage 3 allocated, if it got that far
PS_DIAG_FREE = PD_RVA + 72    # dword: MEM_FREE regions the walk saw
PS_DIAG_TRIES = PD_RVA + 76   # dword: VirtualAlloc attempts it made
PS_DIAG_CAND = PD_RVA + 80    # qword: the last candidate it tried
PS_DIAG_ERR = PD_RVA + 88     # dword: GetLastError after the last failed VirtualAlloc
GLE_PTR = PD_RVA + 96         # qword: GetLastError, resolved in stage 1
PS_RETRIES = PD_RVA + 104     # dword: stage-3 soft failures so far (retried by the worker)
BLOCKED_FMT = 0x2B108      # "BLOCKED: unsafe state (mode=0x%02X sub=0x%02X)"
GETPROCADDRESS = 0x280F0   # IAT

# The pristine mod resolves the game root ("MainCharGlobal") itself, by scanning
# the game for `mov rax,[rip+G] ; mov REG,[rax+DISP8] ; cmp byte [REG+D],imm8`.
# Both DISP8 and the window D falls in are literals inside that scan: 0x48 and
# 0xC00..0xCFF. On 2.01.00 the game uses DISP8=0x10 and D=0xDD8, so the scan
# found nothing, MainCharGlobal came back FAIL, and the mod's own readiness gate
# -- which requires that global to be non-null -- aborted startup with
# "FATAL: pattern scan failed". These two RVAs are where those literals live.
MAINCHAR_DISP8_IMM = 0x9B5E    # the 0x48 in `cmp byte [rax+rdi], 0x48`
MAINCHAR_WINDOW_DISP = 0x9B91  # the -0xC00 in `lea eax,[rcx-0xC00]`

# The pristine mod also resolves the inventory manager itself, by scanning
# SetInventory's body for `mov REG,[rip+G]` (an image-relative global at RVA
# >= 0x3000000) followed within 0x60 bytes by `add r64,[REG+0x60|0x70|0x78]`,
# the manager's bucket idiom. On 2.01.00 SetInventory no longer loads that
# global at all -- the lookup was outlined into callees -- so the scan has zero
# stage-1 candidates and cannot be retuned, only replaced. INV_MGR_SCAN is the
# scan's entry; INV_MGR_FOUND is the success path it falls into, which stores
# the slot address, logs it, and reloads the loop's exit flag from it.
INV_MGR_SCAN = 0xA47E
INV_MGR_SCAN_LEN = 0x25
INV_MGR_FOUND = 0xA848
INV_MGR_SCAN_ORIG = bytes.fromhex(
    "488b1d3b300300"            # mov rbx,[SetInventory]
    "4533e4"                    # xor r12d,r12d
    "48c705fd30030000000000"    # mov qword[..],0
    "4c8925fe300300"            # mov [InvMgrPtr],r12
    "4885db"                    # test rbx,rbx
    "0f84e8030000")             # je warn
LOADLIBRARYA = 0x280F8     # IAT

# --- 1.18.2 field layout ---------------------------------------------------
L_MODE, L_SUB, L_FLAGS, L_SUBTYPES = 0x18, 0x19, 0x21, 0x28
L_DIRTY = 0x4B
MODE_OBJ_IN_MENUMGR = None   # derived from ModeSwitch's call site

# ModeSwitch's first fifteen bytes: three 5-byte register spills, so the entry
# splits on an instruction boundary and the first eight bytes are replaceable
# by one aligned store. Both the derivation and the runtime installer check it.
MODE_SWITCH_PROLOGUE = bytes.fromhex("48895C2408" "4889742410" "48897C2418")


def rel32(insn_rva: int, insn_size: int, target_rva: int) -> bytes:
    return struct.pack("<i", target_rva - (insn_rva + insn_size))


class Asm:
    """Tiny position-aware emitter so rip-relative displacements stay correct."""

    def __init__(self, rva: int):
        self.start = rva
        self.buf = bytearray()

    @property
    def rva(self) -> int:
        return self.start + len(self.buf)

    def raw(self, *chunks: bytes) -> "Asm":
        for chunk in chunks:
            self.buf += chunk
        return self

    def riprel(self, opcode: bytes, target: int, tail: bytes = b"") -> "Asm":
        size = len(opcode) + 4 + len(tail)
        self.buf += opcode + rel32(self.rva, size, target) + tail
        return self

    def call(self, target: int) -> "Asm":
        self.buf += b"\xE8" + rel32(self.rva, 5, target)
        return self

    def jmp32(self, target: int) -> "Asm":
        self.buf += b"\xE9" + rel32(self.rva, 5, target)
        return self

    def jmp8(self, target: int) -> "Asm":
        delta = target - (self.rva + 2)
        if not -128 <= delta <= 127:
            raise ValueError(f"rel8 out of range: {delta}")
        self.buf += b"\xEB" + struct.pack("<b", delta)
        return self

    def pad_to(self, size: int) -> "Asm":
        if len(self.buf) > size:
            raise ValueError(f"overflow: {len(self.buf)} > {size}")
        self.buf += b"\x90" * (size - len(self.buf))
        return self

    def bytes(self) -> bytes:
        return bytes(self.buf)


def patch(pe: pefile.PE, image: bytearray, rva: int, expected: bytes, new: bytes) -> None:
    if len(expected) != len(new):
        raise ValueError(f"size mismatch at RVA 0x{rva:X}: {len(expected)} vs {len(new)}")
    off = pe.get_offset_from_rva(rva)
    actual = bytes(image[off:off + len(expected)])
    if actual != expected:
        raise RuntimeError(
            f"unexpected bytes at RVA 0x{rva:X}\n"
            f"  expected {expected.hex(' ')}\n"
            f"  got      {actual.hex(' ')}"
        )
    image[off:off + len(new)] = new


def derive_game_targets(exe_path):
    """Locate the three game addresses this patch calls into.

    All three moved in 2.00. None of them is found by absolute address: each is
    anchored on a shape the game cannot change without changing behaviour.
    """
    import derive_modestate

    pe = pefile.PE(str(exe_path), fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    code = [x for x in pe.sections if x.Characteristics & 0x20000000]
    data = Path(exe_path).read_bytes()
    out = {}

    # NameToKey: `bool NameToKey(const char* name, uint16_t* outKey)`, the only
    # game function the [PRIV] capacity feature calls. 2.00 located it from the
    # call shape `lea rdx,[rsp+N] ; mov rcx,[rax] ; call` with the manager's
    # bucket idiom -- (key % bucketCount) << 8 added to [mgr+0x78] -- within
    # 0x60 after: three sites matched, two agreed, majority won. On 2.01.00 the
    # caller loads the name with `mov rcx,[rcx]` rather than `mov rcx,[rax]`,
    # so that sequence matches nothing at all and the derivation returned None.
    #
    # Widening the shape is not enough by itself. NameToKey is a
    # StaticInfoManager2 template instantiation and this image carries about
    # eighty-five of them, one per static-data table, structurally identical
    # down to the bucket walk, the entry verify and the 0xFFFF miss sentinel.
    # Which clone owns the inventory name table is decided by the data files
    # the game loads, not by anything present in the executable, so it is not
    # derivable from the exe -- the 2.00 majority vote picked a clone, and got
    # a right answer by luck rather than by evidence.
    #
    # The clone is therefore pinned per game version, and everything that *is*
    # checkable about it is checked below: it has to be a function start, it
    # has to read its first argument as a C string and zero its second, and it
    # has to be reached from a call site that hands it a stack out-slot, tests
    # the result as a bool, and then walks the manager's buckets with the key
    # it wrote back. A game update that moves or reshapes it fails the build
    # instead of baking in a stale address, which is the failure §57 describes.
    #
    # Evidence for this address on 2.01.00 (exe 1.0.0.2760): the call site at
    # game+0xFC913E reproduces §41's documented path instruction for
    # instruction -- lea rdx,[rsp+0x20] ; mov rcx,[rcx] ; call ; test al,al ;
    # je ; cmp [mgr+0x6c],0 ; mov [mgr+0x68] ; div ; shl r11,8 ;
    # add r11,[mgr+0x78] ; cmp [bucket+i*8+8],key ; mov [bucket+i*8+0xc] ;
    # mov [mgr+0x80] ; entry ; cmp word[entry+4],key.
    INV_NAME_TO_KEY = 0x20BFF60
    bucket = bytes.fromhex("49C1E3084D035A78")

    def _read(rva, n):
        for sec in code:
            at = rva - sec.VirtualAddress
            blob = sec.get_data()
            if 0 <= at < len(blob):
                return blob[at:at + n]
        return b""

    starts = {e.struct.BeginAddress
              for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])}
    if INV_NAME_TO_KEY not in starts:
        raise RuntimeError(f"NameToKey at {INV_NAME_TO_KEY:#x} is not a function "
                           "start in this executable")
    head = _read(INV_NAME_TO_KEY, 0x20)
    spill = re.search(rb"\x48\x8B[\xC2\xCA\xD2\xDA\xEA\xF2\xFA]", head)   # mov r64,rdx
    zero_out = re.search(rb"\x89[\x02\x0A\x12\x1A\x22\x2A\x32\x3A]", head)  # mov [rdx],r32
    null_arg = b"\x48\x85\xC9" in head                                      # test rcx,rcx
    # cmp byte[rcx],r8 / cmp byte[rcx],0 / movzx r32,byte[rcx]
    cstr = re.search(rb"[\x40-\x47]?\x38[\x01\x09\x11\x19\x21\x29\x31\x39]"
                     rb"|\x80\x39\x00|\x0F\xB6[\x01\x09\x11\x19\x21\x29\x31\x39]", head)
    if not (spill and zero_out and null_arg and cstr):
        raise RuntimeError(
            f"NameToKey at {INV_NAME_TO_KEY:#x} no longer reads a C string in "
            f"rcx and zeroes the out word in rdx: {head.hex()}")

    # and it must still be called the way the feature calls it
    managers = set()
    call_shape = re.compile(
        rb"\x48\x8D\x54\x24(.)(?:\x48|\x49)\x8B[\x08-\x0F\xC8-\xCF]\xE8....\x84\xC0",
        re.S)
    proof = 0
    for sec in code:
        blob = sec.get_data()
        for m in call_shape.finditer(blob):
            ci = m.end() - 7
            if sec.VirtualAddress + ci + 5 + struct.unpack_from("<i", blob, ci + 1)[0] \
                    != INV_NAME_TO_KEY:
                continue
            win = blob[ci + 5:ci + 5 + 0x60]
            b = win.find(bucket)
            if b < 0:
                continue
            nn = m.group(1)[0]
            slot = [bytes([0x8B, r, 0x24, nn]) for r in
                    (0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C, 0x74, 0x7C)]
            if not any(r in win[:b] for r in slot):
                continue
            proof += 1
            # The manager whose buckets this key walks is the manager the
            # [PRIV] feature will use, so read it off the same site rather
            # than from a scan of SetInventory that 2.01.00 emptied out.
            for mm in re.finditer(rb"[\x48-\x4F]\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]",
                                  win[:b]):
                k = mm.start()
                if k + 7 <= b:
                    managers.add(sec.VirtualAddress + ci + 5 + k + 7
                                 + struct.unpack_from("<i", win, k + 3)[0])
    if not proof:
        raise RuntimeError(
            f"no call site hands NameToKey at {INV_NAME_TO_KEY:#x} a stack "
            "out-slot whose key then drives the manager's bucket walk")
    if len(managers) != 1:
        raise RuntimeError("the inventory manager behind NameToKey is not "
                           "unique: " + str(sorted(hex(x) for x in managers)))
    out["NAME_TO_KEY"] = INV_NAME_TO_KEY
    out["INV_MGR_GLOBAL"] = next(iter(managers))

    # The actor handle resolver, `Out* Resolve(Holder*, Out* out)`. 2.00 keyed on
    # the exact prologue `mov [rsp+0x10],rdx ; push rbx ; sub rsp,0x30 ;
    # mov rbx,rdx`, but that is register allocation rather than behaviour: on
    # 2.01.00 the compiler dropped the home-slot spill and shrank the frame to
    # 0x20, so the prologue matched 159 unrelated functions and the body test
    # rejected all of them. Anchor on what the function has to do instead --
    # keep the out pointer in rbx, read [rcx+0x50] off the holder, and hand rbx
    # back as rcx -- bounded by the function's own end so a short neighbour
    # cannot lend bytes to the window, and require a unique answer.
    spill_out = bytes.fromhex("488BDA")     # mov rbx,rdx
    holder_50 = bytes.fromhex("488B5150")   # mov rdx,[rcx+0x50]
    out_as_rcx = bytes.fromhex("488BCB")    # mov rcx,rbx
    resolvers = set()
    blobs = [(sec.VirtualAddress, sec.get_data()) for sec in code]
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        lo, hi = entry.struct.BeginAddress, entry.struct.EndAddress
        for sva, blob in blobs:
            at = lo - sva
            if not 0 <= at < len(blob):
                continue
            head = blob[at:at + min(hi - lo, 0x40)]
            if spill_out in head and holder_50 in head and out_as_rcx in head:
                resolvers.add(lo)
            break
    if len(resolvers) == 1:
        out["RESOLVE_ACTOR"] = resolvers.pop()
    elif resolvers:
        raise RuntimeError("the actor handle resolver is not unique: "
                           + str(sorted(hex(x) for x in resolvers)))

    # "CampWareHouse": two copies ship -- on 2.01.00 one of them is only the
    # tail of "UI_WareHouse_KeyGuideFocusCampWareHouse" and nothing points at
    # it -- so keep the one code actually loads. The pointing instruction is
    # `lea r8,[rip+disp]` on 2.01.00 where 2.00 used a low register, so match
    # any REX.W prefix instead of a literal 0x48; collecting every lea target
    # once keeps this a single pass over the code.
    lea_rip = re.compile(rb"[\x48-\x4F]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]", re.S)
    lea_targets = set()
    for sec in code:
        blob = sec.get_data()
        for m in lea_rip.finditer(blob):
            j = m.start()
            if j + 7 <= len(blob):
                lea_targets.add(sec.VirtualAddress + j + 7
                                + struct.unpack_from("<i", blob, j + 3)[0])
    pos = 0
    while True:
        i = data.find(b"CampWareHouse\x00", pos)
        if i < 0:
            break
        pos = i + 1
        try:
            rva = pe.get_rva_from_offset(i)
        except Exception:
            continue
        if rva in lea_targets:
            out["CAMP_NAME"] = rva
            break

    # ModeSwitch. The mode object is the argument it is handed, and S68 showed
    # there is no static route to that object -- 54657 rip-relative global loads
    # were walked and not one reaches the field -- so the only way to get it is
    # to take it from this call. Through 2.00 the anchor was the call shape
    # itself: `mov r64,[r64+0x1158]` immediately followed by `call rel32`. But
    # 0x1158 is a game constant, not a shape: on 2.01.00 the mode object moved
    # to menuMgr+0x1178, the search matched nothing, and the build stopped.
    #
    # Locate ModeSwitch through derive_modestate instead -- it is anchored on
    # the UI tag strings and already has to find ModeSwitch to read the layout
    # out of it -- and keep the three properties the old search relied on as
    # checks rather than as the search itself. The menuMgr field is then read
    # off the one call site, where the game spells it out.
    layout = derive_modestate.derive(exe_path, verbose=False)
    ms = layout["modeswitch"]
    if ms % 8:
        raise RuntimeError(f"ModeSwitch at {ms:#x} is not 8-byte aligned; the "
                           "hot-patch relies on a single aligned qword store")
    host = next((x for x in code
                 if x.VirtualAddress <= ms < x.VirtualAddress + len(x.get_data())), None)
    if host is None:
        raise RuntimeError(f"ModeSwitch at {ms:#x} is not inside a code section")
    at = ms - host.VirtualAddress
    if host.get_data()[at:at + len(MODE_SWITCH_PROLOGUE)] != MODE_SWITCH_PROLOGUE:
        raise RuntimeError(f"ModeSwitch at {ms:#x} does not begin with the three "
                           "register spills the capture hook overwrites")

    # Exactly one direct caller is part of the evidence that this is the mode
    # tick's ModeSwitch and not another function sharing its prologue. That one
    # call site also carries the field the fallback walk needs, as the
    # `mov rcx,[reg+disp32]` feeding the call.
    sites, fields = [], []
    for sec in code:
        blob = sec.get_data()
        pos = 0
        while True:
            i = blob.find(b"\xE8", pos)
            if i < 0 or i + 5 > len(blob):
                break
            pos = i + 1
            if sec.VirtualAddress + i + 5 + struct.unpack_from("<i", blob, i + 1)[0] != ms:
                continue
            sites.append(sec.VirtualAddress + i)
            if i < 7:
                continue
            modrm = blob[i - 5]
            if (blob[i - 7] in (0x48, 0x49) and blob[i - 6] == 0x8B
                    and modrm >> 6 == 2 and (modrm >> 3) & 7 == 1 and modrm & 7 != 4):
                fields.append(struct.unpack_from("<I", blob, i - 4)[0])
    if len(sites) != 1:
        raise RuntimeError(f"ModeSwitch at {ms:#x} has {len(sites)} direct "
                           "callers, expected 1")
    if len(fields) != 1 or not 0x100 <= fields[0] <= 0x4000:
        raise RuntimeError("the mode object's field in menuMgr is not readable "
                           f"from the call site at {sites[0]:#x}: {fields}")
    out["MODE_SWITCH"] = ms
    out["MODE_OBJ_IN_MENUMGR"] = fields[0]

    # The parameters of the mod's own MainCharGlobal scan, re-derived the same
    # way it scans: find every site matching the singleton shape with DISP8 and
    # D left open, then take the (DISP8, D) pair with the most sites. Requiring
    # that pair to resolve to exactly one global is the real check -- it is what
    # says the scan will land on one answer rather than on whichever clone of
    # the shape happens to come first in address order.
    singles = {}
    for sec in code:
        blob = sec.get_data()
        for m in re.finditer(rb"\x48\x8B\x05....\x48\x8B", blob, re.S):
            i = m.start()
            if i + 17 > len(blob):
                continue
            modrm = blob[i + 9]
            if modrm & 0xC7 != 0x40 or blob[i + 11] != 0x80:
                continue
            if blob[i + 12] != (0xB8 | ((modrm >> 3) & 7)):
                continue
            key = (blob[i + 10], struct.unpack_from("<I", blob, i + 13)[0])
            g = sec.VirtualAddress + i + 7 + struct.unpack_from("<i", blob, i + 3)[0]
            singles.setdefault(key, []).append(g)
    if not singles:
        raise RuntimeError("the MainCharGlobal singleton shape is absent from "
                           "this executable")
    (disp8, dfield), sites = max(singles.items(), key=lambda kv: len(kv[1]))
    globals_ = set(sites)
    if len(sites) < 2 or len(globals_) != 1:
        raise RuntimeError(
            "the MainCharGlobal singleton scan is ambiguous: winning pair "
            f"(disp8=0x{disp8:X}, off=0x{dfield:X}) has {len(sites)} sites over "
            f"{len(globals_)} globals")
    out["MAINCHAR_DISP8"] = disp8
    out["MAINCHAR_WINDOW"] = dfield & ~0xFF
    out["MAINCHAR_GLOBAL"] = next(iter(globals_))

    missing = [k for k in ("NAME_TO_KEY", "RESOLVE_ACTOR", "CAMP_NAME")
               if k not in out]
    if missing:
        raise RuntimeError("could not derive from the executable: "
                           + ", ".join(missing))
    out.update(layout)
    return out


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: patch_private_storage_1182_modestate.py "
                         "<pristine.asi> <output.asi> <CrimsonDesert.exe>")
    source, destination = Path(sys.argv[1]), Path(sys.argv[2])

    global CAMP_NAME, NAME_TO_KEY, RESOLVE_ACTOR, MODE_SWITCH
    global L_MODE, L_SUB, L_FLAGS, L_SUBTYPES, L_DIRTY, MODE_OBJ_IN_MENUMGR
    t = derive_game_targets(Path(sys.argv[3]))
    CAMP_NAME, NAME_TO_KEY, RESOLVE_ACTOR, MODE_SWITCH = (
        t["CAMP_NAME"], t["NAME_TO_KEY"], t["RESOLVE_ACTOR"], t["MODE_SWITCH"])
    MODE_OBJ_IN_MENUMGR = t["MODE_OBJ_IN_MENUMGR"]
    L_MODE, L_SUB, L_FLAGS, L_SUBTYPES, L_DIRTY = (
        t["mode"], t["submode"], t["flags"], t["subtypes"], t["dirty"])
    # The mod resolves the store sub-index itself at runtime (ASI global
    # STORE_SUB_INDEX), so this is a sanity check on the derivation, not a
    # value the patch bakes in.
    if t["ingame_mode"] != 4 or not 1 <= t["store_sub"] <= 16:
        raise RuntimeError(f"unexpected mode values: ingame={t['ingame_mode']} "
                           f"store={t['store_sub']}")
    print(f"derived  CampWareHouse=0x{CAMP_NAME:X} NameToKey=0x{NAME_TO_KEY:X} "
          f"ResolveActor=0x{RESOLVE_ACTOR:X} ModeSwitch=0x{MODE_SWITCH:X}")
    print(f"derived  modeObj=menuMgr+0x{MODE_OBJ_IN_MENUMGR:X}")
    print(f"derived  mainchar-scan disp8=0x{t['MAINCHAR_DISP8']:X} "
          f"window=0x{t['MAINCHAR_WINDOW']:X}..0x{t['MAINCHAR_WINDOW'] + 0xFF:X} "
          f"-> global=0x{t['MAINCHAR_GLOBAL']:X}")
    print(f"derived  inventory-manager global=0x{t['INV_MGR_GLOBAL']:X}")
    print(f"derived  ingame-mode={t['ingame_mode']} store-sub={t['store_sub']}")
    image = bytearray(source.read_bytes())
    digest = hashlib.sha256(image).hexdigest()
    if digest != EXPECTED_SHA256:
        raise RuntimeError(f"unsupported input ASI SHA-256: {digest}")
    pe = pefile.PE(data=image)

    # ------------------------------------------------------------------ (A)
    # Replace the legacy 0xC00-0xCFF layout scanner with a stub publishing the
    # real 1.18.2 offsets. MODE_ANCHOR must stay non-zero or the caller skips
    # StoreSubIndex derivation.
    asm = Asm(CAVE)
    asm.riprel(b"\x48\x89\x15", MODE_ANCHOR)                       # mov [MODE_ANCHOR],rdx
    for glob, value in ((MODE_OFF, L_MODE), (SUB_OFF, L_SUB),
                        (FLAGS_OFF, L_FLAGS), (SUBTYPES_OFF, L_SUBTYPES)):
        asm.riprel(b"\xC7\x05", glob, struct.pack("<I", value))    # mov dword [g],imm32
    asm.raw(b"\xB0\x01", b"\xC3")                                  # mov al,1 ; ret
    stub = asm.bytes()
    off = pe.get_offset_from_rva(CAVE)
    if bytes(image[off:off + 6]) != b"\x48\x89\x5c\x24\x08\x57":
        raise RuntimeError("legacy resolver prolog was not found")
    if CAVE + len(stub) > HELPER:
        raise RuntimeError("stub collides with helper")
    image[off:off + len(stub)] = stub

    # ------------------------------------------------------------------ (B)
    # get_mode_obj -> rax = the mode object, ZF reflects rax == 0.
    #
    # AT walked root -> +0x90 -> +0x1158 and reached a readable but wrong object
    # (§59, confirmed by AV in §66). §68 then established that no static route
    # exists at all: of 54657 rip-relative global loads in the 2.00 image, none
    # reaches +0x1158, and every real consumer takes its base from [this+0x28]
    # with `this` a parameter. So the object is no longer derived here -- the
    # capture hook takes it from ModeSwitch and this helper just reads it.
    #
    # Only a 5-byte jump lives in the cave now; the body is in .pstext, where
    # there is room for both the read and the old walk as a fallback. The body
    # is still a LEAF -- no call, no push, no stack write -- so it needs no
    # unwind info, which is what let the original live in the dead resolver's
    # .pdata range in the first place.
    if HELPER + 5 > CAVE_END:
        raise RuntimeError("no room in the cave for the helper jump")
    hoff = pe.get_offset_from_rva(HELPER)
    tail = pe.get_offset_from_rva(TELEMETRY) - (hoff + 5)
    if tail < 0:
        raise RuntimeError("helper jump would overrun the telemetry stub")
    image[hoff:hoff + 5] = Asm(HELPER).jmp32(AW_MODEOBJ).bytes()
    image[hoff + 5:hoff + 5 + tail] = b"\xCC" * tail

    # --------------------------------------------------------------- (C/D)
    # Re-point the two mode-base loads from g_mainChar to modeObj.
    for rva, expected_hex in (
        (0xB447, "33 c0 f0 48 0f b1 3d ce 20 03 00"),   # hotkey gate
        (0xC4FE, "33 c0 f0 48 0f b1 1d 17 10 03 00"),   # cleanup path
    ):
        expected = bytes.fromhex(expected_hex)
        patch(pe, image, rva, expected,
              Asm(rva).call(HELPER).pad_to(len(expected)).bytes())

    # ------------------------------------------------------------------ (E)
    # Both Safe* functions gate their offsets on (off - 0xC00) <= 0x200, which
    # rejects the real 1.18.2 offsets. Rebase the check at zero: off <= 0x200.
    for rva in (0xB006, 0xAEF6):
        patch(pe, image, rva, bytes.fromhex("8d 82 00 f4 ff ff"),
              b"\x8D\x82\x00\x00\x00\x00")
    for rva in (0xB01E, 0xAF0E):
        patch(pe, image, rva, bytes.fromhex("41 8d 80 00 f4 ff ff"),
              b"\x41\x8D\x80\x00\x00\x00\x00")

    # ----------------------------------------------------------------- (F1)
    # SafeSetupModeForWarehouse tail: same writes, compacted to free five bytes
    # for the mandatory dirty flag.
    tail_rva = 0xB0DA
    tail = Asm(tail_rva)
    tail.riprel(b"\x8B\x05", SUBTYPES_OFF)        # mov eax,[SUBTYPES_OFF]   eax = 0x28
    tail.raw(b"\x8D\x48\xFD")                     # lea ecx,[rax-3]          FLAGS_OFF+4
    tail.raw(b"\x42\xC6\x04\x09\x01")             # mov byte [rcx+r9],1      flags[4]=1 -> mode 4
    tail.riprel(b"\x03\x05", STORE_SUB_INDEX)     # add eax,[StoreSubIndex]
    tail.raw(b"\x42\xC6\x04\x08\x01")             # mov byte [rax+r9],1      subtypes[5]=1 -> store
    tail.raw(b"\x41\xC6\x41" + bytes([L_DIRTY]) + b"\x01")   # mov byte [r9+0x4B],1
    tail.jmp8(0xB115)
    expected_tail = bytes.fromhex(
        "8b 05 44 0f 03 00 83 c0 04 42 c6 04 08 01 8b 0d 3a 0f 03 00 "
        "03 0d 38 0f 03 00 42 c6 04 09 01 eb 1a"
    )
    patch(pe, image, tail_rva, expected_tail, tail.pad_to(len(expected_tail)).bytes())

    # ----------------------------------------------------------------- (F2)
    # SafeRestoreMode body: restore the saved arrays with wider moves, then set
    # the dirty flag so the game resolves back to the gameplay sub-mode.
    body_rva = 0xAF4E
    body = Asm(body_rva)
    body.riprel(b"\x8B\x0D", FLAGS_OFF)           # mov ecx,[FLAGS_OFF]
    body.raw(b"\x49\x03\xC9")                     # add rcx,r9          rcx = &flags[0]
    body.riprel(b"\x8B\x05", SAVED_FLAGS)         # mov eax,[saved+0]
    body.raw(b"\x89\x01")                         # mov [rcx],eax
    body.riprel(b"\x8B\x05", SAVED_FLAGS + 3)     # mov eax,[saved+3]   overlapping tail
    body.raw(b"\x89\x41\x03")                     # mov [rcx+3],eax
    body.riprel(b"\x48\x8B\x05", SAVED_SUBTYPES)  # mov rax,[savedsub+0]
    body.raw(b"\x48\x89\x41\x07")                 # mov [rcx+7],rax     subtypes = flags+7
    body.riprel(b"\x48\x8B\x05", SAVED_SUBTYPES + 7)
    body.raw(b"\x48\x89\x41\x0E")                 # mov [rcx+0xE],rax
    body.raw(b"\x41\xC6\x41" + bytes([L_DIRTY]) + b"\x01")   # mov byte [r9+0x4B],1
    body.jmp8(0xAFC6)
    expected_body = bytes.fromhex(
        "8b 0d d0 10 03 00 8b 05 c2 56 03 00 42 89 04 09 0f b7 05 bb 56 03 00 "
        "66 42 89 44 09 04 0f b6 05 b0 56 03 00 42 88 44 09 06 8b 0d ab 10 03 00 "
        "49 03 c9 f2 0f 10 05 a0 56 03 00 f2 0f 11 01 8b 05 9e 56 03 00 89 41 08 "
        "0f b7 05 98 56 03 00 66 89 41 0c 0f b6 05 8f 56 03 00 88 41 0e eb 1a"
    )
    patch(pe, image, body_rva, expected_body, body.pad_to(len(expected_body)).bytes())

    # ------------------------------------------------------------------ (G)
    # 1.18.2 menu-manager backlink: +0x11C0 now holds a different valid object,
    # so the old equality check rejects the right manager.
    patch(pe, image, 0xAA8C, bytes.fromhex("4d 3b c1 75 09"), b"\x90" * 5)

    # ================================================================== W2
    # Build W proved the mode transition works (it logged the true live
    # mode=0x04 sub=0x10), then froze. The mod's legacy code was written for a
    # world where no view ever mounts, so it fakes the whole panel by hand.
    # Now that a real mount happens, those writes race the game's own UI script
    # against the same controller. Stop fighting the mount.

    # ------------------------------------------------------------------ (I)
    # ViewMount (0xB880) sets the menu-layer request byte to 1. game+0x7DD6B0
    # answers any request other than 3 by setting modeObj+0x2C -- subtypes[4],
    # which is `alert, cinema, subtitle`. ModeSwitch takes the FIRST non-zero
    # index, so cinema (4) would beat store (5). The menu-layer path and the
    # store path are alternatives; asking for both is the v1.5.5 bug restated.
    #
    # Leave the layer alone entirely. Its idle request value is 3, which is the
    # branch that *clears* cinema for us. Nothing is set on open, so nothing
    # needs restoring on close -- the v1.5.6 leaked-layer failure mode goes away
    # by construction.
    for rva, expected_hex in (
        (0xB8DE, "66 c7 80 5e 10 00 00 01 01"),  # ViewMount   current=1, request=1
        (0xB950, "c6 80 5f 10 00 00 03"),        # ViewUnmount request=3
        (0xB965, "66 c7 80 5e 10 00 00 04 03"),  # ViewUnmount current=4, request=3
    ):
        expected = bytes.fromhex(expected_hex)
        patch(pe, image, rva, expected, b"\x90" * len(expected))

    # ------------------------------------------------------------------ (J)
    # InitWarehousePanel (0x4730) is left BYTE-IDENTICAL to the original.
    #
    # Earlier builds NOP'd parts of it -- the prepare packet, the 0x0E command,
    # the SetInventory calls, the modal-pointer clear -- on the theory that a
    # native mount made them redundant. That was wrong twice over. It is a
    # coherent sequence, and running half of it corrupted the panel rather than
    # configuring it. And the routine was always designed for a mounted view:
    # even in the working era the flow was set store sub-mode -> game mounts ->
    # init configures. The real bug was never this routine, it was the two
    # re-entrant routes that called it from inside the game's own mount.
    #
    # The per-panel table at 0x3C058 is why it cannot simply be skipped: it
    # carries the container string for each hotkey, and applying it is the only
    # thing that distinguishes F4 from F5-F9.
    #     panel[0] CampWareHouse              panel[3] Housing_Refrigerator
    #     panel[1] Housing_GatheredMaterials  panel[4] Housing_Symbol
    #     panel[2] Housing_Dresser            panel[5] Housing_Collecting

    # ------------------------------------------------------------------ (K)
    # Telemetry: re-read mode/sub-mode one frame after the request, from the
    # deferred-init path, so the log says whether the game actually reached the
    # store sub-mode. Reuses the existing format string at 0x2B1D8, so no new
    # data is needed.
    #
    # This routine is a LEAF that TAIL-JUMPS to the logger: no call, no stack
    # frame. It lives inside the dead resolver's .pdata range, whose unwind info
    # describes a different prologue, and a leaf is the one shape that unwinds
    # correctly regardless. The tail jump also lets the logger reuse the
    # caller's shadow space.
    tel = Asm(TELEMETRY)
    fails = []
    tel.riprel(b"\x48\x8B\x05", GAME_GLOBAL_SLOT)                  # mov rax,[g_slotHolder]
    tel.raw(b"\x48\x85\xC0")                                       # test rax,rax
    fails.append(tel.rva)
    tel.raw(b"\x74\x00")                                           # je fallback
    tel.raw(b"\x48\x8B\x00")                                       # mov rax,[rax]
    for deref in (0x90, MODE_OBJ_IN_MENUMGR):
        tel.raw(b"\x48\x3D\x00\x00\x01\x00")                       # cmp rax,0x10000
        fails.append(tel.rva)
        tel.raw(b"\x76\x00")                                       # jbe fallback
        tel.raw(b"\x48\x8B\x80" + struct.pack("<I", deref))        # mov rax,[rax+deref]
    tel.raw(b"\x48\x3D\x00\x00\x01\x00")                           # cmp rax,0x10000
    fails.append(tel.rva)
    tel.raw(b"\x76\x00")                                           # jbe fallback
    tel.riprel(b"\x8B\x0D", MODE_OFF)                              # mov ecx,[MODE_OFF]
    tel.raw(b"\x0F\xB6\x14\x01")                                   # movzx edx,byte [rcx+rax]
    tel.riprel(b"\x8B\x0D", SUB_OFF)                               # mov ecx,[SUB_OFF]
    tel.raw(b"\x44\x0F\xB6\x04\x01")                               # movzx r8d,byte [rcx+rax]
    tel.riprel(b"\x48\x8D\x0D", FMT_OPENED)                        # lea rcx,[fmt]
    tel.jmp32(LOGGER)                                              # tail call
    fallback = tel.rva
    tel.riprel(b"\x48\x8D\x0D", FMT_DEFERRED)                      # lea rcx,[original string]
    tel.jmp32(LOGGER)
    telemetry = bytearray(tel.bytes())
    for site in fails:
        delta = fallback - (site + 2)
        if not 0 <= delta <= 127:
            raise ValueError(f"telemetry rel8 out of range at 0x{site:X}: {delta}")
        telemetry[site - TELEMETRY + 1] = delta
    if TELEMETRY + len(telemetry) > CAVE_END:
        raise RuntimeError("telemetry overruns the cave")
    toff = pe.get_offset_from_rva(TELEMETRY)
    image[toff:toff + len(telemetry)] = telemetry

    # Redirect the two "about to init the panel" log lines to the telemetry
    # stub. There are two independent routes into InitWarehousePanel -- the
    # deferred one and the CanShow first-open one -- and which fires depends on
    # whether the controller was already captured. Build X instrumented only the
    # deferred route and the run took the other one, so instrument both.
    for site, expected_hex in (
        (0x42E7, "48 8d 0d 12 7c 02 00 e8 ed 2a 00 00"),  # "Deferred init: handler captured"
        (0xC345, "48 8d 0d d4 d9 01 00 e8 8f aa ff ff"),  # "CanShow: running ... inline"
    ):
        expected = bytes.fromhex(expected_hex)
        patch(pe, image, site, expected,
              Asm(site).call(TELEMETRY).pad_to(len(expected)).bytes())

    # =================================================================== Z
    # Build Y proved the native mount works: sub-mode 0x05, no crash, ESC clean.
    # What it lacked was configuration -- the store tag mounts the whole
    # store-tagged family (Camp Provisions donation, Trade Goods, Mount
    # Inventory, Hold) with package defaults. InitWarehousePanel is what turns
    # that into Private Storage, so it has to run after all. The problem was
    # never what it does, only when.
    #
    # Three routes reach it, two of them re-entrant:
    #     0x4319  posted message 0x65B, handled on the message pump   SAFE
    #     0xBE3F  Handler hook   -- inside the game's packet dispatch
    #     0xC375  CanShow hook   -- inside the game's mount call      (crashed X)

    # ------------------------------------------------------------------ (L)
    # Make both inline routes decline. Critically they must NOT clear the arm
    # flag 0x408F4 on the way out: the input thread (0x5CC0) re-posts 0x65B
    # while armed, and that retry is what eventually lands the init on the
    # message pump once the controller is captured and the mount is past
    # CanShow. Both arm-flag clears (0xBE09, 0xC33F) sit inside the skipped
    # region, and both jumps land exactly where the original branch went.
    patch(pe, image, 0xBE05, bytes.fromhex("74 3d"), b"\xEB\x3D")
    patch(pe, image, 0xC337, bytes.fromhex("0f 84 f3 00 00 00"),
          Asm(0xC337).jmp32(0xC430).pad_to(6).bytes())

    # ------------------------------------------------------------------ (M)
    # Readiness gate (AD).
    #
    # Every subset of the init crashed -- full, minus the packet sends, minus
    # the teardown writes -- and the Sentry crash event pins the fault at
    # game+0xA0318F4, on the FIRST dereference of `this` in a UI helper's
    # prologue: `mov rcx,[rcx+0x168]`. So the game was handed a garbage control
    # pointer and tripped over it while walking children, after our init had
    # already returned.
    #
    # What explains 'every subset fails' is not one bad write. It is that the
    # init runs while the game is still building the panel. Moving it to the
    # message pump fixed re-entrancy, but the pump still runs inside the frame;
    # the mount completes over several.
    #
    # So gate on the panel being real before touching it, using the very field
    # whose staleness produced the fault. Returning without disarming means
    # 'try again next tick' -- the input thread re-posts 0x65B while 0x408F4
    # stays armed, bounded by its own 1800-tick budget.
    #
    # Leaf plus tail jump, as with the other stubs: no frame, so the cave's
    # inherited unwind info is never consulted, and rcx/rdx pass through.
    gate = Asm(DISARM)
    waits = []
    gate.riprel(bytes.fromhex("48 8b 05"), CAPTURED_HANDLER)   # mov rax,[captured]
    gate.raw(bytes.fromhex("48 85 c0"))                        # test rax,rax
    waits.append(gate.rva)
    gate.raw(bytes.fromhex("74 00"))                           # jz not_ready
    gate.raw(bytes.fromhex("48 8b 80") + struct.pack("<I", UI_CHILD_VEC))
    gate.raw(bytes.fromhex("48 85 c0"))                        # test rax,rax
    waits.append(gate.rva)
    gate.raw(bytes.fromhex("74 00"))                           # jz not_ready
    gate.raw(bytes.fromhex("31 c0"))                           # xor eax,eax
    gate.riprel(bytes.fromhex("87 05"), ARM_FLAG)              # xchg [ARM_FLAG],eax
    gate.jmp32(INIT_PANEL)                                     # commit
    not_ready = gate.rva
    gate.raw(bytes.fromhex("c3"))                              # ret, still armed
    gate_bytes = bytearray(gate.bytes())
    for site in waits:
        delta = not_ready - (site + 2)
        if not 0 <= delta <= 127:
            raise ValueError(f"gate rel8 out of range at 0x{site:X}: {delta}")
        gate_bytes[site - DISARM + 1] = delta
    if TELEMETRY + len(telemetry) > DISARM or DISARM + len(gate_bytes) > CAVE_END:
        raise RuntimeError("readiness gate does not fit the cave")
    doff = pe.get_offset_from_rva(DISARM)
    image[doff:doff + len(gate_bytes)] = gate_bytes
    patch(pe, image, 0x4319, bytes.fromhex("e8 12 04 00 00"),
          Asm(0x4319).call(DISARM).bytes())

    # ------------------------------------------------------------------ (N)
    # "Handler: blocking %u sub-commands" -- the mod zeroes the sub-command
    # count on the game's own type-0x15 packets while an init is pending. That
    # was deliberate when the mod faked the whole panel; now it can only destroy
    # the very commands that configure it.
    patch(pe, image, 0xBE6D, bytes.fromhex("89 7e 10"), b"\x90" * 3)

    # ================================================================== AA
    # Four builds have now crashed on variations of "which parts of the mod's
    # init to run". Stop guessing and capture the packet trace instead.
    #
    # AA is deliberately diagnostic and non-crashing: revert to Y's behaviour
    # (init neutered -- the one configuration that reliably survives) and open
    # the gates on the handler hook's existing packet inspection.

    # ------------------------------------------------------------------ (O)
    # ROOT CAUSE (AG): the mod plants two landmines in fields the game owns.
    #
    # Both are 'clean up leftovers from the previous mod-driven open' steps.
    # They made sense when the mod built the panel itself. On 1.18.2 the game
    # builds it, so these now overwrite live state with values the game then
    # dereferences without checking.
    #
    # LANDMINE 1 -- donation clear -> controller+0x330
    #   AE minidump:  game+0xA0318F4  mov rcx,[rcx+0x168]
    #                 Rcx = 0x0000FFFFFFFFFFFF   (48 bits of ones)
    #   caller:       game+0xB32AAB  mov rcx,[rbx+0x330]   (rbx == our controller)
    #   the mod writes: dword 0xFFFFFFFF at +0x330, word cx (==0xFFFF) at +0x334
    #                 -> six 0xFF bytes -> 0x0000FFFFFFFFFFFF as a qword. Exact match.
    #   why: the boot log says 'SetDonationFaction: FAIL' then
    #        'DonationOff: FALLBACK offset=0x330'. It is a guess. On an older
    #        build that field was a faction ID where all-ones meant 'none'; on
    #        1.18.2 it is a POINTER the game calls a method on.
    #
    # LANDMINE 2 -- modal clear -> controller+0x258
    #   AF minidump:  game+0xB2F62D  mov rcx,[rax+8]   with rax == 0
    #                 preceded by     mov rax,[rsi+0x258]  (rsi == our controller)
    #   the game dereferences the modal-view pointer with NO null check, and the
    #   mod writes NULL into it.
    #
    # Together these explain every build:
    #   modal off, donation off  Y, AA           -> no crash
    #   modal off, donation on   Z, AC, AD, AE   -> crash at 0xA0318F4 (donation)
    #   modal on,  donation on   W, AB           -> crash at 0xA0318F4
    #   modal on,  donation on   AF              -> crash at 0xB2F62D (modal, hits first)
    #
    # AF only patched the je at 0x4968, which is the branch taken when the field
    # is ALREADY all-ones. Two earlier `jne 0x496A` at 0x495A and 0x4961 jump
    # straight past it in the normal case, so the write still happened. NOP the
    # write block itself instead -- unreachable by construction, from any path.
    patch(pe, image, 0x496A,
          bytes.fromhex("c7 04 3a ff ff ff ff 66 89 4c 3a 04"
                        "48 8d 0d 23 5c 02 00 e8 5e 24 00 00"),
          bytes.fromhex("90" * 24))   # both writes + the now-false log line

    # Landmine 2. Same reasoning: stop zeroing a pointer the game owns.
    patch(pe, image, 0x47C8, bytes.fromhex("48 89 34 3a"),
          bytes.fromhex("90 90 90 90"))            # clear modal pointer +0x258

    # Everything else in the init is the original, byte for byte. SetInventory
    # was cleared by AE (disabled, still crashed), and it is the one step F5-F9
    # cannot work without. Assert rather than patch so a future edit that
    # reintroduces surgery here fails loudly.
    for rva, expect in ((INIT_PANEL, "48 89 5c 24 18"), (0x487E, "41 ff d2"),
                        (0x4911, "41 ff d2"), (0x4968, "74 18"),
                        (0x5335, "ff 15 85 81 03 00"), (0x53B2, "ff 15 08 81 03 00"),
                        (0x53D2, "ff 15 e8 80 03 00")):
        off = pe.get_offset_from_rva(rva)
        want = bytes.fromhex(expect)
        if bytes(image[off:off + len(want)]) != want:
            raise RuntimeError(f"init body at 0x{rva:X} is not pristine")

    # ------------------------------------------------------------------ (P)
    # The handler-hook tail already inspects packet bytes; it just gates the
    # logging behind "init pending AND type == 0x15". Open every gate and print
    # the packet TYPE rather than the sub-command count. All replacements are
    # the same length, so nothing reflows. The `test rsi,rsi` null guard at
    # 0xBE50 is deliberately left in place.
    patch(pe, image, 0xBE4E, bytes.fromhex("74 22"), bytes.fromhex("90 90"))  # ignore pending flag
    patch(pe, image, 0xBE58, bytes.fromhex("75 16"), bytes.fromhex("90 90"))  # log every type
    patch(pe, image, 0xBE5A, bytes.fromhex("8b 56 10"),
          bytes.fromhex("0f b6 16"))                                  # movzx edx, byte [rsi]
    patch(pe, image, 0xBE5F, bytes.fromhex("74 0f"), bytes.fromhex("90 90"))  # do not skip type 0

    # Retitle the message so the trace reads honestly. The string is referenced
    # only from 0xBE61, and has 35 bytes plus 5 of padding to work with.
    fmt_off = pe.get_offset_from_rva(FMT_BLOCKING)
    old_fmt = b"  Handler: blocking %u sub-commands"
    if bytes(image[fmt_off:fmt_off + len(old_fmt)]) != old_fmt:
        raise RuntimeError("blocking format string was not found")
    new_fmt = b"  [PKT] handler type=%u"
    image[fmt_off:fmt_off + len(old_fmt)] = new_fmt.ljust(len(old_fmt), bytes(1))
    # =================================================================== AH
    # Restore the 1000-slot inventory expansion.
    #
    # The boot log has said 'Inventory mgr ptr: WARN dynamic scan failed' since
    # 1.18.2, which disables both the worker thread and the on-open slot patch.
    # Three things are involved; two are proven and the third is why the write
    # stays suppressed in this build.
    #
    # (1) The resolver's secondary validation is too strict.
    #     The primary scan of game SetInventory (game+0xB32AD0) SUCCEEDS -- one
    #     candidate in the whole function:
    #         SetInventory+0x225  mov r10,[rip+0x578EFE4]  -> RVA 0x62C1CE0
    #     and that global is real (110 code sites load it). The secondary check
    #     at 0xA560 then wants mov r64,[r10+disp8] with disp8 in {60,70,78}
    #     within 0x60 bytes. 1.18.2 has exactly one qualifying instruction:
    #         SetInventory+0x24F  4D 03 5A 78   add r11,[r10+0x78]
    #     REX.W ok, mod=01 ok, base r10 ok, disp 0x78 ok -- only the opcode
    #     differs: 0x03 (add) where the validator hardcodes 0x8B (mov).
    patch(pe, image, 0xA583, bytes.fromhex("8b"), bytes.fromhex("03"))

    # (2) The entry array moved. The patcher reads count from mgr+0x08 and the
    #     array from mgr+0x50. The game's own linear accessor shows 1.18.2:
    #         game+0x3AA5BC  cmp edi, dword [rbx+0x08]   ; count  -- still right
    #         game+0x3AA5CD  mov rax, qword [rbx+0x58]   ; array  -- was 0x50
    #         game+0x3AA5D1  mov rax, [r14+rax]          ; 8-byte stride
    #     Only the array pointer shifted. Patch the disp8 of
    #     `mov r10,[rax+0x50]` (4c 8b 50 50) at 0x874C.
    patch(pe, image, 0x874F, bytes.fromhex("50"), bytes.fromhex("58"))
    # =================================================================== AO
    # Private Storage capacity as an EXACT TOTAL.
    #
    # AN proved the mechanism: writing the static base made Private read 1200,
    # i.e. base 1000 plus the 200 expansion slots already on the save. The game
    # computes the displayed capacity itself, at game+0x1DDE3A3:
    #
    #   movzx ecx, word [info+0x48]      ; base slots  (what we set)
    #   add   cx,  word [container+0x1a] ; + purchased expansions
    #   mov   word [container+0x14], cx  ; = displayed total
    #
    # So to make PrivateStorageSlots mean the total, read the expansion count
    # and write base = total - expansions.
    #
    # The container is found the way the game finds it (game+0x84A5A0,
    # game+0x5328B0 and game+0x1DDE300 all use this identical walk):
    #
    #   owner = GetInventoryOwner(actor)      ; game+0x1DD2C60
    #   for c in owner+0x18[0 .. owner+0x20]: if word[c+0x10] == key: found
    #
    # The actor is the mainChar the mod already caches at ASI 0x3D520.
    #
    # That lookup runs ONLY on the on-open path, where we are on the game thread
    # with the warehouse live and mainChar certainly valid -- GetInventoryOwner
    # dereferences actor+0x68 -> +0x20 -> +0x30, which is not something to do
    # from a background thread against a cached pointer. The expansion count is
    # cached in this section so the worker can keep the value applied using
    # arithmetic alone, with no game call of its own beyond NameToKey.
    #
    # Until the expansion count is known (before the first open) nothing is
    # written at all: showing the unmodified number briefly is better than
    # showing total+expansions, which is the exact thing this build removes.
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    opt_hdr = e_lfanew + 24
    sect_hdr = (opt_hdr + pe.FILE_HEADER.SizeOfOptionalHeader
                + pe.FILE_HEADER.NumberOfSections * 40)
    if struct.unpack_from("<I", image, e_lfanew)[0] != 0x00004550:
        raise RuntimeError("e_lfanew does not point at the PE signature")
    if struct.unpack_from("<H", image, e_lfanew + 6)[0] != pe.FILE_HEADER.NumberOfSections:
        raise RuntimeError("NumberOfSections offset disagrees with pefile")
    if struct.unpack_from("<I", image, opt_hdr + 56)[0] != pe.OPTIONAL_HEADER.SizeOfImage:
        raise RuntimeError("SizeOfImage offset disagrees with pefile")
    last = max(pe.sections, key=lambda x: x.VirtualAddress)
    if sect_hdr != last.get_file_offset() + 40:
        raise RuntimeError("section-table slot is not where it was expected")
    if sect_hdr + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise RuntimeError("no room in the section table for .pstext")
    # Two sections rather than one RWX section: a lone write+execute section
    # trips the "packed executable" heuristic in PE scanners, and this feature
    # needs exactly four writable bytes.
    added = ((b".pstext", PS_RVA, PS_RAW, PS_SIZE, 0x60000020),   # code, R+X
             (b".psdata", PD_RVA, PD_RAW, PD_SIZE, 0xC0000040))   # data, R+W
    for n, (name, rva, raw, size, chars) in enumerate(added):
        slot = sect_hdr + n * 40
        if slot + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise RuntimeError("no room in the section table")
        if any(image[slot:slot + 40]):
            raise RuntimeError("section-table slot is not zero-filled")
        if len(image) != raw:
            raise RuntimeError(f"image is {len(image)} bytes, expected {raw:#x}")
        image[slot:slot + 40] = (
            name + bytes(8 - len(name))
            + struct.pack("<IIIIIIHHI", size, rva, size, raw, 0, 0, 0, 0, chars))
        image.extend(bytes(size))
    struct.pack_into("<H", image, e_lfanew + 6,
                     pe.FILE_HEADER.NumberOfSections + len(added))
    struct.pack_into("<I", image, opt_hdr + 56, PD_RVA + PD_SIZE)

    def ps_off(rva):
        if rva >= PD_RVA:
            return PD_RAW + (rva - PD_RVA)
        return PS_RAW + (rva - PS_RVA)
    image[ps_off(EXP_CACHE):ps_off(EXP_CACHE) + 4] = bytes([0xFF] * 4)
    image[ps_off(BASE_ORIG):ps_off(BASE_ORIG) + 4] = bytes([0xFF] * 4)

    strs = {}
    cur = PS_RVA
    for nm, txt in (
            ("key", b"PrivateStorageSlots"),
            ("set", b"  [PRIV] exp=%u (0x16=%u tot=%u) base %u -> %u"),
            ("nc",  b"  [PRIV] no container - root=%llX actor=%llX owner=%llX n=%u"),
            ("nf",  b"  [PRIV] no entry"),
            ("exp", b"PrivateStorageExpansions"),
            ("st",  b"  [PRIV] base=%u max=%u exp=%d owner=%llX n=%u"),
            ("tot", b"  [PRIV] container total %u -> %u")):
        strs[nm] = cur
        blob = txt + bytes(1)
        image[ps_off(cur):ps_off(cur) + len(blob)] = blob
        cur = (cur + len(blob) + 3) & ~3
    code_at = (cur + 15) & ~15

    code = bytearray()
    fix = []
    lbl = {}

    def emit(h):
        code.extend(bytes.fromhex(h))

    def imm(h, value):
        code.extend(bytes.fromhex(h))
        code.extend(struct.pack("<I", value))

    def rip(h, tgt):
        code.extend(bytes.fromhex(h))
        fix.append((len(code), tgt))
        code.extend(bytes(4))

    def jr(h, label):
        code.extend(bytes.fromhex(h))
        fix.append((len(code), label))
        code.extend(bytes(4))

    # Two entry points: the worker must stay silent, and the on-open path is the
    # only one allowed to touch the game's container list.
    lbl["quiet"] = 0                           # <- worker  (0x1400)
    emit("48 81 EC C8 00 00 00")
    emit("C6 44 24 60 00")
    skip = len(code)
    emit("EB 00")
    lbl["loud"] = len(code)                    # <- on-open (0x4776)
    emit("48 81 EC C8 00 00 00")
    emit("C6 44 24 60 01")
    code[skip + 1] = len(code) - (skip + 2)
    # Both entries converge here, so this is the one place that runs on every
    # pass of either path. The installer is a no-op after its first call.
    rip("E8", AW_HOOKINST)                     # one-shot ModeSwitch capture hook
    rip("E8", SLOT_PATCHER)                    # original housing patcher
    emit("89 44 24 30")                        # preserve its return value

    rip("48 8D 0D", SECTION_STR)               # "Settings"
    rip("48 8D 15", strs["key"])               # "PrivateStorageSlots"
    emit("45 31 C0")
    rip("4C 8D 0D", INI_PATH)
    rip("FF 15", GPP_INT)                      # GetPrivateProfileIntA
    emit("89 44 24 38")                        # desired TOTAL; 0 = put it back

    # Manual expansion count. -1 (the default) means "use what the container
    # walk finds"; any 0..2000 value overrides it, which delivers an exact
    # total even while the automatic lookup is still being nailed down.
    rip("48 8D 0D", SECTION_STR)
    rip("48 8D 15", strs["exp"])
    emit("41 B8 FF FF FF FF")
    rip("4C 8D 0D", INI_PATH)
    rip("FF 15", GPP_INT)
    emit("89 44 24 34")

    # Off, and this process has never written anything -> do nothing at all.
    # Without this, "off" still walked the whole lookup, which is how a stale
    # game address took the game down on 2.00 even with the feature disabled.
    emit("83 7C 24 38 00")
    jr("0F 85", "armed")
    rip("8B 05", PS_DIRTY)
    emit("85 C0")
    jr("0F 84", "done")
    lbl["armed"] = len(code)

    # Manager first: a constructed StaticInfoManager2 is the cheapest proof that
    # the game finished loading its data, and it gates every game call below.
    rip("48 8B 05", INVMGR_PTR)
    emit("48 85 C0")
    jr("0F 84", "nf")
    emit("48 8B 00")
    emit("48 85 C0")
    jr("0F 84", "nf")
    emit("83 78 6C 00")
    jr("0F 84", "nf")
    emit("83 78 68 00")
    jr("0F 84", "nf")
    emit("48 89 44 24 40")                     # save mgr

    rip("48 8B 05", GAME_BASE)
    emit("48 85 C0")
    jr("0F 84", "done")
    emit("66 C7 44 24 28 FF FF")               # outKey = 0xFFFF
    imm("48 8D 88", CAMP_NAME)                 # lea rcx,[base+"CampWareHouse"]
    emit("48 8D 54 24 28")
    imm("48 05", NAME_TO_KEY)
    emit("FF D0")
    emit("84 C0")
    jr("0F 84", "nf")
    emit("0F B7 44 24 28")
    emit("89 44 24 48")                        # key (survives the calls below)

    emit("48 8B 44 24 40")
    emit("44 8B 40 68")                        # r8d = bucket count
    emit("8B 44 24 48")
    emit("31 D2")
    emit("41 F7 F0")                           # edx = key % bucketCount
    emit("48 8B 4C 24 40")
    emit("89 D0")
    emit("48 C1 E0 08")
    emit("48 03 41 78")                        # bucket = (key%n)<<8 + [mgr+0x78]
    emit("44 8B 08")
    emit("45 85 C9")
    jr("0F 84", "nf")
    emit("31 D2")
    lbl["scan"] = len(code)
    emit("44 39 CA")
    jr("0F 83", "nf")
    emit("44 8B 54 D0 08")
    emit("44 3B 54 24 48")
    jr("0F 84", "hit")
    emit("FF C2")
    jr("E9", "scan")
    lbl["hit"] = len(code)
    emit("8B 54 D0 0C")                        # entry index
    emit("48 8B 4C 24 40")
    emit("3B 51 08")
    jr("0F 83", "nf")
    emit("89 54 24 4C")                        # the container list keys on THIS
    emit("48 8B 49 58")                        # array A
    emit("48 85 C9")
    jr("0F 84", "nf")
    emit("48 8B 0C D1")
    emit("48 85 C9")
    jr("0F 84", "nf")
    emit("48 89 4C 24 68")                     # info entry
    emit("0F B7 41 48")
    emit("85 C0")
    jr("0F 84", "nf")
    emit("3D D0 07 00 00")
    jr("0F 87", "nf")
    # First sight of the base in this process, before any write of ours. The
    # static table is rebuilt from the game's data files every launch, so this
    # is always the game's own number -- and it is what "0" restores to.
    rip("8B 15", BASE_ORIG)
    emit("83 FA FF")
    emit("75 06")
    rip("89 05", BASE_ORIG)

    # --- the player's expansion count, on-open path only -------------------
    #
    # AO crashed here. It passed the mod's cached mainChar (ASI 0x3D520, built
    # by ASI 0xAA10 as [[0x62C1500]+0x48]) to GetInventoryOwner, which promptly
    # dereferenced [that+0x68] -> [+0x20] -> word[+0x30]. That field is not the
    # component table, so the chain walked into garbage.
    #
    # The game's own way of reaching the actor repeats at game+0xAECF8F,
    # game+0xAF819B, game+0xB02A0C and ~700 other sites -- and it starts from
    # root+0x00, not root+0x48:
    #
    #   rax = [game+0x62C1500]            ; root
    #   rcx = [rax]                       ; handle holder
    #   call game+0x751D20(rcx, &out)     ; resolve  -> returns &out
    #   if !byte[out+0x10]: invalid
    #   actor = [out+0x08]
    #
    # The owner is then inlined rather than called for: GetInventoryOwner's
    # common path returns [[actor+0x68]+0xb8], which the game itself computes
    # inline at game+0x532903. That leaves one game call in the whole feature
    # and drops the type lookup at game+0x312740 that AO also ran.
    #
    # Every pointer is range-checked before use, with the same test the mod
    # already applies to its own globals at ASI 0xAA58, so a wrong field now
    # logs the chain instead of faulting.
    emit("C7 44 24 58 00 00 00 00")            # +0x16 cross-check
    emit("C7 44 24 5C 00 00 00 00")            # +0x14 cross-check
    emit("31 C0")
    emit("48 89 44 24 50")                     # root  = 0
    emit("48 89 84 24 88 00 00 00")            # actor = 0
    emit("48 89 84 24 90 00 00 00")            # owner = 0
    emit("89 84 24 98 00 00 00")               # count = 0
    emit("48 89 84 24 B8 00 00 00")            # matched container = none
    emit("80 7C 24 60 00")
    jr("0F 84", "apply")                       # worker -> cached value only

    def guard(bail):
        """rax must look like a user-mode heap pointer, or bail.

        The test runs on a scratch copy in r11: shifting rax itself would
        leave the caller holding the shift result instead of the pointer.
        """
        emit("48 3D 00 00 01 00")              # not a small integer
        jr("0F 86", bail)
        emit("49 89 C3")
        emit("49 C1 EB 2F")                    # high 17 bits clear?
        jr("0F 85", bail)

    # The mod already resolves this global at startup and logs it as
    # "MainCharGlobal:", so read its result instead of carrying the address.
    # One less thing for the next game update to move.
    rip("48 8B 05", GAME_GLOBAL_SLOT)
    emit("48 85 C0")
    jr("0F 84", "apply")
    emit("48 8B 00")                           # rax = root
    emit("48 89 44 24 50")
    emit("48 89 C1")                           # keep a copy for the guard
    guard("apply")
    emit("48 8B 09")                           # rcx = [root]  (handle holder)
    emit("48 89 C8")
    guard("apply")
    emit("48 8D 54 24 70")                     # rdx = &out
    emit("48 C7 02 00 00 00 00")
    emit("48 C7 42 08 00 00 00 00")
    emit("48 C7 42 10 00 00 00 00")            # zero the 24-byte out struct
    rip("48 8B 05", GAME_BASE)
    imm("48 05", RESOLVE_ACTOR)
    emit("FF D0")                              # rax = resolve(holder, &out)
    emit("48 85 C0")
    jr("0F 84", "apply")
    emit("80 78 10 00")                        # out+0x10: resolved?
    jr("0F 84", "apply")
    emit("48 8B 40 08")                        # rax = actor
    guard("apply")
    emit("48 89 84 24 88 00 00 00")
    emit("48 8B 40 68")                        # rax = component table
    guard("apply")
    imm("48 8B 80", 0xB8)                      # rax = [+0xb8]  = inventory owner
    guard("apply")
    emit("48 89 84 24 90 00 00 00")
    emit("49 89 C2")                           # r10 = owner
    emit("4D 8B 42 18")                        # r8 = container array
    emit("4C 89 C0")
    guard("apply")
    emit("41 8B 4A 20")                        # ecx = count
    emit("85 C9")
    jr("0F 84", "apply")
    emit("83 F9 40")
    jr("0F 87", "apply")                       # sanity: at most 64 containers
    emit("89 8C 24 98 00 00 00")               # count
    emit("4C 89 84 24 A0 00 00 00")            # array
    emit("31 C0")
    emit("89 84 24 A8 00 00 00")               # idx = 0
    emit("C6 44 24 64 00")                     # nothing recorded yet
    # The cursor lives on the stack, not in a register: the walk now logs each
    # container and the logger clobbers every volatile.
    lbl["cloop"] = len(code)
    emit("8B 84 24 A8 00 00 00")
    emit("3B 84 24 98 00 00 00")
    jr("0F 83", "apply")
    emit("48 8B 8C 24 A0 00 00 00")
    emit("48 8B 14 C1")                        # rdx = array[idx]
    emit("48 89 D0")
    guard("cnext")                             # skip a bad slot, keep walking
    # AQ's dump settled what container+0x10 holds: it is the INDEX into the
    # manager's array A, not the inventory key. 17 of the 18 containers satisfy
    # arrayA[c+0x10] == tot - expansions, and game+0x3AA5B2 uses word[c+0x10]
    # directly as that index. AP compared it against the key NameToKey returns
    # (8 for CampWareHouse) and so matched index 8 -- a decoy sitting right
    # beside the real one, 240 slots with no expansions. Private is index 7:
    # base 240 + 200 expansions = the 440 on screen.
    emit("0F B7 42 10")
    emit("3B 44 24 4C")
    jr("0F 84", "cfound")
    lbl["cnext"] = len(code)
    emit("8B 84 24 A8 00 00 00")
    emit("FF C0")
    emit("89 84 24 A8 00 00 00")
    jr("E9", "cloop")
    lbl["cfound"] = len(code)
    # First match wins, exactly as AP behaved; the walk continues only so the
    # dump covers the whole list.
    emit("80 7C 24 64 00")
    jr("0F 85", "cnext")
    emit("C6 44 24 64 01")
    emit("48 89 94 24 B8 00 00 00")            # keep it: the total is fixed below
    emit("0F B7 42 1A")                        # expansions (what the total uses)
    rip("89 05", EXP_CACHE)
    emit("0F B7 42 16")
    emit("89 44 24 58")
    emit("0F B7 42 14")
    emit("89 44 24 5C")
    jr("E9", "cnext")
    lbl["apply"] = len(code)
    # Unconditional status on the on-open path: AP only logged when the value
    # changed, so there was no way to tell whether an earlier write was still
    # standing on later opens.
    emit("80 7C 24 60 00")
    jr("0F 84", "stdone")
    emit("48 8B 4C 24 68")
    emit("48 85 C9")
    jr("0F 84", "stdone")
    emit("8B 84 24 98 00 00 00")
    emit("48 89 44 24 28")                     # n
    emit("48 8B 84 24 90 00 00 00")
    emit("48 89 44 24 20")                     # owner
    rip("44 8B 0D", EXP_CACHE)
    emit("44 0F B7 41 4A")                     # max
    emit("0F B7 51 48")                        # base
    rip("48 8D 0D", strs["st"])
    rip("E8", LOGGER)
    lbl["stdone"] = len(code)
    emit("8B 44 24 34")                        # manual override?
    emit("3D D0 07 00 00")
    emit("76 06")
    rip("8B 05", EXP_CACHE)                    # no -> what the walk found
    emit("3D D0 07 00 00")
    jr("0F 87", "nocont")
    emit("89 44 24 3C")                        # expansions

    emit("8B 54 24 38")
    emit("85 D2")
    jr("0F 85", "onpath")

    # PrivateStorageSlots=0 means "put it back", not "do nothing" -- AR left
    # whatever it had last written in place. Both numbers go to what the game
    # itself would hold: the captured base, and that base plus the player's own
    # expansions. Both writes are skipped when the values already match, so a
    # save that never had the option on is never touched.
    rip("8B 15", BASE_ORIG)
    emit("83 FA FF")
    jr("0F 84", "done")                        # never captured -> nothing to undo
    emit("8B 44 24 3C")
    emit("01 D0")
    emit("89 84 24 C0 00 00 00")               # target total = base + expansions
    jr("E9", "wr")                             # edx already holds the base

    lbl["onpath"] = len(code)
    emit("89 94 24 C0 00 00 00")               # target total = what was asked for
    emit("8B 44 24 3C")
    emit("29 C2")                              # base = total - expansions
    emit("83 FA 01")
    emit("7D 05")
    emit("BA 01 00 00 00")
    emit("81 FA D0 07 00 00")
    emit("7E 05")
    emit("BA D0 07 00 00")

    lbl["wr"] = len(code)
    emit("48 8B 4C 24 68")
    emit("0F B7 41 48")
    emit("39 D0")
    jr("0F 84", "tfix")                        # already correct -> just the total
    emit("66 89 51 48")                        # word[info+0x48] = base
    emit("41 BB 01 00 00 00")
    rip("44 89 1D", PS_DIRTY)
    emit("48 89 44 24 20")                     # 4th vararg: old base
    emit("89 D1")
    emit("48 89 4C 24 28")                     # 5th vararg: new base
    rip("8B 15", EXP_CACHE)
    emit("44 8B 44 24 58")
    emit("44 8B 4C 24 5C")
    rip("48 8D 0D", strs["set"])
    rip("E8", LOGGER)

    # The container caches its own total at +0x14, and the game only recomputes
    # it when expansions change -- which is why AQ's base=800 never reached the
    # screen. Setting the base keeps any future recompute correct; setting this
    # makes the number right now. The two agree: base + expansions == the total
    # written here.
    lbl["tfix"] = len(code)
    emit("48 8B 8C 24 B8 00 00 00")
    emit("48 85 C9")
    jr("0F 84", "done")
    emit("8B 84 24 C0 00 00 00")               # the target total
    emit("85 C0")
    jr("0F 84", "done")
    emit("3D D0 07 00 00")
    jr("0F 87", "done")
    emit("0F B7 51 14")
    emit("39 C2")
    jr("0F 84", "done")                        # already right
    emit("66 89 41 14")
    emit("41 BB 01 00 00 00")
    rip("44 89 1D", PS_DIRTY)
    emit("44 8B 84 24 C0 00 00 00")
    rip("48 8D 0D", strs["tot"])
    rip("E8", LOGGER)
    jr("E9", "done")

    lbl["nocont"] = len(code)
    emit("80 7C 24 60 00")
    jr("0F 84", "done")
    emit("48 8B 54 24 50")                     # root
    emit("4C 8B 84 24 88 00 00 00")            # actor
    emit("4C 8B 8C 24 90 00 00 00")            # owner
    emit("8B 84 24 98 00 00 00")
    emit("48 89 44 24 20")                     # count
    rip("48 8D 0D", strs["nc"])
    rip("E8", LOGGER)
    jr("E9", "done")

    lbl["nf"] = len(code)
    emit("80 7C 24 60 00")
    jr("0F 84", "done")
    rip("48 8D 0D", strs["nf"])
    rip("E8", LOGGER)

    lbl["done"] = len(code)
    emit("8B 44 24 30")
    emit("48 81 C4 C8 00 00 00")
    emit("C3")

    for at, tgt in fix:
        dest = lbl[tgt] + code_at if isinstance(tgt, str) else tgt
        code[at:at + 4] = struct.pack("<i", dest - (code_at + at + 4))
    if code_at + len(code) > PS_RVA + PS_SIZE:
        raise RuntimeError(f"AO wrapper overruns .pstext by "
                           f"{code_at + len(code) - (PS_RVA + PS_SIZE)} bytes")
    image[ps_off(code_at):ps_off(code_at) + len(code)] = code

    # The old .text cave is left untouched, so everything in .text outside these
    # two call sites is byte-identical to AI again.
    for site, entry in ((0x1400, "quiet"), (0x4776, "loud")):
        o = pe.get_offset_from_rva(site)
        if image[o] != 0xE8:
            raise RuntimeError(f"patcher call site {site:#x} is not a direct call")
        patch(pe, image, site, bytes(image[o:o + 5]),
              Asm(site).call(code_at + lbl[entry]).bytes())

    # =================================================================== AW
    # Take the mode object from the game instead of guessing a route to it.
    #
    # AU searched (§61: froze the game). AV enumerated twelve fixed chains
    # (§66: all twelve disproven). §68 closed the question statically -- of
    # 54657 rip-relative global loads in the 2.00 image not one reaches
    # +0x1158, and every real consumer takes its base from [this+0x28] where
    # `this` is a parameter. There is nothing left to derive.
    #
    # ModeSwitch (game+0x530E20 on this build, derived) is handed the object in
    # rcx, once per frame, from its single call site. AW hot-patches its entry
    # so the pointer lands in PS_MODEOBJ, and get_mode_obj reads it from there.
    #
    # The patch is one 8-byte store to an 8-byte-aligned address, which x86-64
    # performs atomically: every thread sees either the whole original qword or
    # the whole replacement, and both decode to a complete instruction at the
    # entry. That matters because ModeSwitch runs every frame -- a 15-byte
    # memcpy into live code has a window where the entry decodes as garbage,
    # and there is no ordering of those bytes that closes it.
    #
    # Eight bytes only reach ±2GB, and the ASI is further away than that, so
    # the store is `jmp rel32` + 3 nops into a one-page trampoline allocated
    # near the game image, which then jumps the rest of the way. If the
    # allocation, the API resolution, or the byte check fails, nothing is
    # written and the mod behaves exactly as AT did.
    av_strs = {}
    cur = PS_RVA + 0x700
    if cur < code_at + len(code):
        raise RuntimeError("AW strings would overlap the private-slots wrapper")
    for nm, txt in (
            ("k32",  b"kernel32.dll"),
            ("vq",   b"VirtualQuery"),
            ("vp",   b"VirtualProtect"),
            ("va",   b"VirtualAlloc"),
            ("gle",  b"GetLastError"),
            ("head", b"  [MODE] root=%llX menuMgr=%llX capture=%llX"),
            ("novq", b"  [MODE] VirtualQuery unavailable - probe skipped"),
            ("hkok", b"  [MODE] capture hook armed at %llX -> %llX"),
            ("hkno", b"  [MODE] capture hook NOT armed (stage %u)"),
            ("cand", b"  [MODE] c%u ptr=%llX m=%02X s=%02X f=%02X t=%02X d=%02X"
                     b" x=%02X%02X")):
        av_strs[nm] = cur
        blob = txt + bytes(1)
        image[ps_off(cur):ps_off(cur) + len(blob)] = blob
        cur = (cur + len(blob) + 3) & ~3
    if cur > AW_BASE:
        raise RuntimeError(f"AW strings run into the AW code block by "
                           f"{cur - AW_BASE} bytes")
    av_at = AW_BASE

    acode = bytearray()
    afix = []
    albl = {}

    def ae(h):
        acode.extend(bytes.fromhex(h))

    def ai32(h, value):
        acode.extend(bytes.fromhex(h))
        acode.extend(struct.pack("<I", value))

    def ar(h, tgt):
        acode.extend(bytes.fromhex(h))
        afix.append((len(acode), tgt))
        acode.extend(bytes(4))

    def aj(h, label):
        acode.extend(bytes.fromhex(h))
        afix.append((len(acode), label))
        acode.extend(bytes(4))

    def ai64(h, value):
        acode.extend(bytes.fromhex(h))
        acode.extend(struct.pack("<Q", value))

    # ---- the two fixed entry points ---------------------------------------
    # These must be the first ten bytes of the block: the cave helper and the
    # private-slots wrapper both branch here by absolute RVA, and both are
    # written before this code is laid out.
    aj("E9", "modeobj")                         # AW_MODEOBJ
    aj("E9", "hookinst")                        # AW_HOOKINST
    if av_at + len(acode) != AW_HOOKINST + 5:
        raise RuntimeError("AW dispatch table is not the expected 10 bytes")

    # ---- get_mode_obj ------------------------------------------------------
    # Leaf: no call, no push, no stack write, so it needs no unwind info even
    # though .pstext has no .pdata of its own.
    albl["modeobj"] = len(acode)
    ar("48 8B 05", PS_MODEOBJ)                  # mov rax,[PS_MODEOBJ]
    ae("48 3D 00 00 01 00")
    aj("0F 86", "mo_fb")                        # jbe -> AT's old walk
    ae("48 85 C0")                              # test rax,rax -> ZF=0
    ae("C3")
    albl["mo_fb"] = len(acode)
    ar("48 8B 05", GAME_GLOBAL_SLOT)
    ae("48 85 C0")
    aj("0F 84", "mo_no")
    ae("48 8B 00")                              # rax = root
    for deref in (0x90, MODE_OBJ_IN_MENUMGR):
        ae("48 3D 00 00 01 00")
        aj("0F 86", "mo_no")
        ai32("48 8B 80", deref)                 # mov rax,[rax+deref]
    ae("48 3D 00 00 01 00")
    aj("0F 86", "mo_no")
    ae("48 85 C0")
    ae("C3")
    albl["mo_no"] = len(acode)
    ae("31 C0")
    ae("48 85 C0")                              # ZF=1
    ae("C3")

    # ---- the capture stub, entered from ModeSwitch's patched entry ---------
    # Arrives with rsp exactly as ModeSwitch was called (the hot patch is a
    # jump, not a call), rcx = the mode object, rax dead. It records rcx,
    # re-issues the three spills the patch displaced, and rejoins ModeSwitch at
    # its fourth instruction. It pushes nothing, so an unwind through it reads
    # the return address at [rsp] and is correct.
    albl["capture"] = len(acode)
    ar("48 89 0D", PS_MODEOBJ)                  # mov [PS_MODEOBJ],rcx
    ae(MODE_SWITCH_PROLOGUE.hex())              # the displaced spills, verbatim
    ar("48 8B 05", GAME_BASE)
    ai32("48 05", MODE_SWITCH + len(MODE_SWITCH_PROLOGUE))
    ae("FF E0")                                 # jmp back

    # ---- the one-shot installer -------------------------------------------
    # Volatile registers and its own frame only. Every failure is silent to the
    # game: it logs a stage number and leaves ModeSwitch untouched, which puts
    # the mod back to exactly AT's behaviour.

    albl["hookinst"] = len(acode)
    ae("48 81 EC 98 00 00 00")                  # 0x98: room for an mbi at +0x58
    ae("48 C7 44 24 48 00 00 00 00")            # page slot = 0 until allocated
    ae("48 C7 44 24 50 00 00 00 00")            # cursor slot = 0 until stage 3
    ar("8B 05", PS_HOOKED)
    ae("85 C0")
    aj("0F 85", "hi_out")                       # tried once already
    ae("B8 02 00 00 00")
    ar("89 05", PS_HOOKED)                      # assume failure from here on

    ae("B9 01 00 00 00")                        # stage 1: resolve the APIs
    ae("89 4C 24 30")
    ar("48 8D 0D", av_strs["k32"])
    ar("FF 15", LOADLIBRARYA)
    ae("48 85 C0")
    aj("0F 84", "hi_fail")
    ae("48 89 44 24 50")
    ae("48 8B 4C 24 50")
    ar("48 8D 15", av_strs["vp"])
    ar("FF 15", GETPROCADDRESS)
    ae("48 85 C0")
    aj("0F 84", "hi_fail")
    ar("48 89 05", VP_PTR)
    ae("48 8B 4C 24 50")
    ar("48 8D 15", av_strs["va"])
    ar("FF 15", GETPROCADDRESS)
    ae("48 85 C0")
    aj("0F 84", "hi_fail")
    ar("48 89 05", VA_PTR)
    ae("48 8B 4C 24 50")
    ar("48 8D 15", av_strs["vq"])
    ar("FF 15", GETPROCADDRESS)
    ae("48 85 C0")
    aj("0F 84", "hi_fail")
    ar("48 89 05", VQ_PTR)
    ae("48 8B 4C 24 50")
    ar("48 8D 15", av_strs["gle"])
    ar("FF 15", GETPROCADDRESS)
    ar("48 89 05", GLE_PTR)                     # optional: null just skips the errno

    ae("B9 02 00 00 00")                        # stage 2: the bytes are still ours
    ae("89 4C 24 30")
    ar("48 8B 05", GAME_BASE)
    ae("48 85 C0")
    aj("0F 84", "hi_fail")
    ai32("48 05", MODE_SWITCH)
    ae("48 89 44 24 38")                        # the hook target
    ai64("48 BA", struct.unpack("<Q", MODE_SWITCH_PROLOGUE[0:8])[0])
    ae("48 39 10")
    aj("0F 85", "hi_fail")
    ai64("48 BA", struct.unpack("<Q", MODE_SWITCH_PROLOGUE[7:15])[0])
    ae("48 39 50 07")
    aj("0F 85", "hi_fail")

    # stage 3: a page within reach of ModeSwitch for the trampoline.
    #
    # 2.00 found one on its first guess, 1 MB below the image. 2.01.00 refused
    # sixteen guesses at 16 MB steps below the base, and guessing harder is the
    # wrong tool: whether an address is free depends on what the game and the
    # other plugins in the process have reserved, which no static value can
    # know. So stop guessing. Walk the address space with VirtualQuery from
    # ~2 GB below the hook target upward, region by region, and allocate in the
    # first MEM_FREE region that has a 64 KB-aligned page to spare. VirtualQuery
    # skips a whole region per call, so this is a handful of calls, and stage 4
    # still measures the displacement rather than trusting the walk's bound.
    #
    # mbi lives at [rsp+0x58]: BaseAddress +0x58, RegionSize +0x70, State +0x78.
    ae("B9 03 00 00 00")
    ae("89 4C 24 30")
    ae("48 8B 44 24 38")                        # rax = hook target
    ae("48 2D 00 00 00 7F")                     # start 0x7F000000 below it
    ae("48 3D 00 00 01 00")
    aj("0F 8D", "hi_clamp")                     # signed: negative -> clamp
    ae("B8 00 00 01 00")                        # lowest user address
    albl["hi_clamp"] = len(acode)
    ae("48 89 44 24 50")                        # cursor
    albl["hi_walk"] = len(acode)
    ae("48 8B 44 24 50")
    ae("48 2B 44 24 38")                        # cursor - target
    ae("48 3D 00 00 00 7F")
    aj("0F 8F", "hi_f32")                       # 32: walked past +2 GB
    ae("48 8B 4C 24 50")
    ae("48 8D 54 24 58")                        # &mbi
    ae("41 B8 30 00 00 00")                     # sizeof(mbi)
    ar("FF 15", VQ_PTR)
    ae("48 85 C0")
    aj("0F 84", "hi_f31")                       # 31: VirtualQuery returned 0
    ae("8B 44 24 78")                           # mbi.State
    ae("3D 00 00 01 00")                        # MEM_FREE
    aj("0F 85", "hi_next")
    ar("FF 05", PS_DIAG_FREE)                   # inc dword [free seen]
    ae("48 8B 44 24 50")
    ae("48 05 FF FF 00 00")
    ae("48 25 00 00 FF FF")                     # candidate = align_up(cursor, 64 KB)
    ae("48 8B 4C 24 58")
    ae("48 03 4C 24 70")                        # region end
    ae("48 8D 90 00 10 00 00")                  # candidate + 0x1000
    ae("48 39 CA")
    aj("0F 87", "hi_next")                      # page would spill past the region
    ar("48 89 05", PS_DIAG_CAND)                # last candidate
    ar("FF 05", PS_DIAG_TRIES)                  # inc dword [attempts]
    ae("48 89 C1")
    ae("BA 00 10 00 00")                        # 0x1000 bytes
    ae("41 B8 00 30 00 00")                     # MEM_COMMIT | MEM_RESERVE
    ae("41 B9 04 00 00 00")                     # PAGE_READWRITE, execute later
    ar("FF 15", VA_PTR)
    ae("48 85 C0")
    aj("0F 85", "hi_got")
    ar("48 8B 05", GLE_PTR)                     # errno of that failure, if resolvable
    ae("48 85 C0")
    aj("0F 84", "hi_next")
    ae("FF D0")
    ar("89 05", PS_DIAG_ERR)
    albl["hi_next"] = len(acode)
    ae("48 8B 44 24 58")
    ae("48 03 44 24 70")                        # cursor = BaseAddress + RegionSize
    ae("48 89 44 24 50")
    aj("E9", "hi_walk")
    albl["hi_got"] = len(acode)
    ae("48 89 44 24 48")
    aj("48 8D 05", "capture")                   # lea rax,[capture]
    ae("48 8B 54 24 48")
    ae("66 C7 02 48 B8")                        # mov rax, imm64
    ae("48 89 42 02")
    ae("66 C7 42 0A FF E0")                     # jmp rax
    # Write first, execute after: never leave a writable+executable page behind.
    # Same reasoning as the two appended sections above.
    ae("48 8B 4C 24 48")
    ae("BA 00 10 00 00")
    ae("41 B8 20 00 00 00")                     # PAGE_EXECUTE_READ
    ae("4C 8D 4C 24 40")
    ar("FF 15", VP_PTR)
    ae("85 C0")
    aj("0F 84", "hi_f33")                       # 33: RX protect of the new page failed

    ae("B9 04 00 00 00")                        # stage 4: the displacement fits
    ae("89 4C 24 30")
    ae("48 8B 44 24 48")
    ae("48 2B 44 24 38")
    ae("48 83 E8 05")
    ae("48 63 D0")
    ae("48 39 C2")                              # sign-extends back? then it fits
    aj("0F 85", "hi_fail")
    ae("89 C2")                                 # rdx = (uint32)rel
    ae("48 C1 E2 08")
    ae("48 81 CA E9 00 00 00")                  # E9 in byte 0
    ai64("48 B8", 0x9090900000000000)           # three nops in bytes 5..7
    ae("48 09 C2")
    ae("48 89 54 24 20")

    ae("B9 05 00 00 00")                        # stage 5: the store itself
    ae("89 4C 24 30")
    ae("48 8B 4C 24 38")
    ae("BA 08 00 00 00")
    ae("41 B8 40 00 00 00")
    ae("4C 8D 4C 24 40")
    ar("FF 15", VP_PTR)
    ae("85 C0")
    aj("0F 84", "hi_fail")
    ae("48 8B 4C 24 38")
    ae("48 8B 54 24 20")
    ae("48 89 11")                              # ONE aligned 8-byte store
    ae("48 8B 4C 24 38")
    ae("BA 08 00 00 00")
    ae("44 8B 44 24 40")
    ae("4C 8D 4C 24 40")
    ar("FF 15", VP_PTR)

    ae("B8 01 00 00 00")
    ar("89 05", PS_HOOKED)
    ae("4C 8B 44 24 48")
    ae("48 8B 54 24 38")
    ar("48 8D 0D", av_strs["hkok"])
    ar("E8", LOGGER)
    aj("E9", "hi_out")
    for code in (31, 33):
        albl["hi_f%d" % code] = len(acode)
        ae("C7 44 24 30 %02X 00 00 00" % code)
        aj("E9", "hi_fail")
    # 32: nothing in reach *right now*. That is a property of the moment --
    # mid-load the band is carved into slivers -- not of the process, so leave
    # PS_HOOKED at 0 and let the worker's next cycle try again. Say so once,
    # retry quietly, and only give up for good (36) after 600 attempts (~10 min).
    albl["hi_f32"] = len(acode)
    ae("C7 44 24 30 20 00 00 00")
    ar("FF 05", PS_RETRIES)                     # inc dword [retries]
    ar("8B 05", PS_RETRIES)
    ae("3D 58 02 00 00")                        # 600 attempts: the worker sleeps 1 s per cycle, so ~10 min
    aj("0F 8C", "hi_f32r")
    ae("C7 44 24 30 24 00 00 00")               # 36: gave up after retrying
    aj("E9", "hi_fail")
    albl["hi_f32r"] = len(acode)
    ae("31 C9")
    ar("89 0D", PS_HOOKED)                      # PS_HOOKED = 0: try again later
    ae("3D 01 00 00 00")
    aj("0F 85", "hi_out")                       # retries after the first are silent
    aj("E9", "hi_fail")                         # first time: log stage 32 once
    albl["hi_fail"] = len(acode)
    ae("48 8B 44 24 50")
    ar("48 89 05", PS_DIAG_CURSOR)              # where the walk was
    ae("48 8B 44 24 48")
    ar("48 89 05", PS_DIAG_PAGE)                # what, if anything, it allocated
    ae("8B 54 24 30")
    ar("48 8D 0D", av_strs["hkno"])
    ar("E8", LOGGER)
    albl["hi_out"] = len(acode)
    ae("48 81 C4 98 00 00 00")
    ae("C3")

    # ---- rdbl(rcx) -> al: is this exact address committed and readable? ----
    albl["rdbl"] = len(acode)
    ae("48 83 EC 58")
    ae("48 85 C9")
    aj("0F 84", "rdblno")
    ar("48 8B 05", VQ_PTR)
    ae("48 85 C0")
    aj("0F 84", "rdblno")
    ae("48 8D 54 24 20")                        # &mbi
    ae("41 B8 30 00 00 00")                     # sizeof(MEMORY_BASIC_INFORMATION)
    ae("FF D0")
    ae("48 85 C0")
    aj("0F 84", "rdblno")
    ae("8B 44 24 40")                           # mbi.State
    ae("3D 00 10 00 00")                        # MEM_COMMIT
    aj("0F 85", "rdblno")
    ae("8B 44 24 44")                           # mbi.Protect
    ae("A8 01")                                 # PAGE_NOACCESS
    aj("0F 85", "rdblno")
    ae("A9 00 01 00 00")                        # PAGE_GUARD
    aj("0F 85", "rdblno")
    ae("B0 01")
    ae("48 83 C4 58")
    ae("C3")
    albl["rdblno"] = len(acode)
    ae("30 C0")
    ae("48 83 C4 58")
    ae("C3")

    # ---- finish(rcx = candidate, edx = index): validate, read, log ---------
    #
    # Two bugs have lived here, and both are structural rather than careless.
    #
    # §65: the format has N conversions, so under Win64 the stack arguments
    # start at [rsp+0x20] -- and AV parked the saved pointer and index in two of
    # those slots, silently overwriting the last two conversions. The saved
    # values now live ABOVE the whole argument block.
    #
    # §73: this function hardcoded +0x50/+0x51/+0x31/+0x38/+0x5B while the patch
    # itself used the derived L_* values. Two sources of truth, so when the
    # derivation was wrong the probe agreed with it and could not expose it.
    # It now emits the derived offsets, and logs the discarded +0x50/+0x51 pair
    # as `x` so a future divergence between the mode and the shadow array shows
    # up in the log instead of costing a test round.
    #
    # Index 0 is reserved for the object the capture hook recorded.
    FIN_ARGS = ((L_SUB, 0x20), (L_FLAGS, 0x28), (L_SUBTYPES, 0x30),
                (L_DIRTY, 0x38), (0x50, 0x40), (0x51, 0x48))
    albl["fin"] = len(acode)
    ae("48 83 EC 68")
    ae("48 89 4C 24 50")                        # keep the pointer
    ae("89 54 24 58")                           # keep the index
    for probe in sorted({L_MODE} | {off for off, _ in FIN_ARGS}):
        ae("48 8B 4C 24 50")
        ai32("48 8D 89", probe)                 # the exact byte about to be read
        aj("E8", "rdbl")
        ae("84 C0")
        aj("0F 84", "finout")
    ae("48 8B 4C 24 50")
    for off, slot in FIN_ARGS:
        ai32("0F B6 81", off)                   # movzx eax, byte [rcx+off]
        ae("48 89 44 24 %02X" % slot)
    ai32("44 0F B6 89", L_MODE)                 # mode -> r9
    ae("49 89 C8")                              # ptr  -> r8
    ae("8B 54 24 58")                           # index -> rdx
    ar("48 8D 0D", av_strs["cand"])
    ar("E8", LOGGER)
    albl["finout"] = len(acode)
    ae("48 83 C4 68")
    ae("C3")

    # ---- the probe ---------------------------------------------------------
    albl["diag"] = len(acode)
    ae("50 51 52 41 50 41 51 41 52 41 53")
    ae("48 81 EC A0 00 00 00")   # imm32: 0xA0 will not fit an imm8

    # resolve VirtualQuery once
    ar("48 8B 05", VQ_PTR)
    ae("48 85 C0")
    aj("0F 85", "havevq")
    ar("48 8D 0D", av_strs["k32"])
    ar("FF 15", LOADLIBRARYA)
    ae("48 85 C0")
    aj("0F 84", "novq")
    ae("48 89 C1")
    ar("48 8D 15", av_strs["vq"])
    ar("FF 15", GETPROCADDRESS)
    ar("48 89 05", VQ_PTR)
    ae("48 85 C0")
    aj("0F 85", "havevq")
    albl["novq"] = len(acode)
    ar("48 8D 0D", av_strs["novq"])
    ar("E8", LOGGER)
    aj("E9", "dgout")
    albl["havevq"] = len(acode)

    # root, then menuMgr = [root+0x90]
    ar("48 8B 05", GAME_GLOBAL_SLOT)
    ae("48 85 C0")
    aj("0F 84", "dgout")
    ae("48 89 C1")
    aj("E8", "rdbl")
    ae("84 C0")
    aj("0F 84", "dgout")
    ar("48 8B 05", GAME_GLOBAL_SLOT)
    ae("48 8B 00")
    ae("48 89 44 24 70")                        # root
    ae("48 8D 88 90 00 00 00")
    aj("E8", "rdbl")
    ae("84 C0")
    aj("0F 84", "nomm")
    ae("48 8B 4C 24 70")
    ae("48 8B 89 90 00 00 00")
    ae("48 89 4C 24 78")                        # menuMgr
    albl["nomm"] = len(acode)

    ar("4C 8B 0D", PS_MODEOBJ)                  # r9 = whatever the hook caught
    ae("4C 8B 44 24 78")
    ae("48 8B 54 24 70")
    ar("48 8D 0D", av_strs["head"])
    ar("E8", LOGGER)

    # The captured object goes through the same guarded reader as everything
    # else and logs as candidate 0. If the hook never armed, PS_MODEOBJ is
    # still zero and this is skipped.
    ar("48 8B 0D", PS_MODEOBJ)
    ae("48 85 C9")
    aj("0F 84", "nocap")
    ae("31 D2")
    aj("E8", "fin")
    albl["nocap"] = len(acode)

    # ---- the twelve candidates --------------------------------------------
    def candidate(idx, base_slot, steps):
        """base_slot is the frame offset holding the starting pointer."""
        skip = f"cskip{idx}"
        ae("48 8B 4C 24 %02X" % base_slot)
        ae("48 85 C9")
        aj("0F 84", skip)
        for disp in steps:
            ae("48 89 8C 24 80 00 00 00")       # keep the current pointer
            ai32("48 8D 89", disp)              # the exact address about to be read
            aj("E8", "rdbl")
            ae("84 C0")
            aj("0F 84", skip)
            ae("48 8B 8C 24 80 00 00 00")
            ai32("48 8B 89", disp)
        ae("BA %02X 00 00 00" % idx)
        aj("E8", "fin")
        albl[skip] = len(acode)

    MENUMGR, ROOT = 0x78, 0x70
    candidate(1,  MENUMGR, [MODE_OBJ_IN_MENUMGR])       # the derived route
    candidate(2,  MENUMGR, [0x1150])
    candidate(3,  MENUMGR, [0x1158])            # where 2.00 kept it
    candidate(4,  MENUMGR, [0x1160])
    candidate(5,  MENUMGR, [0x11A0])
    candidate(6,  MENUMGR, [0x11B0])
    candidate(7,  MENUMGR, [0x11B8])
    candidate(8,  MENUMGR, [0x28, MODE_OBJ_IN_MENUMGR])
    candidate(9,  ROOT,    [0x28, MODE_OBJ_IN_MENUMGR])
    candidate(10, ROOT,    [0x28, 0x28, MODE_OBJ_IN_MENUMGR])   # the game's own shape
    candidate(11, ROOT,    [MODE_OBJ_IN_MENUMGR])
    candidate(12, ROOT,    [0x98, MODE_OBJ_IN_MENUMGR])

    albl["dgout"] = len(acode)
    ae("48 81 C4 A0 00 00 00")
    ae("41 5B 41 5A 41 59 41 58 5A 59 58")
    ae("44 8B C1")                              # mov r8d, ecx
    ar("48 8D 0D", BLOCKED_FMT)
    ae("C3")

    for at, tgt in afix:
        dest = albl[tgt] + av_at if isinstance(tgt, str) else tgt
        acode[at:at + 4] = struct.pack("<i", dest - (av_at + at + 4))
    if av_at + len(acode) > PS_RVA + PS_SIZE:
        raise RuntimeError(f"AW block overruns .pstext by "
                           f"{av_at + len(acode) - (PS_RVA + PS_SIZE)} bytes")
    image[ps_off(av_at):ps_off(av_at) + len(acode)] = acode
    print(f"AW block  {len(acode):#x} of {PS_RVA + PS_SIZE - av_at:#x} bytes "
          f"at {av_at:#x}; modeobj={AW_MODEOBJ:#x} hookinst={AW_HOOKINST:#x}")

    o = pe.get_offset_from_rva(0xB5F3)
    patch(pe, image, 0xB5F3, bytes(image[o:o + 10]),
          Asm(0xB5F3).call(av_at + albl["diag"]).bytes() + b"\x90" * 5)







    # (3) The per-entry slot field at +0x48 is CONFIRMED by the AH diagnostic.
    #     AH ran this same walk with the write NOP'd and reported 5 matches on
    #     every one of 167 worker passes, zero variance. The game's
    #     InventoryInfoKey pool holds exactly five Housing_* keys (Symbol,
    #     Refrigerator, GatheredMaterials, Collecting, Dresser) -- the five
    #     housing chests that default to 10 slots. CampWareHouse (440) and the
    #     other 13 keys correctly fail the == 10 guard. So the walk selects
    #     exactly the intended containers, and the write is enabled here.
    #
    #     Leaving the original instruction in place also stops the log spam AH
    #     produced: once the entries read 1000 the guard stops matching, the
    #     count goes to zero and the worker's `jle` skips logging entirely.


    # ------------------------------------------------------------------ (H")
    # Hand the inventory-manager slot straight to the success path. The scan
    # this replaces cannot work on 2.01.00 at any tuning, so retuning it would
    # only move the failure; the value it was looking for is derived above.
    inv = Asm(INV_MGR_SCAN)
    inv.riprel(b"\x48\x8B\x05", GAME_BASE)               # mov rax,[game base]
    inv.raw(b"\x48\x05" + struct.pack("<I", t["INV_MGR_GLOBAL"]))   # add rax,rva
    inv.raw(b"\x49\x89\xC7")                             # mov r15,rax
    inv.raw(b"\x41\xBB" + struct.pack("<I", t["INV_MGR_GLOBAL"]))   # mov r11d,rva
    inv.raw(b"\x33\xFF")                                 # xor edi,edi
    inv.jmp32(INV_MGR_FOUND)                              # jmp found
    if len(inv.bytes()) > INV_MGR_SCAN_LEN:
        raise RuntimeError("the inventory-manager stub does not fit the scan "
                           f"it replaces: {len(inv.bytes())} > {INV_MGR_SCAN_LEN}")
    patch(pe, image, INV_MGR_SCAN, INV_MGR_SCAN_ORIG,
          inv.pad_to(INV_MGR_SCAN_LEN).bytes())

    # ------------------------------------------------------------------ (H')
    # Retune the pristine MainCharGlobal scan to this executable. Nothing about
    # the shape it looks for changes; only the two literals that 2.01.00 moved.
    patch(pe, image, MAINCHAR_DISP8_IMM, b"\x48",
          struct.pack("<B", t["MAINCHAR_DISP8"]))
    patch(pe, image, MAINCHAR_WINDOW_DISP, struct.pack("<i", -0xC00),
          struct.pack("<i", -t["MAINCHAR_WINDOW"]))

    # ------------------------------------------------------------------ (H)
    old_tag, new_tag = b"CD 1.13.01", b"CD 2.01.00"   # same length as the tag it replaces
    at = image.find(old_tag)
    if at < 0 or image.find(old_tag, at + 1) >= 0:
        raise RuntimeError("expected exactly one build tag")
    image[at:at + len(old_tag)] = new_tag

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(image)
    print(f"input_sha256={digest}")
    print(f"layout mode=0x{L_MODE:X} sub=0x{L_SUB:X} flags=0x{L_FLAGS:X} "
          f"subtypes=0x{L_SUBTYPES:X} dirty=0x{L_DIRTY:X}")
    print(f"stub=0x{CAVE:X}+0x{len(stub):X} helper=0x{HELPER:X}+0x5(jmp) "
          f"telemetry=0x{TELEMETRY:X}+0x{len(telemetry):X} "
          f"gate=0x{DISARM:X}+0x{len(gate_bytes):X} cave_end=0x{CAVE_END:X}")
    print(f"modeswitch=0x{MODE_SWITCH:X} capture-hook=8 bytes, aligned")
    print(f"output_sha256={hashlib.sha256(image).hexdigest()}")
    print(f"wrote={destination} bytes={len(image)}")


# Guarded so validate_aw.py can import derive_game_targets and the layout
# constants without running a build.
if __name__ == "__main__":
    main()
