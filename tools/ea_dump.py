"""Save the EA build of DAOrigins.exe as it is in memory once its own wrapper
has decrypted it, so tools/daoexe.py and tools/exemap.py can read it like the
GOG file (dev/BUILDS.md).

    python tools/ea_dump.py [install's bin_ship]     writes game/ea/DAOrigins.dump.exe

THIS STARTS THE GAME, through the EA app, which it opens if it is not open.
Say so before running it, and not while another copy of the game is in use.

The EA file's .text and .data are encrypted on disk, and its entry point is
one jump into Core\\Activation.dll (ordinal 100), which checks the licence,
decrypts both sections in place and goes on to the game's real entry point.
Nothing here touches that. The installed, licensed game is started and left
to decrypt itself:

1. daorigins.exe, started by anything but the EA app, decrypts nothing. It
   asks the EA app to start the game and exits with 0.
2. The EA app starts daorigins.exe again, and that run decrypts. It is
   frozen as soon as the sections in memory differ from the file, about a
   second and a half in and before a window opens, the image is copied out,
   and the process is ended.

Seen 2026-10-01: the wrapper's own Core\\ActivationUI.exe, which the frozen
run had started, is left behind with no window and has to be ended by hand,
and the EA app stays open.

What is written is the file on disk with the two sections replaced from
memory and the header fields the wrapper took over (entry point, import, IAT
and relocation directories) pointed back at the game's own, which are still
there in .rdata and .reloc; .rdata, .rsrc and .reloc are the same in memory
as on disk. It is for reading, and stays in game\\, which git ignores.
"""

import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import daoexe  # noqa: E402

INSTALL = r"C:\Program Files\EA Games\Dragon Age\bin_ship"
OUT = os.path.join(HERE, "..", "game", "ea", "DAOrigins.dump.exe")

CREATE_SUSPENDED = 0x4
TH32CS_SNAPPROCESS = 0x2
# terminate, suspend, read memory, query, wait
ACCESS = 0x0001 | 0x0800 | 0x0010 | 0x1000 | 0x00100000
TIMEOUT_SECONDS = 240

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


k32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
k32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
k32.ResumeThread.argtypes = [wintypes.HANDLE]
k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]


def sections(img):
    """(name, rva, virtual size, raw size, raw offset), which daoexe.Image
    folds into one size."""
    d = img.data
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec, optsz = (
        struct.unpack_from("<H", d, pe + 6)[0],
        struct.unpack_from("<H", d, pe + 20)[0],
    )
    at = pe + 24 + optsz
    out = []
    for i in range(nsec):
        name = d[at + 40 * i : at + 40 * i + 8].rstrip(b"\0").decode()
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", d, at + 40 * i + 8)
        out.append((name, va, vsize, rawsize, raw))
    return out


def probes(img):
    """(va, the bytes on disk) near the start, at the middle and near the end
    of each encrypted section. The wrapper's own jump and import table sit in
    the first bytes of .text and .data, so the first probe starts past them."""
    out = []
    for name, rva, _, rawsize, raw in sections(img):
        if name in (".text", ".data"):
            for where in (0x400, rawsize // 2, rawsize - 0x400):
                at = where & ~0xF
                out.append(
                    (img.image_base + rva + at, img.data[raw + at : raw + at + 32])
                )
    return out


def read(process, va, size):
    """size bytes of the process at va, or None where they cannot be read:
    a page not there, or a process that has gone."""
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(process, va, buf, size, ctypes.byref(got)):
        return None
    return buf.raw[: got.value]


def running(exe, access=ACCESS, apart_from=()):
    """(handle, pid) of a running process whose image is exe, or None. The
    GOG game has the same file name, so the full path decides."""
    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    found = None
    more = k32.Process32FirstW(snapshot, ctypes.byref(entry))
    while more and found is None:
        if (
            entry.szExeFile.lower() == os.path.basename(exe).lower()
            and entry.th32ProcessID not in apart_from
        ):
            process = k32.OpenProcess(access, False, entry.th32ProcessID)
            if process:
                path = ctypes.create_unicode_buffer(1024)
                size = wintypes.DWORD(1024)
                k32.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(size))
                if os.path.normcase(path.value) == os.path.normcase(exe):
                    found = (process, entry.th32ProcessID)
                else:
                    k32.CloseHandle(process)
        more = k32.Process32NextW(snapshot, ctypes.byref(entry))
    k32.CloseHandle(snapshot)
    return found


def freeze_when_decrypted(process, watch, seconds):
    """Freeze the process as soon as every probe reads differently from the
    file; False if it exits first. A read that fails is not a difference: the
    first version of this took a process that had gone for one that had
    decrypted. No sleep in the loop: the gap between the last block
    decrypted and the process frozen is what game code gets to run."""
    started = time.monotonic()
    while True:
        seen = [(read(process, va, len(on_disk)), on_disk) for va, on_disk in watch]
        if all(now is not None and now != on_disk for now, on_disk in seen):
            ntdll.NtSuspendProcess(process)
            print(f"decrypted and frozen after {time.monotonic() - started:.3f} s")
            return True
        if k32.WaitForSingleObject(process, 0) == 0:
            return False
        if time.monotonic() - started > seconds:
            raise RuntimeError(f"nothing decrypted in {seconds} s")


def copy_out(process, img):
    """{section: its bytes in the process}, zeroes where a page is not there."""
    memory = {}
    for name, va, vsize, rawsize, _ in sections(img):
        pages = bytearray()
        for page in range(0, max(vsize, rawsize), 0x1000):
            got = read(process, img.image_base + va + page, 0x1000)
            pages += got if got and len(got) == 0x1000 else bytes(0x1000)
        memory[name] = bytes(pages)
    return memory


def dump(install):
    exe = os.path.join(install, "daorigins.exe")
    img = daoexe.Image(exe)
    watch = probes(img)

    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    made = PROCESS_INFORMATION()
    command = ctypes.create_unicode_buffer(f'"{exe}"')
    if not k32.CreateProcessW(
        exe,
        command,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        install,
        ctypes.byref(startup),
        ctypes.byref(made),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    process, thread = made.hProcess, made.hThread
    print(f"started {exe}, pid {made.dwProcessId}")
    try:
        for va, on_disk in watch:
            if read(process, va, len(on_disk)) != on_disk:
                raise RuntimeError(
                    f"{va:#x} differs from the file before the wrapper ran: not at the preferred base?"
                )
        k32.ResumeThread(thread)
        if freeze_when_decrypted(process, watch, TIMEOUT_SECONDS):
            return img, copy_out(process, img)
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(process, ctypes.byref(code))
        print(
            f"that run exited with {code.value:#x}, nothing decrypted; waiting for the EA app to start the game"
        )
    finally:
        k32.TerminateProcess(process, 0)
        k32.CloseHandle(thread)
        k32.CloseHandle(process)

    deadline = time.monotonic() + TIMEOUT_SECONDS
    while True:
        found = running(exe)
        if found:
            break
        if time.monotonic() > deadline:
            raise RuntimeError(
                f"the EA app did not start the game in {TIMEOUT_SECONDS} s: is it signed in?"
            )
    process, pid = found
    print(f"the EA app started pid {pid}")
    try:
        if not freeze_when_decrypted(process, watch, TIMEOUT_SECONDS):
            raise RuntimeError("the run the EA app started exited before decrypting")
        return img, copy_out(process, img)
    finally:
        k32.TerminateProcess(process, 0)
        k32.CloseHandle(process)
        print("process ended")


def original_imports(img):
    """(rva, size) of the game's own import directory in .rdata, which the
    wrapper's header no longer points at: the descriptor naming KERNEL32.dll,
    then back and forward over its neighbours."""
    start, end, raw = img.section(".rdata")
    d = img.data
    lo, hi = start - img.image_base, end - img.image_base

    def descriptor(off):
        ilt, stamp, _, name, iat = struct.unpack_from("<IIIII", d, off)
        return lo <= ilt < hi and lo <= name < hi and lo <= iat < hi and stamp == 0

    at = d.find(b"KERNEL32.dll\0", raw, raw + hi - lo)
    name = struct.pack("<I", at - raw + lo)
    hit = d.find(name, raw, raw + hi - lo)
    while hit != -1 and not descriptor(hit - 12):
        hit = d.find(name, hit + 1, raw + hi - lo)
    if hit == -1:
        raise RuntimeError("no import descriptor names KERNEL32.dll")
    first = hit - 12
    while descriptor(first - 20):
        first -= 20
    last = first
    while descriptor(last):
        last += 20
    return first - raw + lo, last + 20 - first


def entry_point(text, text_rva):
    """The MSVC 8 CRT's entry: call __security_init_cookie, jmp
    __tmainCRTStartup, then padding and memcpy, as at 0x008E3024 in the GOG
    build."""
    tail = bytes.fromhex("cc cc 55 8b ec 57 56 8b 75 0c 8b 4d 10 8b 7d 08")
    at = text.find(tail)
    while at != -1:
        if text[at - 10] == 0xE8 and text[at - 5] == 0xE9:
            return text_rva + at - 10
        at = text.find(tail, at + 1)
    raise RuntimeError("no CRT entry point found in the decrypted .text")


def rebuild(img, memory):
    out = bytearray(img.data)
    layout = {
        name: (va, vsize, rawsize, raw)
        for name, va, vsize, rawsize, raw in sections(img)
    }
    for name in (".text", ".data"):
        _, _, rawsize, raw = layout[name]
        out[raw : raw + rawsize] = memory[name][:rawsize]

    pe = struct.unpack_from("<I", out, 0x3C)[0]
    opt = pe + 24
    entry = entry_point(memory[".text"], layout[".text"][0])
    struct.pack_into("<I", out, opt + 16, entry)

    imports = original_imports(img)
    struct.pack_into("<II", out, opt + 96 + 8 * 1, *imports)

    # The IAT is every descriptor's thunk array, which the linker lays end to
    # end at the start of .rdata.
    o = img.offset(imports[0])
    lowest, highest = None, 0
    while True:
        _, _, _, name, iat = struct.unpack_from("<IIIII", img.data, o)
        if name == 0:
            break
        p = img.offset(iat)
        n = 0
        while struct.unpack_from("<I", img.data, p + 4 * n)[0]:
            n += 1
        lowest = iat if lowest is None else min(lowest, iat)
        highest = max(highest, iat + 4 * (n + 1))
        o += 20
    struct.pack_into("<II", out, opt + 96 + 8 * 12, lowest, highest - lowest)

    # The relocation directory is the .reloc section, blocks to the first empty one.
    reloc_rva, _, _, reloc_raw = layout[".reloc"]
    p = reloc_raw
    while True:
        _, size = struct.unpack_from("<II", img.data, p)
        if size == 0:
            break
        p += size
    struct.pack_into("<II", out, opt + 96 + 8 * 5, reloc_rva, p - reloc_raw)

    # The Authenticode signature covers the file as EA shipped it.
    struct.pack_into("<II", out, opt + 96 + 8 * 4, 0, 0)

    print(
        f"entry point {img.image_base + entry:#010x}, imports at rva {imports[0]:#x} ({imports[1]:#x} bytes)"
    )
    print(
        f"IAT at rva {lowest:#x} ({highest - lowest:#x} bytes), relocations {p - reloc_raw:#x} bytes"
    )
    return bytes(out)


def main(argv):
    install = argv[0] if argv else INSTALL
    img, memory = dump(install)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    # Kept beside the result, so a rebuild that fails does not cost a launch.
    for name, pages in memory.items():
        with open(os.path.join(os.path.dirname(OUT), f"memory{name}.bin"), "wb") as f:
            f.write(pages)
    rebuilt = rebuild(img, memory)
    with open(OUT, "wb") as f:
        f.write(rebuilt)
    print(f"wrote {os.path.normpath(OUT)}, {len(rebuilt)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
