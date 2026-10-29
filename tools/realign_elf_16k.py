#!/usr/bin/env python3
"""Repack an AAR so every native library's LOAD segments are 16KB-aligned.

Android 15+ devices with 16KB pages refuse to load a .so whose program headers
are only congruent modulo 4KB. Virtual addresses stay the same; only file
offsets move, with padding inserted before each LOAD that needs it.
"""
import io
import struct
import sys
import zipfile

ALIGN = 16384
PT_LOAD = 1


def _u(fmt, data, off):
    return struct.unpack_from("<" + fmt, data, off)


def _p(buf, off, fmt, *values):
    struct.pack_into("<" + fmt, buf, off, *values)


def realign_elf(data: bytes) -> bytes:
    if data[:4] != b"\x7fELF":
        raise SystemExit("not an ELF")
    elf_class = data[4]
    if elf_class not in (1, 2):
        raise SystemExit("unsupported ELF class")
    if data[5] != 1:
        raise SystemExit("only little-endian ELF is supported")
    loads, phdrs = _loads(data, elf_class)
    pieces, total = _plan(data, loads)
    out = bytearray(total)
    for old_start, old_end, new_start in pieces:
        out[new_start:new_start + (old_end - old_start)] = data[old_start:old_end]
    _patch_headers(data, out, elf_class, pieces, phdrs)
    _verify(bytes(out), elf_class)
    return bytes(out)


def _loads(data, elf_class):
    if elf_class == 2:
        e_phoff = _u("Q", data, 32)[0]
        e_phentsize = _u("H", data, 54)[0]
        e_phnum = _u("H", data, 56)[0]
        loads = []
        phdrs = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = _u("I", data, off)[0]
            p_offset, p_vaddr, _, p_filesz, p_memsz, p_align = _u("QQQQQQ", data, off + 8)
            phdrs.append((off, p_type, p_offset, p_vaddr, p_filesz))
            if p_type == PT_LOAD and p_filesz:
                loads.append((p_offset, p_offset + p_filesz, p_vaddr))
        return loads, phdrs
    e_phoff = _u("I", data, 28)[0]
    e_phentsize = _u("H", data, 42)[0]
    e_phnum = _u("H", data, 44)[0]
    loads = []
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _, p_filesz, _, _, _ = _u("IIIIIIII", data, off)
        phdrs.append((off, p_type, p_offset, p_vaddr, p_filesz))
        if p_type == PT_LOAD and p_filesz:
            loads.append((p_offset, p_offset + p_filesz, p_vaddr))
    return loads, phdrs


def _plan(data, loads):
    loads = sorted(loads)
    pieces = []
    cursor_old = 0
    cursor_new = 0
    for start, end, vaddr in loads:
        if start < cursor_old:
            raise SystemExit("overlapping LOAD segments")
        if start > cursor_old:
            pieces.append((cursor_old, start, cursor_new))
            cursor_new += start - cursor_old
        need = vaddr % ALIGN
        if cursor_new % ALIGN != need:
            cursor_new += (need - cursor_new % ALIGN) % ALIGN
        pieces.append((start, end, cursor_new))
        cursor_new += end - start
        cursor_old = end
    if cursor_old < len(data):
        pieces.append((cursor_old, len(data), cursor_new))
        cursor_new += len(data) - cursor_old
    return pieces, cursor_new


def _map(pieces, old):
    if old == 0:
        return 0
    for start, end, new_start in pieces:
        if start <= old < end:
            return new_start + (old - start)
        if old == end:
            # Exclusive end maps to the end of this piece when nothing follows inside it.
            continue
    for start, end, new_start in pieces:
        if old == end:
            return new_start + (end - start)
    raise SystemExit(f"file offset {old:#x} is not in the rebuilt layout")


def _patch_headers(original, out, elf_class, pieces, phdrs):
    if elf_class == 2:
        e_shoff = _u("Q", original, 40)[0]
        e_phoff = _u("Q", original, 32)[0]
        e_phentsize = _u("H", original, 54)[0]
        e_phnum = _u("H", original, 56)[0]
        e_shentsize = _u("H", original, 58)[0]
        e_shnum = _u("H", original, 60)[0]
        if e_shoff:
            _p(out, 40, "Q", _map(pieces, e_shoff))
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = _u("I", original, off)[0]
            p_offset = _u("Q", original, off + 8)[0]
            p_filesz = _u("Q", original, off + 32)[0]
            if p_filesz == 0 and p_offset == 0:
                new_off = 0
            else:
                new_off = _map(pieces, p_offset)
            _p(out, off + 8, "Q", new_off)
            if p_type == PT_LOAD:
                _p(out, off + 48, "Q", ALIGN)
        if e_shoff and e_shnum:
            new_shoff = _map(pieces, e_shoff)
            for i in range(e_shnum):
                sh = new_shoff + i * e_shentsize
                sh_offset = _u("Q", original, _map_old_sh(original, e_shoff, e_shentsize, i))[0]
                # sh_offset is at +24 in the section header; read from original
                sh_offset = _u("Q", original, e_shoff + i * e_shentsize + 24)[0]
                if sh_offset:
                    _p(out, sh + 24, "Q", _map(pieces, sh_offset))
        return
    e_shoff = _u("I", original, 32)[0]
    e_phoff = _u("I", original, 28)[0]
    e_phentsize = _u("H", original, 42)[0]
    e_phnum = _u("H", original, 44)[0]
    e_shentsize = _u("H", original, 46)[0]
    e_shnum = _u("H", original, 48)[0]
    if e_shoff:
        _p(out, 32, "I", _map(pieces, e_shoff))
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, _, _, p_filesz, _, _, _ = _u("IIIIIIII", original, off)
        new_off = 0 if p_filesz == 0 and p_offset == 0 else _map(pieces, p_offset)
        _p(out, off + 4, "I", new_off)
        if p_type == PT_LOAD:
            _p(out, off + 28, "I", ALIGN)
    if e_shoff and e_shnum:
        new_shoff = _map(pieces, e_shoff)
        for i in range(e_shnum):
            sh_offset = _u("I", original, e_shoff + i * e_shentsize + 16)[0]
            if sh_offset:
                _p(out, new_shoff + i * e_shentsize + 16, "I", _map(pieces, sh_offset))


def _map_old_sh(original, e_shoff, e_shentsize, i):
    return e_shoff + i * e_shentsize + 24


def _verify(data, elf_class):
    loads, _ = _loads(data, elf_class)
    for start, end, vaddr in loads:
        if start % ALIGN != vaddr % ALIGN:
            raise SystemExit(f"LOAD still misaligned off={start:#x} vaddr={vaddr:#x}")
        align = _align_of(data, elf_class, start)
        if align < ALIGN:
            raise SystemExit(f"p_align {align} is below 16KB")


def _align_of(data, elf_class, p_offset):
    if elf_class == 2:
        e_phoff = _u("Q", data, 32)[0]
        e_phentsize = _u("H", data, 54)[0]
        e_phnum = _u("H", data, 56)[0]
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if _u("I", data, off)[0] == PT_LOAD and _u("Q", data, off + 8)[0] == p_offset:
                return _u("Q", data, off + 48)[0]
    else:
        e_phoff = _u("I", data, 28)[0]
        e_phentsize = _u("H", data, 42)[0]
        e_phnum = _u("H", data, 44)[0]
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if _u("I", data, off)[0] == PT_LOAD and _u("I", data, off + 4)[0] == p_offset:
                return _u("I", data, off + 28)[0]
    raise SystemExit("updated LOAD not found")


def realign_aar(src: str, dest: str) -> None:
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            payload = zin.read(info.filename)
            if info.filename.endswith(".so"):
                payload = realign_elf(payload)
            out_info = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
            out_info.compress_type = info.compress_type
            out_info.external_attr = info.external_attr
            zout.writestr(out_info, payload)


def _self_test() -> None:
    # Two LOAD segments, 4KB aligned, second not congruent mod 16KB.
    elf = bytearray(8192)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2
    elf[5] = 1
    elf[6] = 1
    _p(elf, 16, "H", 3)  # e_type ET_DYN
    _p(elf, 18, "H", 0x3E)
    _p(elf, 20, "I", 1)
    _p(elf, 32, "Q", 64)  # e_phoff
    _p(elf, 40, "Q", 4096)  # e_shoff inside second segment's original place, will move
    _p(elf, 52, "H", 64)
    _p(elf, 54, "H", 56)
    _p(elf, 56, "H", 2)
    _p(elf, 58, "H", 64)
    _p(elf, 60, "H", 1)
    # LOAD 0: offset 0 size 4096 vaddr 0
    _p(elf, 64, "I", PT_LOAD)
    _p(elf, 68, "I", 5)
    _p(elf, 72, "Q", 0)
    _p(elf, 80, "Q", 0)
    _p(elf, 88, "Q", 0)
    _p(elf, 96, "Q", 4096)
    _p(elf, 104, "Q", 4096)
    _p(elf, 112, "Q", 4096)
    # LOAD 1: offset 4096 size 4096 vaddr 8192 (congruent mod 4096, not 16384)
    _p(elf, 120, "I", PT_LOAD)
    _p(elf, 124, "I", 6)
    _p(elf, 128, "Q", 4096)
    _p(elf, 136, "Q", 8192)
    _p(elf, 144, "Q", 8192)
    _p(elf, 152, "Q", 4096)
    _p(elf, 160, "Q", 4096)
    _p(elf, 168, "Q", 4096)
    # one section header at offset 4096
    _p(elf, 4096 + 24, "Q", 100)  # sh_offset
    rebuilt = realign_elf(bytes(elf))
    loads, _ = _loads(rebuilt, 2)
    assert loads[1][0] % ALIGN == 8192 % ALIGN
    print("self-test ok", len(rebuilt))


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        _self_test()
        return
    if len(sys.argv) != 3:
        raise SystemExit("usage: realign_elf_16k.py input.aar output.aar | --self-test")
    realign_aar(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
