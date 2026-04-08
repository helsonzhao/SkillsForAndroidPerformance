#!/usr/bin/env python3
"""
HPROF Heap Dump Analyzer
Parses standard J2SE HPROF binary format and produces class histogram reports.
For Android dumps, run hprof-conv first.

Usage: python3 analyze_hprof.py <path-to-standard-hprof>
"""
import struct, sys, collections

PRIM_SIZES = {4: 1, 5: 2, 6: 4, 7: 8, 8: 1, 9: 2, 10: 4, 11: 8}
PRIM_NAMES = {4: "boolean[]", 5: "char[]", 6: "float[]", 7: "double[]",
              8: "byte[]", 9: "short[]", 10: "int[]", 11: "long[]"}
ROOT_SKIPS = {0xFF: lambda s: s, 0x01: lambda s: 2*s, 0x02: lambda s: s+8,
              0x03: lambda s: s+8, 0x04: lambda s: s+4, 0x05: lambda s: s,
              0x06: lambda s: s+4, 0x07: lambda s: s, 0x08: lambda s: s+8}


def analyze(path):
    f = open(path, "rb")
    # Header
    hdr = b""
    while True:
        b = f.read(1)
        if b == b"\x00":
            break
        hdr += b
    id_size = struct.unpack(">I", f.read(4))[0]
    f.read(8)
    id_fmt = ">Q" if id_size == 8 else ">I"

    strings = {}
    class_names = {}
    inst_count = collections.Counter()
    inst_bytes = collections.Counter()
    arr_count = collections.Counter()
    arr_bytes = collections.Counter()

    def read_id():
        return struct.unpack(id_fmt, f.read(id_size))[0]

    while True:
        tag_b = f.read(1)
        if not tag_b:
            break
        tag = tag_b[0]
        f.read(4)
        length = struct.unpack(">I", f.read(4))[0]

        if tag == 0x01:  # UTF8
            sid = read_id()
            strings[sid] = f.read(length - id_size).decode("utf-8", errors="replace")
        elif tag == 0x02:  # LOAD_CLASS
            f.read(4)
            cid = read_id()
            f.read(4)
            nid = read_id()
            class_names[cid] = nid
        elif tag in (0x0C, 0x1C):  # HEAP_DUMP / HEAP_DUMP_SEGMENT
            end = f.tell() + length
            while f.tell() < end:
                stag = f.read(1)[0]
                if stag == 0x21:  # INSTANCE_DUMP
                    read_id()
                    f.read(4)
                    cid = read_id()
                    sz = struct.unpack(">I", f.read(4))[0]
                    f.read(sz)
                    inst_count[cid] += 1
                    inst_bytes[cid] += sz + id_size * 2 + 8
                elif stag == 0x22:  # OBJ_ARRAY_DUMP
                    read_id()
                    f.read(4)
                    num = struct.unpack(">I", f.read(4))[0]
                    cid = read_id()
                    f.read(num * id_size)
                    arr_count[cid] += 1
                    arr_bytes[cid] += num * id_size
                elif stag == 0x23:  # PRIM_ARRAY_DUMP
                    read_id()
                    f.read(4)
                    num = struct.unpack(">I", f.read(4))[0]
                    etype = f.read(1)[0]
                    esz = PRIM_SIZES.get(etype, 0)
                    f.read(num * esz)
                    name = PRIM_NAMES.get(etype, f"prim[{etype}][]")
                    arr_count[name] += 1
                    arr_bytes[name] += num * esz
                elif stag == 0x20:  # CLASS_DUMP
                    read_id()
                    f.read(4)
                    for _ in range(6):
                        read_id()
                    f.read(4)
                    cp = struct.unpack(">H", f.read(2))[0]
                    for _ in range(cp):
                        f.read(2)
                        t = f.read(1)[0]
                        f.read(id_size if t == 2 else PRIM_SIZES.get(t, 0))
                    st = struct.unpack(">H", f.read(2))[0]
                    for _ in range(st):
                        read_id()
                        t = f.read(1)[0]
                        f.read(id_size if t == 2 else PRIM_SIZES.get(t, 0))
                    fi = struct.unpack(">H", f.read(2))[0]
                    for _ in range(fi):
                        read_id()
                        f.read(1)
                elif stag in ROOT_SKIPS:
                    f.read(ROOT_SKIPS[stag](id_size))
                else:
                    f.seek(end)
                    break
        else:
            f.read(length)

    f.close()

    def cname(cid):
        nid = class_names.get(cid)
        return strings.get(nid, f"unknown-{cid:#x}") if nid else f"unknown-{cid:#x}"

    total_inst = sum(inst_bytes.values())
    total_arr = sum(arr_bytes.values())
    grand = total_inst + total_arr

    print(f"\n{'=' * 90}")
    print(f"  INSTANCE HISTOGRAM (Top 50 by shallow size)")
    print(f"{'=' * 90}")
    print(f"{'Rank':>4}  {'Count':>12}  {'ShallowBytes':>14}  {'MB':>8}  {'%':>6}  Class")
    print(f"{'-' * 4}  {'-' * 12}  {'-' * 14}  {'-' * 8}  {'-' * 6}  {'-' * 45}")
    for i, (cid, total) in enumerate(inst_bytes.most_common(50), 1):
        pct = total / grand * 100 if grand else 0
        print(f"{i:>4}  {inst_count[cid]:>12,}  {total:>14,}  {total / 1024 / 1024:>8.2f}  {pct:>5.1f}%  {cname(cid)}")

    print(f"\n{'=' * 90}")
    print(f"  ARRAY HISTOGRAM (Top 30 by shallow size)")
    print(f"{'=' * 90}")
    print(f"{'Rank':>4}  {'Count':>12}  {'ShallowBytes':>14}  {'MB':>8}  {'%':>6}  Type")
    print(f"{'-' * 4}  {'-' * 12}  {'-' * 14}  {'-' * 8}  {'-' * 6}  {'-' * 45}")
    for i, (key, total) in enumerate(arr_bytes.most_common(30), 1):
        name = key if isinstance(key, str) else cname(key)
        pct = total / grand * 100 if grand else 0
        print(f"{i:>4}  {arr_count[key]:>12,}  {total:>14,}  {total / 1024 / 1024:>8.2f}  {pct:>5.1f}%  {name}")

    print(f"\n{'=' * 90}")
    print(f"  SUMMARY")
    print(f"{'=' * 90}")
    print(f"  Total instance shallow size : {total_inst:>14,} bytes  ({total_inst / 1024 / 1024:.1f} MB)")
    print(f"  Total array shallow size    : {total_arr:>14,} bytes  ({total_arr / 1024 / 1024:.1f} MB)")
    print(f"  Grand total                 : {grand:>14,} bytes  ({grand / 1024 / 1024:.1f} MB)")
    print(f"  Total instance count        : {sum(inst_count.values()):>14,}")
    print(f"  Total array count           : {sum(arr_count.values()):>14,}")
    print(f"  Unique classes (instances)  : {len(inst_count):>14,}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_hprof.py <path-to-standard-hprof>")
        sys.exit(1)
    analyze(sys.argv[1])
