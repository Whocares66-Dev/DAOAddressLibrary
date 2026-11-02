"""The shapes of the engine's classes: data/structs.csv, a field per row.

    python tools/structs.py --check          the file is sound
    python tools/structs.py --add FILE.tsv   merge a batch's rows: struct, offset,
                                             size, type, field, evidence

The table says what a thing is called; this says what is in it, which is what
another implementation of the engine needs. Ghidra's own recovered structs are
often off by 8 or 0x20 bytes (the user, 2026-11-02: keep the layouts here).
tools/ghidra_sync.py writes them into the database.

A row is a field read in the code, its `evidence` the address of an instruction
that reads or writes it; a row whose field is `sizeof` gives the class's whole
size, its evidence where it is allocated. Offsets are from the start of the
class named, a base's fields under the base's own name.
"""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "data" / "structs.csv"
COLUMNS = ["struct", "offset", "size", "type", "field", "evidence"]
SIZEOF = "sizeof"


def read(path=FILE):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def faults(rows):
    """What is wrong with these rows, a line each."""
    out, fields, whole = [], {}, {}
    for number, row in enumerate(rows, 2):
        where = f"line {number} ({row['struct']} {row['field']})"
        if not all(row[column].strip() for column in COLUMNS):
            out.append(f"{where}: an empty cell")
            continue
        try:
            offset, size = int(row["offset"], 16), int(row["size"], 16)
        except ValueError:
            out.append(f"{where}: offset and size are hex")
            continue
        if size <= 0:
            out.append(f"{where}: a size of {size}")
        if not row["evidence"].lower().startswith("0x"):
            out.append(f"{where}: evidence is an instruction's address")
        if row["field"] == SIZEOF:
            if offset != 0:
                out.append(f"{where}: sizeof is at offset 0")
            whole[row["struct"]] = size
        else:
            fields.setdefault(row["struct"], []).append((offset, size, row["field"]))
    for struct, held in fields.items():
        held.sort()
        for (a, size, name), (b, _, other) in zip(held, held[1:], strict=False):
            if a + size > b:
                out.append(f"{struct}: {name} at {a:#x} overlaps {other} at {b:#x}")
        if struct in whole:
            a, size, name = held[-1]
            if a + size > whole[struct]:
                out.append(
                    f"{struct}: {name} at {a:#x} runs past sizeof {whole[struct]:#x}"
                )
    return out


def add(path):
    """Merges a batch's rows, a later row replacing one at the same place."""
    rows = {(r["struct"], int(r["offset"], 16), r["field"]): r for r in read()}
    with open(path, encoding="utf-8") as f:
        for line in f:
            cells = line.rstrip("\n").split("\t")
            if len(cells) < 6 or not cells[1].lower().startswith("0x"):
                continue
            row = dict(zip(COLUMNS, (cell.strip() for cell in cells[:6]), strict=True))
            rows[(row["struct"], int(row["offset"], 16), row["field"])] = row
    merged = [rows[key] for key in sorted(rows, key=lambda k: (k[0], k[1], k[2]))]
    wrong = faults(merged)
    if wrong:
        print("\n".join(wrong))
        return 1
    with open(FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(merged)
    print(f"{len(merged)} fields of {len({r['struct'] for r in merged})} structs")
    return 0


def main(argv):
    if len(argv) == 2 and argv[0] == "--add":
        return add(argv[1])
    if argv != ["--check"]:
        print(__doc__)
        return 2
    rows = read()
    wrong = faults(rows)
    print("\n".join(wrong) if wrong else f"{len(rows)} rows: 0 faults")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
