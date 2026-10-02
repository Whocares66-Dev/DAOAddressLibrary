"""Build identification must not call Steam GOG just because their stamps
match; and a vftable is as long as its relocated slots, over a PE made here."""

import contextlib
import csv
import hashlib
import io
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import daoexe

BASE = 0x400000


def pe_with_one_vftable(relocations=True):
    """A file's bytes, sections at their own RVAs: .text at 0x1000, .rdata at
    0x2000 with type_info's and Thing's type descriptors, Thing's locator
    and its vftable at 0x402100, two slots and then a word into .text that is
    not an address (as a UTF-16 string's two characters are); .reloc at
    0x3000 covering the locator's word and the two slots."""
    data = bytearray(0x4000)
    data[0:2] = b"MZ"
    pe = 0x80
    struct.pack_into("<I", data, 0x3C, pe)
    data[pe : pe + 4] = b"PE\0\0"
    struct.pack_into("<HHI", data, pe + 4, 0x14C, 3, 0x4EB19D53)
    struct.pack_into("<H", data, pe + 20, 0xE0)
    opt = pe + 24
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 28, BASE)
    struct.pack_into("<I", data, opt + 56, 0x4000)
    reloc = [0x0FC, 0x100, 0x104]
    block = struct.pack("<II", 0x2000, 8 + 2 * 4) + struct.pack(
        "<4H", *[0x3000 | r for r in reloc], 0
    )
    if relocations:
        struct.pack_into("<II", data, opt + 96 + 8 * 5, 0x3000, len(block))
        data[0x3000 : 0x3000 + len(block)] = block
    for i, name in enumerate((b".text", b".rdata", b".reloc")):
        va = 0x1000 * (i + 1)
        struct.pack_into(
            "<8sIIII", data, opt + 0xE0 + 40 * i, name, 0x1000, va, 0x1000, va
        )
    type_info_vftable = BASE + 0x2F00
    struct.pack_into("<II", data, 0x2000, type_info_vftable, 0)
    data[0x2008:0x2018] = b".?AVtype_info@@\0"
    struct.pack_into("<II", data, 0x2040, type_info_vftable, 0)
    data[0x2048:0x2054] = b".?AVThing@@\0"
    struct.pack_into("<5I", data, 0x20A0, 0, 0, 0, BASE + 0x2040, BASE + 0x2080)
    struct.pack_into(
        "<4I", data, 0x20FC, BASE + 0x20A0, BASE + 0x1010, BASE + 0x1020, 0x00401025
    )
    return bytes(data)


class Vftables(unittest.TestCase):
    def image(self, data):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "a.exe")
            with open(path, "wb") as f:
                f.write(data)
            return daoexe.Image(path)

    def test_a_vftable_ends_at_its_last_relocated_slot(self):
        img = self.image(pe_with_one_vftable())
        self.assertEqual(img.relocated, {BASE + 0x20FC, BASE + 0x2100, BASE + 0x2104})
        self.assertEqual(
            img.vtables,
            [(BASE + 0x2100, ".?AVThing@@", 0, [BASE + 0x1010, BASE + 0x1020])],
        )

    def test_without_a_relocation_table_every_word_into_text_counts(self):
        img = self.image(pe_with_one_vftable(relocations=False))
        self.assertIsNone(img.relocated)
        self.assertEqual(len(img.vtables[0][3]), 3)


class Identification(unittest.TestCase):
    def setUp(self):
        self.img = SimpleNamespace(
            data=b"installed",
            time_date_stamp=0x4EB19D53,
            size_of_image=0xA49000,
            entry_point_rva=0x9ED2EE,
            image_base=0x400000,
        )
        self.steam = {
            "key": "steam-1.05",
            "name": "Steam",
            "link_stamp": "0x4eb19d53",
            "size_of_image": "0xa49000",
            "entry_point_rva": "0x9ed2ee",
            "image_base": "0x400000",
            "sha256": hashlib.sha256(b"installed").hexdigest(),
            "image_sha256": hashlib.sha256(b"unpacked").hexdigest(),
        }
        self.gog = self.steam | {
            "key": "gog-1.05",
            "name": "GOG",
            "size_of_image": "0x9ec0a2",
            "entry_point_rva": "0x4e3024",
            "sha256": "other",
            "image_sha256": "other",
        }

    def check(self, builds):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "builds.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, self.steam)
                writer.writeheader()
                writer.writerows(builds)
            out = io.StringIO()
            with patch.object(daoexe, "BUILDS", path), contextlib.redirect_stdout(out):
                result = daoexe.check(self.img)
            return result, out.getvalue()

    def test_timestamp_alone_never_identifies_a_build(self):
        self.assertEqual(self.check([self.gog])[0], 1)

    def test_installed_file_matches_the_correct_build(self):
        result, message = self.check([self.gog, self.steam])
        self.assertEqual(result, 0)
        self.assertIn("steam-1.05 build, as installed", message)

    def test_unpacked_image_is_identified_by_recorded_hash(self):
        self.img.data = b"unpacked"
        self.img.entry_point_rva = 0x4E3024
        self.img.size_of_image = 0x9ED000
        result, message = self.check([self.gog, self.steam])
        self.assertEqual(result, 0)
        self.assertIn("steam-1.05 analysis image", message)

    def test_modified_file_requires_all_header_fields(self):
        self.img.data = b"modified"
        result, message = self.check([self.gog, self.steam])
        self.assertEqual(result, 0)
        self.assertIn("unverified file hash", message)
        self.img.image_base += 0x1000
        self.assertEqual(self.check([self.gog, self.steam])[0], 1)


if __name__ == "__main__":
    unittest.main()
