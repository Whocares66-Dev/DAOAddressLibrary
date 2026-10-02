"""Build identification must not call Steam GOG just because their stamps match."""

import contextlib
import csv
import hashlib
import io
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import daoexe


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
