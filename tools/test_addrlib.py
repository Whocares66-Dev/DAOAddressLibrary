"""tools/addrlib.py's own logic, over a table made up here: no game, and not
the real table, which `addrlib.py check` answers for."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import addrlib  # noqa: E402

BUILD_A = {
    "key": "a",
    "link_stamp": "0x4eb19d53",
    "size_of_image": "0x00100000",
    "entry_point_rva": "0x00001000",
    "image_base": "0x00400000",
}
BUILD_B = BUILD_A | {"key": "b", "link_stamp": "0x52164c37"}


def database():
    db = addrlib.Database()
    db.builds = [BUILD_A, BUILD_B]
    db.columns = ["a", "b"]
    db.rows = {
        1: addrlib.Row("function", "First", {"a": 0x401000, "b": 0x402000}),
        2: addrlib.Row("function", "", {"a": 0x401100}),
        3: addrlib.Row("data", "g_thing", {"a": 0x480000, "b": 0x470000}),
        4: addrlib.Row("function", "", {"b": 0x402000}),
    }
    db.notes = [
        (1, "b", "shared", "one address for IDs 4 too"),
        (1, "b", "changed", "2 instructions differ from a's"),
    ]
    return db


class Pack(unittest.TestCase):
    def test_a_word_per_id_at_the_ids_own_index(self):
        data = addrlib.pack_build(database(), BUILD_A)
        self.assertEqual(data[:8], b"DAOADDR\0")
        fmt, stamp, size, entry, base, count, reserved = struct.unpack_from(
            "<7I", data, 8
        )
        self.assertEqual(
            (fmt, stamp, size, entry, base, reserved),
            (1, 0x4EB19D53, 0x100000, 0x1000, 0x400000, 0),
        )
        self.assertEqual(count, 5)
        self.assertEqual(len(data), 0x24 + 4 * count)
        words = struct.unpack_from("<5I", data, 0x24)
        # ID 0 is no ID, and build a lacks ID 4.
        self.assertEqual(
            words, (addrlib.NONE, 0x1000, 0x1100, 0x01000000 | 0x80000, addrlib.NONE)
        )

    def test_notes_become_flags_in_their_own_build_only(self):
        words = struct.unpack_from("<5I", addrlib.pack_build(database(), BUILD_B), 0x24)
        changed_and_shared = (addrlib.FLAG_CHANGED | addrlib.FLAG_SHARED) << 24
        self.assertEqual(words[1], changed_and_shared | 0x2000)
        self.assertEqual(words[2], addrlib.NONE)
        self.assertEqual(words[4], 0x2000)

    def test_an_address_outside_the_image_is_refused(self):
        db = database()
        db.rows[2].addresses["a"] = 0x400000 + (1 << 24)
        with self.assertRaises(ValueError):
            addrlib.pack_build(db, BUILD_A)

    def test_a_builds_file_is_named_by_its_link_stamp(self):
        self.assertEqual(addrlib.file_name(BUILD_A), "daoaddresses-4eb19d53.bin")


class Asking(unittest.TestCase):
    def test_ids_by_address_in_one_build(self):
        self.assertEqual(database().by_address("b")[0x402000], [1, 4])
        self.assertNotIn(0x401100, database().by_address("b"))

    def test_the_id_at_or_below_an_address(self):
        db = database()
        self.assertEqual(addrlib.nearest(db, "a", 0x401000), (1, 0))
        self.assertEqual(addrlib.nearest(db, "a", 0x4010FF), (1, 0xFF))
        self.assertEqual(addrlib.nearest(db, "a", 0x401100), (2, 0))
        # Where IDs share an address, the lowest.
        self.assertEqual(addrlib.nearest(db, "b", 0x402004), (1, 4))
        self.assertIsNone(addrlib.nearest(db, "a", 0x400FFF))


class Check(unittest.TestCase):
    def faults(self, db):
        stderr, stdout = sys.stderr, sys.stdout
        sys.stderr = sys.stdout = open(os.devnull, "w")
        try:
            return addrlib.check(db)
        finally:
            sys.stdout.close()
            sys.stderr, sys.stdout = stderr, stdout

    def test_a_sound_table_passes(self):
        self.assertEqual(self.faults(database()), 0)

    def test_an_id_taken_out_is_a_fault(self):
        db = database()
        del db.rows[2]
        self.assertEqual(self.faults(db), 1)

    def test_an_id_in_no_build_must_be_retired(self):
        db = database()
        db.rows[2].addresses.clear()
        self.assertEqual(self.faults(db), 1)
        db.rows[2].kind = "retired"
        self.assertEqual(self.faults(db), 0)

    def test_an_address_outside_its_builds_image_is_a_fault(self):
        db = database()
        db.rows[3].addresses["b"] = 0x00300000
        self.assertEqual(self.faults(db), 1)

    def test_a_note_must_fit_a_cell(self):
        db = database()
        db.notes.append((2, "b", "changed", "ID 2 is not in b"))
        self.assertEqual(self.faults(db), 1)
        db = database()
        db.notes.append((1, "b", "renamed", "no such flag"))
        self.assertEqual(self.faults(db), 1)

    def test_a_column_needs_a_build(self):
        db = database()
        db.columns.append("c")
        self.assertEqual(self.faults(db), 1)


class Naming(unittest.TestCase):
    def test_an_id_is_itself(self):
        self.assertEqual(addrlib.resolve(database(), "2"), 2)
        with self.assertRaises(ValueError):
            addrlib.resolve(database(), "9")
        with self.assertRaises(ValueError):
            addrlib.resolve(database(), "SetPaused")

    def test_an_address_is_the_one_id_there(self):
        db = database()
        self.assertEqual(addrlib.resolve(db, "0x00401100"), 2)
        self.assertEqual(addrlib.resolve(db, "0x00480000", "a"), 3)
        # Build b's address of ID 3 is not an address of build a's.
        with self.assertRaises(ValueError):
            addrlib.resolve(db, "0x00470000", "a")

    def test_an_address_two_ids_share_names_neither(self):
        # 0x402000 is ID 1's and ID 4's in build b: the linker made one
        # function of two.
        with self.assertRaises(ValueError):
            addrlib.resolve(database(), "0x00402000", "b")

    def test_a_name_is_given_and_changed(self):
        db = database()
        self.assertEqual(addrlib.set_name(db, 2, "Second"), "")
        self.assertEqual(addrlib.set_name(db, 2, "Second::Again"), "Second")
        self.assertEqual(db.rows[2].name, "Second::Again")

    def test_what_is_not_a_name_is_refused(self):
        db = database()
        for bad in ("", " Second", "Second\t", "one\ntwo"):
            with self.assertRaises(ValueError):
                addrlib.set_name(db, 2, bad)
        self.assertEqual(db.rows[2].name, "")

    def test_a_retired_id_is_not_named(self):
        db = database()
        db.rows[2].kind = "retired"
        with self.assertRaises(ValueError):
            addrlib.set_name(db, 2, "Second")

    def test_many_at_once_says_what_became_of_each(self):
        db = database()
        new, renamed, faults = addrlib.name_many(
            db,
            [
                ("2", "Second"),  # had none
                ("0x00480000", "g_other"),  # had g_thing
                ("1", "First"),  # the name it has
                ("0x00402000", "Shared"),  # two IDs' address
                ("7", "Seventh"),  # no such ID
            ],
            "a",
        )
        self.assertEqual((new, renamed, len(faults)), (1, 1, 2))
        self.assertEqual(db.rows[3].name, "g_other")
        self.assertEqual(db.rows[1].name, "First")


class Kept(unittest.TestCase):
    def test_a_table_is_as_it_was(self):
        self.assertEqual(addrlib.changes(database(), database()), [])

    def test_what_a_table_is_for_changes_nothing(self):
        # A new ID, a new build with its column, an empty cell filled, a
        # name given and a name changed.
        after = database()
        after.builds = [
            *after.builds,
            BUILD_A | {"key": "c", "link_stamp": "0x60000000"},
        ]
        after.columns.append("c")
        after.rows[5] = addrlib.Row("function", "", {"c": 0x403000})
        after.rows[2].addresses["b"] = 0x402100
        after.rows[2].name = "Second"
        after.rows[1].name = "First::Renamed"
        self.assertEqual(addrlib.changes(database(), after), [])

    def test_an_id_gone_is_a_change(self):
        after = database()
        del after.rows[4]
        self.assertEqual(len(addrlib.changes(database(), after)), 1)

    def test_an_address_moved_or_taken_out_is_a_change(self):
        after = database()
        after.rows[1].addresses["b"] = 0x402004
        del after.rows[3].addresses["a"]
        self.assertEqual(len(addrlib.changes(database(), after)), 2)

    def test_a_function_does_not_become_data(self):
        after = database()
        after.rows[2].kind = "data"
        self.assertEqual(len(addrlib.changes(database(), after)), 1)

    def test_an_id_may_be_retired(self):
        after = database()
        after.rows[2].kind = "retired"
        after.rows[2].addresses.clear()
        self.assertEqual(addrlib.changes(database(), after), [])

    def test_a_build_is_its_link_stamp_not_its_key(self):
        after = database()
        after.builds = [BUILD_A | {"key": "a-1.05"}, BUILD_B]
        after.columns = ["a-1.05", "b"]
        for row in after.rows.values():
            if "a" in row.addresses:
                row.addresses["a-1.05"] = row.addresses.pop("a")
        self.assertEqual(addrlib.changes(database(), after), [])
        # The same rename with an address moved under it is still a change.
        after.rows[1].addresses["a-1.05"] = 0x401004
        self.assertEqual(len(addrlib.changes(database(), after)), 1)


if __name__ == "__main__":
    unittest.main()
