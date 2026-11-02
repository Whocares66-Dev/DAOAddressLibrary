"""The layouts file: sound as it stands, and what a fault looks like."""

import unittest

import structs


def row(
    struct="A", offset="0x0", size="0x4", type_="int", field="x", evidence="0x00400000"
):
    return dict(
        zip(
            structs.COLUMNS, (struct, offset, size, type_, field, evidence), strict=True
        )
    )


class Faults(unittest.TestCase):
    def test_the_file_is_sound(self):
        self.assertEqual(structs.faults(structs.read()), [])

    def test_fields_side_by_side_are_fine(self):
        self.assertEqual(structs.faults([row(), row(offset="0x4", field="y")]), [])

    def test_overlapping_fields_are_a_fault(self):
        self.assertTrue(structs.faults([row(size="0x8"), row(offset="0x4", field="y")]))

    def test_two_structs_may_use_one_offset(self):
        self.assertEqual(structs.faults([row(), row(struct="B")]), [])

    def test_a_field_past_sizeof_is_a_fault(self):
        whole = row(size="0x4", type_="size", field=structs.SIZEOF)
        self.assertTrue(structs.faults([whole, row(offset="0x4", field="y")]))

    def test_evidence_is_an_address(self):
        self.assertTrue(structs.faults([row(evidence="read it")]))

    def test_offsets_are_hex(self):
        self.assertTrue(structs.faults([row(offset="sixteen")]))


if __name__ == "__main__":
    unittest.main()
