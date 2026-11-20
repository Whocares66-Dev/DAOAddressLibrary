"""Tests for stlmatch.py's names: they need neither the build nor the compiler."""

import unittest

import stlmatch


class Names(unittest.TestCase):
    def test_vector_member(self):
        self.assertEqual(
            stlmatch.norm_name(
                "std::vector<struct P_8,class std::allocator<struct P_8> >::_Insert_n"
            ),
            "std::vector<?>::_Insert_n",
        )

    def test_wstring_element(self):
        self.assertEqual(
            stlmatch.norm_name(
                "std::vector<class std::basic_string<wchar_t,struct std::char_traits<wchar_t>,"
                "class std::allocator<wchar_t> >,class std::allocator<class std::basic_string<wchar_t,"
                "struct std::char_traits<wchar_t>,class std::allocator<wchar_t> > > >::erase"
            ),
            "std::vector<std::wstring>::erase",
        )

    def test_tree_is_written_as_its_map(self):
        self.assertEqual(
            stlmatch.norm_name(
                "std::_Tree<class std::_Tmap_traits<unsigned int,struct D_8,struct std::less<unsigned int>,"
                "class std::allocator<struct std::pair<unsigned int const ,struct D_8> >,0> >::_Lbound"
            ),
            "std::map<?,?>::_Lbound",
        )

    def test_hash_is_written_as_its_hash_map(self):
        self.assertEqual(
            stlmatch.norm_name(
                "stdext::_Hash<class stdext::_Hmap_traits<unsigned int,int,class stdext::hash_compare<unsigned int,"
                "struct std::less<unsigned int> >,class std::allocator<struct std::pair<unsigned int const ,int> >,0> >::insert"
            ),
            "stdext::hash_map<?,?>::insert",
        )

    def test_destructor_takes_the_owner_leaf(self):
        self.assertEqual(
            stlmatch.norm_name(
                "std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> >"
                "::~basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> >"
            ),
            "std::wstring::~wstring",
        )

    def test_member_template_written_alone(self):
        self.assertEqual(
            stlmatch.norm_name(
                "std::list<int,class std::allocator<int> >::_Insert<int const *>"
            ),
            "std::list<?>::_Insert",
        )

    def test_element(self):
        self.assertEqual(
            stlmatch.element_of("std::vector<struct C_12,x>::erase"),
            (12, stlmatch.KIND["C"]),
        )
        self.assertEqual(
            stlmatch.element_of("std::vector<double,x>::erase"), (8, "scalar double")
        )


class Merge(unittest.TestCase):
    def test_keeps_what_agrees(self):
        self.assertEqual(
            stlmatch.merge(
                [
                    "std::map<std::wstring,?>::insert",
                    "std::map<std::wstring,std::wstring>::insert",
                ]
            ),
            "std::map<std::wstring,?>::insert",
        )

    def test_two_members_are_nothing(self):
        self.assertIsNone(
            stlmatch.merge(["std::vector<?>::_Tidy", "std::vector<?>::~vector"])
        )

    def test_two_templates_are_nothing(self):
        self.assertIsNone(
            stlmatch.merge(["std::list<?>::clear", "std::vector<?>::clear"])
        )


class Generated(unittest.TestCase):
    def test_every_kind_and_container(self):
        lines = [x for v in stlmatch.instantiations().values() for x in v]
        self.assertIn("template class std::vector<D_128 >;", lines)
        self.assertIn("template class std::map<std::wstring,A_64 >;", lines)
        self.assertIn("template class std::basic_string<wchar_t>;", lines)


if __name__ == "__main__":
    unittest.main()
