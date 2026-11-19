"""Tests for tools/interfaces.py: how a header's text becomes slots, and that
data/interfaces.csv is sound.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import interfaces  # noqa: E402

COM = """
DECLARE_INTERFACE_(IThing, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObj) PURE;
    STDMETHOD_(ULONG,AddRef)(THIS) PURE;
    STDMETHOD_(ULONG,Release)(THIS) PURE;
    STDMETHOD(Draw)(THIS_ UINT count) PURE;
    STDMETHOD_(void, SetCursorPosition)(THIS_ int X,int Y,DWORD Flags) PURE;
};
"""

CPP = """
class NxBase
    {
    protected:
    virtual ~NxBase() {}   // not public
    public:
    virtual void setName(const char* name) = 0;
    /* virtual void gone() = 0; */
    virtual const char* getName() const = 0;
    virtual void* is(int type) = 0;
    virtual const void* is(int type) const = 0;
    void* userData;
    };

class NxDerived : public NxBase
    {
    public:
    virtual void setName(const char* name) = 0;
    virtual float getRadius() const = 0;
    class Inner { virtual void notMine() = 0; };
    };
"""


class Headers(unittest.TestCase):
    def test_a_com_interface_is_its_stdmethods_in_order(self):
        self.assertEqual(
            interfaces.com_interfaces(COM),
            {
                "IThing": [
                    "QueryInterface",
                    "AddRef",
                    "Release",
                    "Draw",
                    "SetCursorPosition",
                ]
            },
        )

    def test_a_class_is_its_virtual_functions_in_the_order_declared(self):
        found = interfaces.cpp_classes(CPP)
        self.assertEqual(
            found["NxBase"], (None, ["~NxBase", "setName", "getName", "is", "is"])
        )
        self.assertEqual(found["NxDerived"], ("NxBase", ["setName", "getRadius"]))

    def test_a_base_comes_first_and_an_override_takes_its_slot(self):
        flat = interfaces.flatten(interfaces.cpp_classes(CPP))
        self.assertEqual(flat["NxBase"], ["~", "setName", "getName", "is", "is_2"])
        self.assertEqual(
            flat["NxDerived"], ["~", "setName", "getName", "is", "is_2", "getRadius"]
        )


class TheFile(unittest.TestCase):
    def test_it_is_sound(self):
        self.assertEqual(interfaces.faults(interfaces.read()), [])

    def test_slots_checked_against_the_build(self):
        tables = interfaces.tables()
        # Physics::PhysicsParticleActor::GetRandomPointInShape (0x0081A030)
        # calls slot 0x6C of its shape with a shape type.
        self.assertEqual(tables["NxShape"][0x6C // 4], "is_2")
        self.assertEqual(
            tables["IDirect3DDevice9"][:3], ["QueryInterface", "AddRef", "Release"]
        )
        self.assertEqual(tables["IDirect3DDevice9"][65], "SetTexture")
        # A derived shape's own methods follow NxShape's 39.
        self.assertEqual(tables["NxSphereShape"][:39], tables["NxShape"])

    def test_a_fault_is_found(self):
        rows = [
            {"interface": "I", "slot": "0", "method": "a", "from": "x"},
            {"interface": "I", "slot": "2", "method": "a", "from": "x"},
        ]
        self.assertEqual(len(interfaces.faults(rows)), 2)


if __name__ == "__main__":
    unittest.main()
