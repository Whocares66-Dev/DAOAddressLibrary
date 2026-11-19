"""The types half of tools/ghidra_sync.py: how data/structs.csv's fields
become fields of the types Ghidra's decompiler uses, and what else a
decompile takes from a type.

A type changes a decompile only where it is applied: to a method's `this`,
a parameter, a global, a field. Ghidra gives `this` the structure it finds
for the method's class: the one its class recovery made
(/ClassDataTypes/<namespaces>/<Class>/<Class>), else one named for the class
in its parent's category (/ClassDataTypes/<namespaces>/<Class>), which it
makes empty when it first needs it. Until 2026-11-16 the table's structs
went into a folder of their own (/DAOAddressLibrary) that nothing pointed
at, 231 types that changed no decompile, and onto the recovered types as
names over undefined bytes, their types dropped: 9,448 methods showed
`this->field`, none a typed one, and 28 classes' methods pointed at an
empty placeholder beside the recovered type (CCArea, CCCreature,
CClientOptions among them). The user, 2026-11-16: "Consider what other
information we can feed into ghidra so it produces better decompilations."

So, in order:

- a placeholder that is empty beside a recovered type of the same class is
  replaced by it wherever a pointer to it was used. By value it stood for
  a byte (it is one byte long), and there it becomes that byte;
- a struct of the table whose class has a recovered type has its fields
  written onto that type at their absolute offsets (through the class's own
  <Class>_data, as before), now with their types. Ghidra's guesses in the
  way (an `int offset_0x508` where the table has a 16-byte attribute) give
  way to the table, which has an instruction for each field; a vftable
  pointer or a nested class's data does not. A field that already has the
  table's type takes the table's name, a nested class too: it is the
  table's own, renamed (CGameEffect's second CDataArrays). A field carrying
  the table's note at a place the table no longer has one is cleared,
  unless it is one of those two kinds: syncs before 2026-11-16 put the
  note on Ghidra's own as well, so the note alone does not make a thing
  the table's (six rows had a base's vftable pointer at the base's offset
  in a CCObject, corrected 2026-11-16). Those syncs also gave a nested
  class's data the name of the table's field at its first byte: a
  controller's whole base, 108 bytes, was `rig` for the pointer at +4,
  and the decompiler wrote `(this->rig).field_0x26`. Such a one takes
  back its type's name. Ghidra has many classes short
  (GraphicsStructures::Object 40 bytes of 784), and past a type's end the
  decompiler writes `this[1].field_0x4` for `this + 0x6dc`: the class's
  own type grows to the table's size and to a field past its end. Many of
  these types are packed, laid out by Ghidra, where a write by offset
  replaces a whole component and moves the rest; one is unpacked first,
  which keeps the layout it has;
- a struct whose class has no recovered type is built whole as the type
  `this` finds, and its namespace made a class if it was a plain one, so its
  methods' `this` is a pointer to it. /DAOAddressLibrary is emptied: one
  type a class, the one the decompiler uses;
- the recovered types' own names for what they guessed, offset_0xN with N
  counted from after the vptr or from the start of <Class>_data, become
  field_0xN with N the offset in the class, which is what a reader takes
  them for (four readers were misled by 2026-11-05). The bytes of
  <Class>_data that nothing has defined had no name at all, and the
  decompiler made one from the byte's place in <Class>_data, the same
  wrong count (paragon-agent's writers, 2026-11-16: a sheet copied
  `field_0x20` for +0xA4): each is defined a byte named field_0xN too;
- each vftable's slots take the names and prototypes of the functions in
  them, where the table names the function: `(*this->vftablePtr->vfunction34)()`
  reads `(*this->vftablePtr->PropagateMouseEvent)()`, with that function's
  parameters. A slot whose function has no name, as an abstract class's
  are, takes the name its overrides share (tools/vtables_dump.py,
  inherited_names) and their prototype where they share that too: a
  C2DASource's `vfunction11` reads `GetIntByRowId`.

A field's type is the table's `type` text: a C scalar, `T*`, `T[n]`, a
class named as the table names it (found as `this` would find it; by value
only if its size is the field's), or `union{T a;U b}` for one place read
two ways (std::wstring's buffer). What does not resolve stays undefined
bytes under the field's name, as all of them were, and the run counts them.
"""

import re

from msvc_names import split_top

SCALARS = {
    "int": "int",
    "int32": "int",
    "int32_t": "int",
    "long": "int",
    "signed int": "int",
    "unsigned int": "uint",
    "unsigned": "uint",
    "uint": "uint",
    "uint32": "uint",
    "uint32_t": "uint",
    "unsigned long": "uint",
    "DWORD": "uint",
    "short": "short",
    "int16_t": "short",
    "unsigned short": "ushort",
    "uint16_t": "ushort",
    "WORD": "ushort",
    "char": "char",
    "signed char": "char",
    "int8_t": "char",
    "unsigned char": "uchar",
    "uint8_t": "uchar",
    "BYTE": "uchar",
    "bool": "bool",
    "float": "float",
    "double": "double",
    "wchar_t": "wchar",
    "long long": "longlong",
    "int64_t": "longlong",
    "__int64": "longlong",
    "unsigned long long": "ulonglong",
    "uint64_t": "ulonglong",
    "void": "void",
    # An object's id, a 32-bit word (41 fields on 2026-11-16).
    "ObjectId": "uint",
}


def template_of(name):
    """(what comes before a class's last `<...>`, its arguments), or None
    for a class that ends in no template brackets."""
    if not name.endswith(">"):
        return None
    depth = 0
    for at in range(len(name) - 1, -1, -1):
        depth += name[at] == ">"
        depth -= name[at] == "<"
        if depth == 0:
            break
    else:
        return None
    arguments, piece, depth = [], "", 0
    for ch in name[at + 1 : -1]:
        depth += ch == "<"
        depth -= ch == ">"
        if ch == "," and depth == 0:
            arguments.append(piece.strip())
            piece = ""
        else:
            piece += ch
    return name[:at], [*arguments, piece.strip()]


def class_names(tree):
    """The classes a field_type tree names."""
    if tree is None:
        return []
    if tree["k"] == "class":
        return [tree["text"]]
    if tree["k"] == "union":
        return [name for member, _ in tree["members"] for name in class_names(member)]
    return class_names(tree.get("to") or tree.get("of"))


def with_instances(rows):
    """The table's rows without the families' own, and after them the rows
    of each instance of a family that some field's type names.

    A family is a struct written once for every argument, its name ending
    in single capitals for them: `std::vector<T>` with a `T*` first, or
    `std::map<K,V>`. A field typed `std::vector<unsigned int>` then has a
    layout, that family's with unsigned int for T, and so does what such a
    layout names in turn. 944 fields named a class with no rows of its own
    on 2026-11-16, 163 of them a std::vector and 264 a SmartData::Attribute,
    each a different class to Ghidra. A struct the table has rows for under
    its own name is left as the table has it.

    A family's last field may hold an argument itself, not a pointer to it:
    SmartData::Attribute<T> keeps its value at +0xC, so one of int is 0x10
    bytes and one of a wide string 0x28. That field is written with a
    four-byte argument's size; an instance's is its own argument's, and
    its sizeof grows by the difference, to a multiple of four. Where the
    argument's size is not known the instance has neither that field nor
    a size."""
    families = {}
    for row in rows:
        split = template_of(row["struct"])
        if split and all(re.fullmatch("[A-Z]", a) for a in split[1]):
            families.setdefault((split[0], len(split[1])), (split[1], []))[1].append(
                row
            )
    if not families:
        return list(rows)
    written = {id(row) for _, layout in families.values() for row in layout}
    out = [row for row in rows if id(row) not in written]
    have = {row["struct"] for row in rows}
    sizes = {
        row["struct"]: int(row["size"], 16) for row in out if row["field"] == "sizeof"
    }

    def instance(name):
        split = template_of(name)
        family = families.get((split[0], len(split[1]))) if split else None
        if name in have or family is None:
            return
        have.add(name)
        letters, layout = family
        given = dict(zip(letters, split[1], strict=True))
        for argument in split[1]:
            for inner in class_names(field_type(argument)):
                instance(inner)
        fields = sorted(
            (f for f in layout if f["field"] != "sizeof"),
            key=lambda f: int(f["offset"], 16),
        )
        grown = 0
        for field in fields:
            made = dict(field, struct=name)
            made["type"] = re.sub(
                r"\b[A-Z]\b", lambda m: given.get(m.group(), m.group()), field["type"]
            )
            if field["type"] in given and field is fields[-1]:
                size = tree_size(field_type(made["type"]), sizes)
                if size is None:
                    grown = None
                    continue
                grown = size - int(field["size"], 16)
                made["size"] = f"0x{size:X}"
            out.append(made)
            for inner in class_names(field_type(made["type"])):
                instance(inner)
        whole = next((f for f in layout if f["field"] == "sizeof"), None)
        if whole is not None and grown is not None:
            size = -(-(int(whole["size"], 16) + grown) // 4) * 4
            sizes[name] = size
            out.append(dict(whole, struct=name, size=f"0x{size:X}"))

    for row in list(out):
        for name in class_names(field_type(row["type"])):
            instance(name)
    return out


SIZES = {
    "int": 4,
    "uint": 4,
    "short": 2,
    "ushort": 2,
    "char": 1,
    "uchar": 1,
    "bool": 1,
    "float": 4,
    "double": 8,
    "wchar": 2,
    "longlong": 8,
    "ulonglong": 8,
}


def tree_size(tree, sizes):
    """How many bytes a field_type tree is, given the structs' sizes, or
    None where it cannot be told."""
    if tree is None:
        return None
    if tree["k"] == "scalar":
        return SIZES.get(tree["name"])
    if tree["k"] == "ptr":
        return 4
    if tree["k"] == "array":
        inner = tree_size(tree["of"], sizes)
        return None if inner is None else inner * tree["n"]
    if tree["k"] == "class":
        return sizes.get(tree["text"])
    inner = [tree_size(member, sizes) for member, _ in tree["members"]]
    return None if None in inner else max(inner)


def parts_of(name):
    """A class's namespaces and leaf as Ghidra holds them (ghidra_sync's
    ghidra_parts, which this cannot import: it imports this)."""
    return [part.replace("::", ".").replace(" ", "_") for part in split_top(name)]


def field_type(text):
    """A `type` cell as the tree the Ghidra side builds from: None for what
    says nothing (`struct`, `undefined4`, `?`), else {"k": "scalar"|"ptr"|
    "array"|"class"|"union", ...}."""
    text = re.sub(r"\b(const|struct|class|volatile)\s+", "", text.strip()).strip()
    if text.startswith("union{") and text.endswith("}"):
        members = []
        for member in text[len("union{") : -1].split(";"):
            if member.strip():
                kind, _, name = member.strip().rpartition(" ")
                members.append([field_type(kind), name])
        return {"k": "union", "members": members}
    array = re.fullmatch(r"(.+)\[(0x[0-9a-fA-F]+|\d+)\]", text)
    if array:
        return {
            "k": "array",
            "of": field_type(array.group(1)),
            "n": int(array.group(2), 0),
        }
    if text.endswith(("*", "&")):
        return {"k": "ptr", "to": field_type(text[:-1])}
    if text in SCALARS:
        return {"k": "scalar", "name": SCALARS[text]}
    if not text or text in ("struct", "?") or re.fullmatch(r"undefined\d*", text):
        return None
    if not re.fullmatch(r"[A-Za-z_~][\w:<>,.*& ?~-]*", text):
        return None
    return {"k": "class", "parts": parts_of(text), "text": text}


# Runs inside Ghidra after ghidra_sync's names and fixes, with its program,
# dtm, st, fm, listing, dry, done, faults and W.
GHIDRA_TYPES = r"""
import re
from ghidra.app.util import NamespaceUtils
from ghidra.program.model.data import (
    ArrayDataType,
    DataTypeConflictHandler,
    DataUtilities,
    BooleanDataType,
    CategoryPath,
    CharDataType,
    DoubleDataType,
    FloatDataType,
    FunctionDefinition,
    FunctionDefinitionDataType,
    IntegerDataType,
    LongLongDataType,
    ParameterDefinitionImpl,
    Pointer,
    PointerDataType,
    PointerTypedef,
    ShortDataType,
    Structure,
    StructureDataType,
    Undefined,
    Undefined1DataType,
    Undefined4DataType,
    UnionDataType,
    UnsignedCharDataType,
    UnsignedIntegerDataType,
    UnsignedLongLongDataType,
    UnsignedShortDataType,
    VoidDataType,
    WideCharDataType,
)
from ghidra.program.model.listing import CodeUnit, Function, GhidraClass, ParameterImpl

ROOT = program.getPreferredRootNamespaceCategoryPath() or CategoryPath("/ClassDataTypes")
OURS = "DAOAddressLibrary data/structs.csv"
SCALAR = {
    "int": IntegerDataType.dataType, "uint": UnsignedIntegerDataType.dataType,
    "short": ShortDataType.dataType, "ushort": UnsignedShortDataType.dataType,
    "char": CharDataType.dataType, "uchar": UnsignedCharDataType.dataType,
    "bool": BooleanDataType.dataType, "float": FloatDataType.dataType,
    "double": DoubleDataType.dataType, "wchar": WideCharDataType.dataType,
    "longlong": LongLongDataType.dataType, "ulonglong": UnsignedLongLongDataType.dataType,
    "void": VoidDataType.dataType,
}
for key in ("placeholders", "typed", "untyped", "beyond", "blocked", "built", "renamed",
            "slots", "classes", "grown", "unpacked", "damage", "typedfixes", "notype",
            "noroom", "eh", "byvalue", "dropped", "nothis", "restored", "filled"):
    done.setdefault(key, 0)
unresolved = {}


def type_category(parts):
    path = ROOT
    for part in parts:
        path = CategoryPath(path, part)
    return path


def spellings(parts):
    # A template's arguments hold `.` for `::` in the table's namespaces
    # (ghidra_sync's ghidra_parts) and `::` in the class recovery's types.
    other = [part.replace(".", "::") for part in parts]
    return [parts] if other == parts else [parts, other]


def recovered_type(parts):
    for spelt in spellings(parts):
        found = dtm.getDataType(type_category(spelt), spelt[-1])
        if isinstance(found, Structure):
            return found
    return None


def plain_type(parts):
    for spelt in spellings(parts):
        found = dtm.getDataType(type_category(spelt[:-1]), spelt[-1])
        if isinstance(found, Structure):
            return found
    return None


def class_type(parts):
    # The structure Ghidra gives the class's `this`: the recovered one where
    # it has fields, else the one in the parent's category.
    found = recovered_type(parts)
    if found is not None and found.getNumDefinedComponents() > 0:
        return found
    return plain_type(parts) or found


def merge_placeholders():
    pairs = []
    for shape in dtm.getAllStructures():
        path = shape.getCategoryPath()
        if path.getName() != shape.getName() or not path.isAncestorOrSelf(ROOT) \
                or shape.getNumDefinedComponents() == 0:
            continue
        plain = dtm.getDataType(path.getParent(), shape.getName())
        if isinstance(plain, Structure) and plain.getNumDefinedComponents() == 0:
            pairs.append((plain, shape))
    if pairs and not dry:
        by_value({plain.getPathName() for plain, _ in pairs})
    for plain, shape in pairs:
        done["placeholders"] += 1
        if not dry:
            # False: the recovered type stays in its class's category, with
            # its vftables; True moved all 28 into the placeholder's place.
            dtm.replaceDataType(plain, shape, False)


def by_value(paths):
    # A placeholder is one byte long, and here and there it stands by value
    # for a byte: CCCreature::ForScript_SetPlot's second parameter was "a
    # CCCreature" in a register. Replaced by the class, 3,356 bytes, it gave
    # every caller "Cannot assign parameter address for CCCreature" and no
    # decompile (34 of a sample of 743, 2026-11-16). Such a use becomes the
    # undefined byte it was; a pointer to the placeholder is what the
    # replacement is for.
    byte = Undefined.getUndefinedDataType(1)

    def held(kind):
        return isinstance(kind, Structure) and kind.getPathName() in paths

    for f in fm.getFunctions(True):
        for param in f.getParameters():
            if held(param.getDataType()):
                done["byvalue"] += 1
                param.setDataType(byte, SOURCE)
        if held(f.getReturnType()):
            done["byvalue"] += 1
            f.setReturnType(byte, SOURCE)
    for path in paths:
        plain = dtm.getDataType(path)
        for parent in list(plain.getParents()):
            if isinstance(parent, FunctionDefinition):
                args = list(parent.getArguments())
                for arg in args:
                    if held(arg.getDataType()):
                        done["byvalue"] += 1
                        arg.setDataType(byte)
                parent.setArguments(args)
                if held(parent.getReturnType()):
                    done["byvalue"] += 1
                    parent.setReturnType(byte)
            elif isinstance(parent, Structure):
                for unit in list(parent.getDefinedComponents()):
                    if held(unit.getDataType()):
                        done["byvalue"] += 1
                        parent.replace(unit.getOrdinal(), byte, 1, unit.getFieldName(), unit.getComment())


def build(tree, size, owner, field, strict=False):
    # The Ghidra type of a field_type tree, or None: it must be `size` long.
    # A pointer to a class Ghidra has no type for is a void *, or with
    # `strict` nothing: a field is better a void * than undefined bytes, a
    # global or a return type that is one already gains nothing.
    if tree is None:
        return None
    kind = tree["k"]
    made = None
    if kind == "scalar":
        made = SCALAR[tree["name"]].clone(dtm)
    elif kind == "ptr":
        to = build(tree["to"], None, owner, field, strict) if tree["to"] else None
        if to is None and strict:
            return None
        made = PointerDataType(to if to is not None else VoidDataType.dataType, dtm)
    elif kind == "array":
        of = build(tree["of"], size // tree["n"] if size else None, owner, field)
        if of is not None and of.getLength() > 0 and tree["n"] > 0:
            made = ArrayDataType(of, tree["n"], of.getLength(), dtm)
    elif kind == "class":
        made = class_type(tree["parts"])
        if made is None or (size is not None and made.getLength() != size):
            unresolved[tree["text"]] = unresolved.get(tree["text"], 0) + 1
            return None if size is not None else made
    elif kind == "union":
        made = UnionDataType(type_category(owner), owner[-1] + "_" + field, dtm)
        for member, name in tree["members"]:
            part = build(member, None, owner, field)
            if part is None:
                return None
            made.add(part, name, None)
    if made is None or (size is not None and made.getLength() != size):
        return None
    return made


def length_of(shape):
    return 0 if shape.isZeroLength() else shape.getLength()


def same_type(a, b):
    return a is not None and b is not None and (a.isEquivalent(b) or a.getPathName() == b.getPathName())


def own_struct(parts, size):
    # The type `this` finds for a class with no recovered type, sized.
    shape = plain_type(parts)
    if shape is None:
        if dry:
            return None
        shape = dtm.addDataType(StructureDataType(type_category(parts[:-1]), parts[-1], size, dtm), None)
    return shape


def fill_own(shape, parts, size, fields):
    # Ours whole: rebuilt when a row has changed it.
    want = []
    for offset, length, tree, field in fields:
        kind = build(tree, length, parts, field)
        done["typed" if kind is not None else "untyped"] += 1
        want.append((offset, length, kind if kind is not None else Undefined.getUndefinedDataType(length), field))
    have = [(c.getOffset(), c.getLength(), c.getDataType(), c.getFieldName())
            for c in shape.getDefinedComponents()]
    if shape.getDescription() == OURS and shape.getLength() == size and len(have) == len(want) and all(
            h[0] == w[0] and h[1] == w[1] and h[3] == w[3] and same_type(h[2], w[2])
            for h, w in zip(have, want)):
        return
    done["built"] += 1
    if dry:
        return
    fixed(shape)
    shape.deleteAll()
    shape.setDescription(OURS)
    if size > length_of(shape):
        shape.growStructure(size - length_of(shape))
    for offset, length, kind, field in want:
        shape.replaceAtOffset(offset, kind, length, field, None)


def class_field(shape, offset, leaf):
    # The structure a field at `offset` of the class is in, and where: the
    # class's own <leaf>_data if it is there. Not inside another's: a base
    # class's _data is shared by every class built on it, and two classes'
    # names would take turns.
    while True:
        unit = shape.getComponentContaining(offset)
        if unit is None:
            return shape, offset
        inner = unit.getDataType()
        if isinstance(inner, Structure) and inner.getName() == leaf + "_data" \
                and offset - unit.getOffset() < inner.getLength():
            offset -= unit.getOffset()
            shape = inner
            continue
        return shape, offset


def fixed(shape):
    # Many of the recovered types are packed: Ghidra lays them out, and a
    # write at an offset of one replaces or deletes a whole component and
    # moves the rest (2026-11-16: 25 types shrank and 32 nested classes'
    # data were lost, seen before a save). Unpacked, a type keeps the layout
    # it has (400 tried, none changed, nor any type holding one) and is then
    # written by offset.
    if shape.isPackingEnabled():
        done["unpacked"] += 1
        shape.setPackingEnabled(False)


def is_kept(unit):
    # What the table's field does not replace: a nested structure (a base's
    # or the class's data), a vftable pointer.
    kind = unit.getDataType()
    if isinstance(kind, Structure) or unit.getFieldName() == "vftablePtr":
        return True
    return isinstance(kind, Pointer) and isinstance(kind.getDataType(), Structure) \
        and "_vftable" in kind.getDataType().getName()


def merge_field(owner, parts, name, size, offset, length, tree, field):
    shape, at = class_field(owner, offset, parts[-1])
    if at + length > length_of(shape):
        # Ghidra has many classes short (GraphicsStructures::Object 40 bytes
        # of 784). The class's own type grows to the field; the data of a
        # class nested in others does not, which would move theirs.
        if shape is not owner:
            done["beyond"] += 1
            return
        done["grown"] += 1
        if not dry:
            fixed(shape)
            shape.growStructure(max(size, at + length) - length_of(shape))
        elif at > length_of(shape):
            done["classfields"] += 1
            return
    note = "%s +0x%X (%s)" % (name, offset, OURS)
    kind = build(tree, length, parts, field)
    done["typed" if kind is not None else "untyped"] += 1
    unit = shape.getComponentContaining(at)
    if unit is not None and unit.getOffset() == at and unit.getFieldName() == field \
            and unit.getComment() == note and (
                same_type(unit.getDataType(), kind) if kind is not None
                else unit.getLength() == length or not Undefined.isUndefined(unit.getDataType())):
        return
    if kind is not None and unit is not None and unit.getOffset() == at and same_type(
            unit.getDataType(), kind):
        # Already the table's type: the row was renamed.
        done["classfields"] += 1
        if not dry:
            unit.setFieldName(field)
            unit.setComment(note)
        return
    over = []
    i = at
    while i < at + length:
        part = shape.getComponentContaining(i)
        if part is None:
            break
        over.append(part)
        i = part.getOffset() + max(1, part.getLength())
    if any(is_kept(part) for part in over):
        done["blocked"] += 1
        return
    done["classfields"] += 1
    if dry:
        return
    fixed(shape)
    if kind is None and unit is not None and unit.getOffset() == at \
            and not Undefined.isUndefined(unit.getDataType()):
        # No type of ours: Ghidra's own stays, under the table's name.
        unit.setFieldName(field)
        unit.setComment(note)
        return
    for start in sorted({part.getOffset() for part in over}, reverse=True):
        shape.clearAtOffset(start)
    shape.replaceAtOffset(at, kind if kind is not None else Undefined.getUndefinedDataType(length),
                          length, field, note)


NOTE = re.compile(r"^(.+) \+0x([0-9A-F]+) \(%s\)$" % re.escape(OURS))


def drop_stale(wrote):
    # A field the table wrote at a place it no longer has one; and a nested
    # class's data an old sync named for a field of another length.
    for shape in list(dtm.getAllStructures()):
        if not shape.getCategoryPath().isAncestorOrSelf(ROOT) or shape.getDescription() == OURS:
            continue
        stale = []
        for unit in shape.getDefinedComponents():
            found = NOTE.match(unit.getComment() or "")
            if not found:
                continue
            length = wrote.get((found.group(1), int(found.group(2), 16)))
            kind = unit.getDataType()
            if isinstance(kind, Structure):
                if length != unit.getLength():
                    done["restored"] += 1
                    if not dry:
                        unit.setFieldName(kind.getName())
                        unit.setComment(None)
            elif length is None and not is_kept(unit):
                stale.append(unit.getOffset())
        done["dropped"] += len(stale)
        if stale and not dry:
            fixed(shape)
            for start in sorted(stale, reverse=True):
                shape.clearAtOffset(start)


def true_offsets(owner, leaf):
    # offset_0xN, as the class recovery named what it guessed, to field_0xN
    # with N the offset in the class.
    for shape, base in [(owner, 0)] + [
            (c.getDataType(), c.getOffset()) for c in owner.getDefinedComponents()
            if isinstance(c.getDataType(), Structure) and c.getDataType().getName() == leaf + "_data"]:
        for unit in shape.getDefinedComponents():
            name = unit.getFieldName()
            if name is not None and name.startswith("offset_0x"):
                done["renamed"] += 1
                if not dry:
                    unit.setFieldName("field_0x%X" % (base + unit.getOffset()))
        if base and not shape.isPackingEnabled():
            # A byte nobody has defined has no name, and the decompiler
            # makes one from where it is in <leaf>_data: GameModeCutscene's
            # +0xA4 read `(this->GameModeCutscene_data).field_0x20`. Each is
            # named for its place in the class: four bytes together where
            # they are a word of the object (as bytes apart, a store of a
            # word read as four stores of a byte each, in 74 functions of
            # 743 tried), a byte alone otherwise.
            def free(i):
                unit = shape.getComponentContaining(i)
                return i < shape.getLength() and (
                    unit is None or unit.getDataType().getName() == "undefined")

            at = 0
            while at < shape.getLength():
                if not free(at):
                    unit = shape.getComponentContaining(at)
                    at = unit.getOffset() + max(1, unit.getLength())
                    continue
                word = (base + at) % 4 == 0 and free(at + 1) and free(at + 2) and free(at + 3)
                size = 4 if word else 1
                done["filled"] += size
                if not dry:
                    shape.replaceAtOffset(
                        at, Undefined4DataType.dataType if word else Undefined1DataType.dataType,
                        size, "field_0x%X" % (base + at), None)
                at += size


def namespace_of(parts):
    cur = program.getGlobalNamespace()
    for part in parts:
        cur = st.getNamespace(part, cur)
        if cur is None:
            return None
    return cur


def kept_parts():
    # Where every class type's vftable pointers and nested classes are, and
    # how long it is: what a write of the table's fields must not move.
    out = {}
    for shape in dtm.getAllStructures():
        if shape.getCategoryPath().isAncestorOrSelf(ROOT) and shape.getDescription() != OURS:
            out[shape.getPathName()] = (length_of(shape), [
                (unit.getOffset(), unit.getLength(), unit.getDataType().getName())
                for unit in shape.getDefinedComponents() if is_kept(unit)])
    return out


def damage(before):
    # What moved that must not have. A type that is gone was a placeholder.
    after = kept_parts()
    for path, (length, parts) in before.items():
        if path not in after:
            continue
        now, has = after[path]
        if now < length:
            done["damage"] += 1
            faults.append("damage: %s shrank from %d to %d" % (path, length, now))
        lost = [part for part in parts if part not in has]
        if lost:
            done["damage"] += 1
            faults.append("damage: %s lost %s" % (path, lost[:3]))


UNNAMED = re.compile(r"^(FUN_|thunk_FUN_|vfunction\d+|_*purecall)")


def shared_shape(overrides, kind):
    # The prototype the functions at these addresses share but for whose
    # method each is, as a slot of the vftable type `kind`: this is that
    # table's class where the table is the class's first (the others' this
    # is inside the object: void*). None where they differ in convention,
    # in what they return or in a parameter, or are not __thiscall.
    shapes = []
    for address in overrides:
        f = fm.getFunctionAt(toAddr(address))
        if f is None:
            return None
        shapes.append(FunctionDefinitionDataType(f, False))
    first = shapes[0]
    args = list(first.getArguments())
    if not args or first.getCallingConventionName() != "__thiscall":
        return None
    for other in shapes[1:]:
        theirs = list(other.getArguments())
        same = other.getCallingConventionName() == "__thiscall" and len(theirs) == len(args) \
            and other.hasVarArgs() == first.hasVarArgs() \
            and other.getReturnType().isEquivalent(first.getReturnType()) \
            and all(a.getDataType().isEquivalent(b.getDataType())
                    for a, b in zip(args[1:], theirs[1:]))
        if not same:
            return None
    path = kind.getCategoryPath()
    owner = dtm.getDataType(path, path.getName())
    whole = owner is not None and kind.getName() == path.getName() + "_vftable"
    receiver = PointerDataType(owner if whole else VoidDataType.dataType, dtm)
    args[0] = ParameterDefinitionImpl("this", receiver, None)
    first.setArguments(args)
    return first


def slot_names():
    # Each vftable's slots, named and typed for the functions in them. A slot
    # that holds no function with a name (an abstract class's _purecall)
    # takes the name its overrides go by and the prototype they share,
    # W["slotnames"]; where they share none it keeps the type it has.
    memory = program.getMemory()
    seen = set()
    for symbol in st.getSymbolIterator("*vftable*", True):
        base = symbol.getAddress()
        if base in seen:
            continue
        seen.add(base)
        data = listing.getDataAt(base)
        kind = data.getDataType() if data is not None else None
        if not isinstance(kind, Structure) or "_vftable" not in kind.getName():
            continue
        used = set()
        inherited = W.get("slotnames", {}).get("0x%08X" % base.getOffset(), {})
        for unit in kind.getDefinedComponents():
            try:
                if unit.getLength() != 4:
                    continue
                f = fm.getFunctionAt(toAddr(memory.getInt(base.add(unit.getOffset())) & 0xFFFFFFFF))
                named = f.getThunkedFunction(True) if f is not None and f.isThunk() else f
                own = named is not None and not UNNAMED.match(named.getName())
                field, overrides = (named.getName(), None) if own \
                    else inherited.get(str(unit.getOffset() // 4), (None, None))
                if field is None:
                    continue
                field = re.sub(r"[^A-Za-z0-9_~]", "_", field)
                if field in used:
                    field = "%s_%X" % (field, unit.getOffset())
                used.add(field)
                want = FunctionDefinitionDataType(f, False) if own else shared_shape(overrides, kind)
                if want is None:
                    if unit.getFieldName() != field:
                        done["slots"] += 1
                        if not dry:
                            unit.setFieldName(field)
                    continue
                want.setName("%s_%X" % (kind.getName(), unit.getOffset()))
                want.setCategoryPath(kind.getCategoryPath())
                has = unit.getDataType()
                has = has.getDataType() if isinstance(has, Pointer) else None
                typed = isinstance(has, FunctionDefinition) and has.getName() == want.getName() \
                    and has.isEquivalent(want)
                if typed and unit.getFieldName() == field:
                    continue
                done["slots"] += 1
                if dry:
                    continue
                if typed:
                    unit.setFieldName(field)
                else:
                    made = dtm.addDataType(want, DataTypeConflictHandler.REPLACE_HANDLER)
                    kind.replace(unit.getOrdinal(), PointerDataType(made, dtm), 4, field, unit.getComment())
            except Exception as e:
                faults.append("slot %s +0x%x: %s" % (kind.getName(), unit.getOffset(), e))


def this_at(f, kind, shift):
    # A method called with this `shift` bytes into its object (a later
    # base's vftable): this becomes a pointer Ghidra knows to be that far
    # in, and the decompiler writes ADJ(this)->field with the object's own
    # fields. Ghidra types a class's this itself unless the function's
    # storage is its own, so the parameters are kept where they are and
    # this alone retyped.
    params = list(f.getParameters())
    first = params[0].getVariableStorage().getRegister() if params else None
    if first is None or first.getName() != "ECX":
        done["nothis"] += 1
        return
    name = "%s_plus_0x%X_ptr" % (kind.getName(), shift)
    if f.hasCustomVariableStorage() and params[0].getDataType().getName() == name:
        return
    done["typedfixes"] += 1
    if dry:
        return
    pointer = PointerTypedef(name, kind, 4, dtm, shift)
    pointer.setCategoryPath(kind.getCategoryPath())
    pointer = dtm.resolve(pointer, DataTypeConflictHandler.REPLACE_HANDLER)
    f.setCustomVariableStorage(True)
    new = [ParameterImpl("this", pointer, params[0].getVariableStorage(), program)] + [
        ParameterImpl(p.getName(), p.getDataType(), p.getVariableStorage(), program)
        for p in params[1:]]
    f.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, True, SOURCE, new)


def typed_fix(address, what, tree, text):
    a = toAddr(address)
    kind = build(tree, None, [], "", True)
    if kind is None:
        done["notype"] += 1
        return
    if what == "thisat":
        this_at(fm.getFunctionAt(a), kind, int(text.rsplit("+", 1)[1], 16))
        return
    if what == "returntype":
        f = fm.getFunctionAt(a)
        if same_type(f.getReturnType(), kind):
            return
        done["typedfixes"] += 1
        if not dry:
            f.setReturnType(kind, SOURCE)
        return
    have = listing.getDataAt(a)
    if have is not None and same_type(have.getDataType(), kind):
        return
    if isinstance(kind, Structure):
        # An object: only a class Ghidra has a layout for, and only where no
        # other name lies before its end, which a size Ghidra has too long
        # would otherwise swallow.
        after = st.getSymbolIterator(a.add(1), True)
        nearest = after.next() if after.hasNext() else None
        if length_of(kind) < 4 or (
                nearest is not None and nearest.getAddress().subtract(a) < kind.getLength()):
            done["noroom"] += 1
            return
        mode = DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
    else:
        inside = listing.getDataContaining(a)
        if inside is not None and inside.getAddress() != a:
            raise Exception("inside the data at %s" % inside.getAddress())
        mode = DataUtilities.ClearDataMode.CLEAR_SINGLE_DATA
    done["typedfixes"] += 1
    if not dry:
        DataUtilities.createData(program, a, kind, -1, mode)


if W.get("types"):
    guard = kept_parts()
    try:
        merge_placeholders()
    except Exception as e:
        faults.append("placeholders: %s" % e)
    # Ours first, sized and empty, so a field of one's type finds it.
    own = {}
    for name, parts, size, fields in W["structs"]:
        try:
            recovered = recovered_type(parts)
            if recovered is None or recovered.getNumDefinedComponents() == 0:
                shape = own_struct(parts, size)
                if shape is not None and shape.getDescription() != OURS \
                        and shape.getNumDefinedComponents() > 0:
                    continue  # someone else's: fields are merged into it below
                own[name] = shape
                if shape is not None and not dry and length_of(shape) < size:
                    shape.setDescription(OURS)
                    shape.growStructure(size - length_of(shape))
                space = namespace_of(parts)
                if space is not None and not isinstance(space, GhidraClass) and not space.isGlobal():
                    done["classes"] += 1
                    if not dry:
                        NamespaceUtils.convertNamespaceToClass(space)
        except Exception as e:
            faults.append("struct %s: %s" % (name, e))
    for name, parts, size, fields in W["structs"]:
        try:
            done["structs"] += 1
            if name in own:
                if own[name] is not None:
                    fill_own(own[name], parts, size, fields)
                continue
            owner = class_type(parts)
            if size > length_of(owner):
                # The table's size, a sizeof row's or the end of its last
                # field: past the end of a type that is short the decompiler
                # writes this[1].field_0x4 for this + 0x6dc.
                done["grown"] += 1
                if not dry:
                    fixed(owner)
                    owner.growStructure(size - length_of(owner))
            for offset, length, tree, field in fields:
                if offset == 0 and field == "vftable":
                    continue
                try:
                    merge_field(owner, parts, name, size, offset, length, tree, field)
                except Exception as e:
                    faults.append("class field %s +0x%x %s: %s" % (name, offset, field, e))
        except Exception as e:
            faults.append("struct %s: %s" % (name, e))
    try:
        drop_stale({(name, offset): length
                    for name, _, _, fields in W["structs"] for offset, length, _, _ in fields})
    except Exception as e:
        faults.append("dropped fields: %s" % e)
    # The folder nothing pointed at.
    old = dtm.getCategory(CategoryPath("/DAOAddressLibrary"))
    if old is not None and not dry:
        for shape in list(old.getDataTypes()):
            dtm.remove(shape, monitor)
        dtm.getRootCategory().removeCategory("DAOAddressLibrary", monitor)
    for shape in list(dtm.getAllStructures()):
        path = shape.getCategoryPath()
        if path.getName() == shape.getName() and path.isAncestorOrSelf(ROOT):
            try:
                true_offsets(shape, shape.getName())
            except Exception as e:
                faults.append("offsets %s: %s" % (shape.getPathName(), e))
    done["unresolved"] = sorted(unresolved.items(), key=lambda kv: -kv[1])[:40]
    damage(guard)

for address, what, tree, text in W.get("typed", []):
    try:
        typed_fix(address, what, tree, text)
    except Exception as e:
        faults.append("fix 0x%08x %s %s: %s" % (address, what, text, e))

# After the typed fixes, which change prototypes (a return's type, a this
# inside its object): before them a whole run typed 842 slots from the
# prototypes the signature rows had just put back, and a run of the types
# alone typed them from the fixed ones (2026-11-18).
if W.get("types"):
    try:
        slot_names()
    except Exception as e:
        faults.append("vftable slots: %s" % e)

EH_NAMES = ("FUN_", "Unwind@", "Catch@", "EhHandler@")
for address, label, text in W.get("eh", []):
    try:
        a = toAddr(address)
        f = fm.getFunctionAt(a)
        if f is None:
            continue
        if f.getName() != label and f.getName().startswith(EH_NAMES):
            done["eh"] += 1
            if not dry:
                f.setName(label, SOURCE)
        unit = listing.getCodeUnitAt(a)
        if unit is not None and unit.getComment(CodeUnit.PLATE_COMMENT) != text:
            done["eh"] += 1
            if not dry:
                unit.setComment(CodeUnit.PLATE_COMMENT, text)
    except Exception as e:
        faults.append("eh 0x%08x: %s" % (address, e))
"""

# Runs inside Ghidra, on its own, after the types are in: W["getters"] is
# (address, offset) of each function that only reads the four-byte field at
# that offset of this (tools/receivers.py, shared_getters), code the linker
# has every class's getter of a field there share. One prototype cannot say
# what each caller gets: SmartData::Attribute::Get (mov eax,[ecx+0xC])
# answers a CCCreatureStats* at one of its 2,044 calls and an int at the
# next. So each call whose receiver the decompiler types as a struct
# with a four-byte field at the offset gets, at the call, a prototype that
# returns that field's type (Ghidra's "override signature"), and what follows
# reads as that type: CCCreature::ReadFields' call through the stats
# attribute reads (*stats->vftablePtr->LoadFromTemplate)(...) (paragon-agent,
# 2026-11-18). A call whose receiver has no such field is left alone, as is
# one whose field is of the type the function's own prototype returns, and
# one that had a prototype from here and no longer earns it loses it.
# Marking the function inline was tried first and dropped: typed receivers
# read as the field, but the other seven in eight read *(int *)(x + 100)
# for Get(x + 0x58), which hides that an attribute is at +0x58.
GHIDRA_GETTERS = r"""
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    Array, Composite, FunctionDefinitionDataType, ParameterDefinitionImpl, Pointer,
    PointerDataType, Structure, TypeDef, Undefined,
)
from ghidra.program.model.pcode import HighFunctionDBUtil, PcodeOp
from ghidra.program.model.symbol import SymbolType
W = json.loads(PAYLOAD)
program = currentProgram
if program.getExecutableSHA256().lower() != W["sha256"]:
    raise Exception("not the " + W["build"] + " build: " + program.getExecutableSHA256())
dry = W["dry"]
fm = program.getFunctionManager()
st = program.getSymbolTable()
dtm = program.getDataTypeManager()
done = {"getters": 0, "getterdropped": 0, "gettersame": 0, "getterfailed": 0}
faults = []


def receiver(value):
    # The struct the decompiler takes the call's this to point to, or None.
    # Under a cast is what the value is; the cast is to the callee's (or an
    # earlier run's) parameter.
    made = value.getDef()
    if made is not None and made.getOpcode() == PcodeOp.CAST:
        value = made.getInput(0)
    high = value.getHigh()
    kind = high.getDataType() if high is not None else None
    if isinstance(kind, TypeDef) or not isinstance(kind, Pointer):
        return None
    to = kind.getDataType()
    return to if isinstance(to, Structure) else None


def shape(callee, owner, offset):
    # (what the call returns, the struct its this points to) for a receiver
    # of this struct, or None.
    # The field is looked for through the structs held by value: a class's
    # own fields are in its <Class>_data, and a base's in the base.
    unit, inside = None, owner
    while isinstance(inside, Structure):
        unit = inside.getComponentContaining(offset)
        inside = unit.getDataType() if unit is not None else None
        if unit is not None:
            offset -= unit.getOffset()
    if unit is None or offset != 0 or unit.getLength() != 4:
        return None
    kind = unit.getDataType()
    if Undefined.isUndefined(kind) or isinstance(kind, (Composite, Array)) \
            or kind.isEquivalent(callee.getReturnType()):
        return None
    return kind, owner


def held_at(at):
    # (the label Ghidra keeps a call's own prototype as, that prototype), or
    # (None, None). It is in a namespace `override` of the caller's, named
    # prt_ and the call's address.
    for symbol in st.getSymbols(at):
        if symbol.getSymbolType() == SymbolType.LABEL and symbol.getName().startswith("prt"):
            held = HighFunctionDBUtil.readOverride(symbol)
            if held is not None:
                return symbol, held.getDataType()
    return None, None


def is_shape(has, want):
    # Ghidra renames the prototype it keeps, so the two are compared by what
    # they say and not as types.
    args = list(has.getArguments())
    return has.getCallingConventionName() == "__thiscall" and len(args) == 1 \
        and has.getReturnType().isEquivalent(want[0]) \
        and args[0].getDataType().isEquivalent(PointerDataType(want[1], dtm))


def calls(dec, f, callee, offset):
    # One reading of a caller: [calls given a prototype, calls that lost
    # theirs, calls that had the one they earn], or None if it did not
    # decompile.
    high = dec.decompileFunction(f, 120, monitor).getHighFunction()
    if high is None:
        return None
    given, lost, same = 0, 0, 0
    ops = high.getPcodeOps()
    while ops.hasNext():
        op = ops.next()
        if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 2 \
                or op.getInput(0).getAddress() != callee.getEntryPoint():
            continue
        at = op.getSeqnum().getTarget()
        want = shape(callee, receiver(op.getInput(1)), offset)
        symbol, has = held_at(at)
        if want is None:
            if symbol is not None:
                lost += 1
                if not dry:
                    symbol.delete()
        elif has is not None and is_shape(has, want):
            same += 1
        else:
            given += 1
            if not dry:
                made = FunctionDefinitionDataType(callee.getName())
                made.setReturnType(want[0])
                made.setArguments([ParameterDefinitionImpl("this", PointerDataType(want[1], dtm), None)])
                made.setCallingConvention("__thiscall")
                # It replaces the label the call had, if any.
                HighFunctionDBUtil.writeOverride(f, at, made)
    return given, lost, same


def settle(dec, f, callee, offset):
    # A caller is read again after a change to it: what one call returns
    # types the receiver of the next (Get(Get(&a->b)->c)), so one reading
    # does not find them all.
    wrote = 0
    for _ in range(6):
        got = calls(dec, f, callee, offset)
        if got is None:
            done["getterfailed"] += 1
            return
        done["getters"] += got[0]
        done["getterdropped"] += got[1]
        if dry or not (got[0] or got[1]):
            done["gettersame"] += got[2] - wrote
            return
        wrote += got[0]


dec = DecompInterface()
dec.openProgram(program)
try:
    for address, offset in W["getters"]:
        callee = fm.getFunctionAt(toAddr(address))
        callers = {}
        for ref in program.getReferenceManager().getReferencesTo(callee.getEntryPoint()):
            f = fm.getFunctionContaining(ref.getFromAddress()) if ref.getReferenceType().isCall() else None
            if f is not None:
                callers[f.getEntryPoint().getOffset()] = f
        for _, f in sorted(callers.items()):
            try:
                settle(dec, f, callee, offset)
            except Exception as e:
                faults.append("getter calls in %s: %s" % (f.getName(True), e))
finally:
    dec.dispose()
print("RESULT " + json.dumps({"done": done, "faults": faults[:50], "nfaults": len(faults)}))
"""

# Runs inside Ghidra, on its own, after the fixes: gives a function the
# parameters its own decompile finds, where Ghidra stores fewer stack
# parameters than the function's ret takes off the stack and no signature row
# says what they are (W["rows"], their addresses). Such a function reads
# rightly by itself, since the decompiler works its parameters out as it
# goes, but a caller's decompile is made without that and loses arguments at
# some of its calls: CResGFF::ReadFieldINT() for 83 calls with a label and a
# default, ECString::Assign() at 61 of its 368 (paragon-agent, 2026-11-18 and
# -19: a porter took the on-hit labels for unknown). 6,431 functions were so
# on 2026-11-19, 2,065 of them the engine's with 13,542 calls. What is stored
# is the decompiler's reading (Ghidra's "commit params"): the count
# and the convention are the code's, the names are param_N and the types its
# guesses, and a signature row replaces them. What a function returns is
# not stored: the decompile's void for one whose value only its callers use
# cost them the value (extraout_ 240 to 432 in the sample of 743).
GHIDRA_PARAMS = r"""
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
W = json.loads(PAYLOAD)
program = currentProgram
if program.getExecutableSHA256().lower() != W["sha256"]:
    raise Exception("not the " + W["build"] + " build: " + program.getExecutableSHA256())
dry = W["dry"]
listing = program.getListing()
held = set(W["rows"])
done = {"params": 0, "paramsfailed": 0}
faults = []
PIECES = ("Unwind@", "Catch@", "EhHandler@")


def short(f):
    # How many bytes more the function's ret takes off the stack than its
    # stored parameters hold.
    purge = 0
    for ins in listing.getInstructions(f.getBody(), True):
        if ins.getMnemonicString() == "RET" and ins.getNumOperands():
            purge = max(purge, ins.getScalar(0).getValue())
    stack = sum(max(p.getLength(), 4) for p in f.getParameters() if p.isStackVariable())
    return max(0, purge - stack)


def found(high):
    # The bytes of stack parameters the decompile finds.
    proto = high.getFunctionPrototype()
    total = 0
    for i in range(proto.getNumParams()):
        storage = proto.getParam(i).getStorage()
        if storage.isStackStorage():
            total += max(storage.size(), 4)
    return total


dec = DecompInterface()
dec.openProgram(program)
try:
    for f in program.getFunctionManager().getFunctions(True):
        if f.isThunk() or f.getEntryPoint().getOffset() in held or f.getName().startswith(PIECES):
            continue
        try:
            if short(f) == 0:
                continue
            done["params"] += 1
            if dry:
                continue
            # Only where the decompile finds all the ret takes: an argument
            # the function never reads is one it does not find, and storing
            # the short list made that function's own decompile worse, as
            # did filling it up with words (both tried 2026-11-19).
            high = dec.decompileFunction(f, 120, monitor).getHighFunction()
            stored = sum(max(q.getLength(), 4) for q in f.getParameters() if q.isStackVariable())
            if high is None or found(high) < stored + short(f):
                done["params"] -= 1
                done["paramsfailed"] += 1
                continue
            HighFunctionDBUtil.commitParamsToDatabase(
                high, True, HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS)
        except Exception as e:
            faults.append("parameters of %s: %s" % (f.getName(True), e))
finally:
    dec.dispose()
print("RESULT " + json.dumps({"done": done, "faults": faults[:50], "nfaults": len(faults)}))
"""
