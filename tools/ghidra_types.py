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
  pointer or a nested class's data does not. Ghidra has many classes short
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
  them for (four readers were misled by 2026-11-05);
- each vftable's slots take the names and prototypes of the functions in
  them, where the table names the function: `(*this->vftablePtr->vfunction34)()`
  reads `(*this->vftablePtr->PropagateMouseEvent)()`, with that function's
  parameters.

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
}


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
    Pointer,
    PointerDataType,
    ShortDataType,
    Structure,
    StructureDataType,
    Undefined,
    UnionDataType,
    UnsignedCharDataType,
    UnsignedIntegerDataType,
    UnsignedLongLongDataType,
    UnsignedShortDataType,
    VoidDataType,
    WideCharDataType,
)
from ghidra.program.model.listing import CodeUnit, GhidraClass

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
            "noroom", "eh", "byvalue"):
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


def slot_names():
    # Each vftable's slots, named and typed for the functions in them.
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
        for unit in kind.getDefinedComponents():
            try:
                if unit.getLength() != 4:
                    continue
                f = fm.getFunctionAt(toAddr(memory.getInt(base.add(unit.getOffset())) & 0xFFFFFFFF))
                if f is None:
                    continue
                named = f.getThunkedFunction(True) if f.isThunk() else f
                if named is None or UNNAMED.match(named.getName()):
                    continue
                field = re.sub(r"[^A-Za-z0-9_~]", "_", named.getName())
                if field in used:
                    field = "%s_%X" % (field, unit.getOffset())
                used.add(field)
                want = FunctionDefinitionDataType(f, False)
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


def typed_fix(address, what, tree, text):
    a = toAddr(address)
    kind = build(tree, None, [], "", True)
    if kind is None:
        done["notype"] += 1
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
    try:
        slot_names()
    except Exception as e:
        faults.append("vftable slots: %s" % e)
    damage(guard)

for address, what, tree, text in W.get("typed", []):
    try:
        typed_fix(address, what, tree, text)
    except Exception as e:
        faults.append("fix 0x%08x %s %s: %s" % (address, what, text, e))

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
