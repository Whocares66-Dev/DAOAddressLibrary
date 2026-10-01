"""Undecorate the MSVC type names RTTI keeps: ".?AVFoo@Bar@@" is Bar::Foo.

Enough of Microsoft's name mangling for the class names in DAOrigins.exe's
type descriptors, templates included:

    .?AV?$MemberFunctionMessageHandler@VGameModeController@@VUserTogglePauseMessage@@$H?HandleMessage@1@QAE_NABV2@@ZA@@Private@Messages@@
    -> Messages::Private::MemberFunctionMessageHandler<GameModeController,UserTogglePauseMessage,&GameModeController::HandleMessage>

A template argument that is a member function pointer ($H) comes out as
&Class::Method, which is what tools/message_handlers.py reads the handler
table from. What this does not know (rvalue references, function-pointer
types, some cv forms) raises ValueError; undecorate() then gives back the
decorated name unchanged, so a caller always has a name.

    python tools/msvc_names.py ".?AVScaleformManager@GUI@@"
"""

import sys

# Built-in types by their one-letter codes, and the two-letter '_' codes.
_PRIMITIVE = {
    "C": "signed char",
    "D": "char",
    "E": "unsigned char",
    "F": "short",
    "G": "unsigned short",
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "M": "float",
    "N": "double",
    "O": "long double",
    "X": "void",
}
_UNDERSCORE = {
    "N": "bool",
    "J": "__int64",
    "K": "unsigned __int64",
    "W": "wchar_t",
}
# Member function access codes with no `this` qualifier: static members and
# free functions.
_NO_THIS = set("CDKLSTYZ")


class _Parser:
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.names = []  # name back-references, 0-9
        self.types = []  # argument-type back-references, 0-9

    # -- characters --
    def peek(self, n=1):
        return self.s[self.i : self.i + n]

    def take(self, n=1):
        t = self.s[self.i : self.i + n]
        if len(t) < n:
            raise ValueError(f"ran out at {self.i} in {self.s!r}")
        self.i += n
        return t

    def expect(self, text):
        if self.take(len(text)) != text:
            raise ValueError(f"expected {text!r} at {self.i - len(text)} in {self.s!r}")

    # -- names --
    def remember(self, name):
        if len(self.names) < 10 and name not in self.names:
            self.names.append(name)

    def fragment(self):
        """One component of a qualified name."""
        c = self.peek()
        if c.isdigit():
            self.i += 1
            return self.names[int(c)]
        if self.peek(2) == "?$":
            self.i += 2
            name = self.template()
            self.remember(name)
            return name
        end = self.s.index("@", self.i)
        name = self.s[self.i : end]
        if not name:
            raise ValueError(f"empty name at {self.i} in {self.s!r}")
        self.i = end + 1
        self.remember(name)
        return name

    def qualified(self):
        """Components innermost first, up to the terminating '@'."""
        parts = []
        while self.peek() != "@":
            parts.append(self.fragment())
        self.i += 1
        return "::".join(reversed(parts))

    def template(self):
        outer_names, outer_types = self.names, self.types
        self.names, self.types = [], []
        end = self.s.index("@", self.i)
        base = self.s[self.i : end]
        self.i = end + 1
        self.names.append(base)
        args = []
        while self.peek() != "@":
            args.append(self.template_arg())
        self.i += 1
        self.names, self.types = outer_names, outer_types
        return f"{base}<{','.join(args)}>"

    # -- template arguments --
    def number(self):
        negative = self.peek() == "?"
        if negative:
            self.i += 1
        c = self.take()
        if c.isdigit():
            value = int(c) + 1
        else:
            value = 0
            while c != "@":
                if not "A" <= c <= "P":
                    raise ValueError(f"bad number digit {c!r} in {self.s!r}")
                value = value * 16 + (ord(c) - ord("A"))
                c = self.take()
        return -value if negative else value

    def template_arg(self):
        if self.peek(2) == "$0":
            self.i += 2
            return str(self.number())
        if self.peek(2) == "$1":
            self.i += 2
            return "&" + self.symbol()
        if self.peek(2) == "$H":
            self.i += 2
            name = self.symbol()
            self.number()  # the this-adjustment
            return "&" + name
        if self.peek(3) in ("$$V", "$$Z") or self.peek(2) == "$S":
            self.i += 3 if self.peek(2) == "$$" else 2
            return ""
        return self.type()

    def symbol(self):
        """A mangled entity, ?name@scope@@<encoding>; its qualified name."""
        self.expect("?")
        name = self.qualified()
        c = self.peek()
        if c.isdigit():  # data: 0-4 storage class, then the type and its cv
            self.i += 1
            self.type()
            self.take()
        else:
            self.function(c)
        return name

    def function(self, access):
        self.i += 1
        if access not in _NO_THIS:
            self.take()  # the this-pointer's cv: A plain, B const, ...
        self.take()  # calling convention
        if self.peek() == "@":
            self.i += 1  # no return type: constructor or destructor
        else:
            if self.peek() == "?":
                self.i += 2  # a cv-qualified return by value
            self.type()
        if self.peek() == "X":
            self.i += 1
        else:
            while self.peek() not in ("@", "Z"):
                self.arg_type()
            self.i += 1
        self.expect("Z")  # no exception specification

    # -- types --
    def arg_type(self):
        c = self.peek()
        if c.isdigit():
            self.i += 1
            return self.types[int(c)]
        start = self.i
        t = self.type()
        if self.i - start > 1 and len(self.types) < 10:
            self.types.append(t)
        return t

    def type(self):
        c = self.take()
        if c in _PRIMITIVE:
            return _PRIMITIVE[c]
        if c == "_":
            d = self.take()
            if d not in _UNDERSCORE:
                raise ValueError(f"unknown type _{d} in {self.s!r}")
            return _UNDERSCORE[d]
        if c in "PQRS":  # pointer: the pointer's own cv, then the pointee's
            self.take()
            return self.type() + "*"
        if c in "AB":  # reference
            self.take()
            return self.type() + "&"
        if c in "VUT":
            return self.qualified()
        if c == "W":
            self.take()  # the enum's underlying size
            return self.qualified()
        raise ValueError(f"unknown type code {c!r} at {self.i - 1} in {self.s!r}")


def parse(decorated):
    """The undecorated name, or ValueError if the mangling is not understood."""
    for prefix in (".?AV", ".?AU", ".?AT"):
        if decorated.startswith(prefix):
            p = _Parser(decorated[len(prefix) :])
            name = p.qualified()
            break
    else:
        if decorated.startswith(".?AW4"):
            p = _Parser(decorated[5:])
            name = p.qualified()
        else:
            raise ValueError(f"not a decorated type name: {decorated!r}")
    if p.i != len(p.s):
        raise ValueError(f"trailing {p.s[p.i :]!r} in {decorated!r}")
    return name


def undecorate(decorated):
    """The undecorated name, or the decorated one if it is not understood."""
    try:
        return parse(decorated)
    except (ValueError, IndexError):
        return decorated


def template_args(name):
    """The top-level arguments of an undecorated template name."""
    start = name.find("<")
    if start < 0 or not name.endswith(">"):
        return []
    args, depth, current = [], 0, ""
    for ch in name[start + 1 : -1]:
        if ch == "," and depth == 0:
            args.append(current)
            current = ""
            continue
        depth += ch == "<"
        depth -= ch == ">"
        current += ch
    args.append(current)
    return args


def split_top(name, sep="::"):
    """A qualified name's components, not splitting inside template brackets."""
    parts, depth, current, i = [], 0, "", 0
    while i < len(name):
        if name.startswith(sep, i) and depth == 0:
            parts.append(current)
            current = ""
            i += len(sep)
            continue
        ch = name[i]
        depth += ch == "<"
        depth -= ch == ">"
        current += ch
        i += 1
    parts.append(current)
    return parts


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        print(undecorate(arg))
