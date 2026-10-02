#include "daoaddr/Library.h"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <filesystem>
#include <vector>

using daoaddr::BuildInfo;
using daoaddr::Entry;
using daoaddr::Id;
using daoaddr::Index;
using daoaddr::Library;

namespace
{

constexpr std::uint32_t kNone = 0xFFFFFFFF;

// A file as tools/addrlib.py pack writes one: the header, then a word per ID.
std::vector<std::byte> File(const BuildInfo &build, const std::vector<std::uint32_t> &words, std::uint32_t format = 1)
{
    std::vector<std::byte> file(0x24 + words.size() * 4);
    std::memcpy(file.data(), "DAOADDR", 8);
    const auto put = [&](std::size_t at, std::uint32_t value) { std::memcpy(&file[at], &value, 4); };
    put(0x08, format);
    put(0x0C, build.linkStamp);
    put(0x10, build.sizeOfImage);
    put(0x14, build.entryPointRva);
    put(0x18, build.imageBase);
    put(0x1C, static_cast<std::uint32_t>(words.size()));
    for (std::size_t i = 0; i < words.size(); ++i)
    {
        put(0x24 + i * 4, words[i]);
    }
    return file;
}

constexpr BuildInfo kBuild{
    .linkStamp = 0x4eb19d53, .sizeOfImage = 0x9ec0a2, .entryPointRva = 0x4e3024, .imageBase = 0x400000};

} // namespace

TEST_CASE("a file reads back as the build and the places it was written from")
{
    // ID 0 is no ID; 1 is code, 2 lacks an address, 3 is a global.
    const auto library = Library::Parse(File(kBuild, {kNone, 0x001000, kNone, 0x01000000 | 0x7f0000}));
    REQUIRE(library.has_value());
    CHECK(library->Build() == kBuild);
    CHECK(library->Size() == 4);
    CHECK(library->Count() == 2);

    CHECK(library->Find(Id{1}) == Entry{.rva = 0x1000});
    CHECK(library->Rva(Id{1}) == 0x1000U);
    CHECK(library->Address(Id{1}) == 0x401000U);
    CHECK(library->Find(Id{3}) == Entry{.rva = 0x7f0000, .isData = true});
    CHECK(library->Address(Id{3}) == 0xbf0000U);
}

TEST_CASE("an ID the build lacks, or the file has never heard of, is nowhere")
{
    const auto library = Library::Parse(File(kBuild, {kNone, 0x001000, kNone}));
    REQUIRE(library.has_value());
    CHECK_FALSE(library->Find(Id{0}).has_value());
    CHECK_FALSE(library->Find(Id{2}).has_value());
    CHECK_FALSE(library->Rva(Id{2}).has_value());
    CHECK_FALSE(library->Address(Id{2}).has_value());
    // A newer table has more IDs than an older file.
    CHECK_FALSE(library->Find(Id{3}).has_value());
    CHECK_FALSE(library->Find(Id{0xFFFFFFFF}).has_value());
}

TEST_CASE("what the table notes about an ID in a build comes through")
{
    const auto library = Library::Parse(
        File(kBuild, {kNone, 0x02000000 | 0x10, 0x04000000 | 0x20, 0x08000000 | 0x30, 0x0F000000 | 0x40}));
    REQUIRE(library.has_value());
    CHECK(library->Find(Id{1}) == Entry{.rva = 0x10, .changed = true});
    CHECK(library->Find(Id{2}) == Entry{.rva = 0x20, .shared = true});
    CHECK(library->Find(Id{3}) == Entry{.rva = 0x30, .ambiguous = true});
    CHECK(library->Find(Id{4}) ==
          Entry{.rva = 0x40, .isData = true, .changed = true, .shared = true, .ambiguous = true});
    // The whole of the low 24 bits is the RVA.
    const auto top = Library::Parse(File(kBuild, {kNone, 0x00FFFFFF}));
    REQUIRE(top.has_value());
    CHECK(top->Rva(Id{1}) == 0x00FFFFFFU);
}

TEST_CASE("bytes that are not a library file give nothing")
{
    CHECK_FALSE(Library::Parse({}).has_value());
    CHECK_FALSE(Library::Parse(std::vector<std::byte>(0x40, std::byte{0x41})).has_value());

    auto wrongMagic = File(kBuild, {kNone, 0x1000});
    wrongMagic[0] = std::byte{'X'};
    CHECK_FALSE(Library::Parse(wrongMagic).has_value());

    // A format this does not read, however well formed.
    CHECK_FALSE(Library::Parse(File(kBuild, {kNone, 0x1000}, 2)).has_value());

    auto cut = File(kBuild, {kNone, 0x1000, 0x2000});
    cut.resize(cut.size() - 4);
    CHECK_FALSE(Library::Parse(cut).has_value());
    cut.resize(cut.size() - 1);
    CHECK_FALSE(Library::Parse(cut).has_value());

    auto longer = File(kBuild, {kNone, 0x1000});
    longer.resize(longer.size() + 4);
    CHECK_FALSE(Library::Parse(longer).has_value());

    auto header = File(kBuild, {});
    header.resize(0x23);
    CHECK_FALSE(Library::Parse(header).has_value());
}

TEST_CASE("a file with no IDs is a library with none")
{
    const auto library = Library::Parse(File(kBuild, {}));
    REQUIRE(library.has_value());
    CHECK(library->Size() == 0);
    CHECK(library->Count() == 0);
    CHECK_FALSE(library->Find(Id{1}).has_value());
    CHECK_FALSE(Index{*library}.At(0x1000).has_value());
}

TEST_CASE("a file that is not there is no library")
{
    CHECK_FALSE(Library::Load(std::filesystem::path(DAOADDR_DATA_DIR) / "no-such-file.bin").has_value());
}

TEST_CASE("an address is the ID at or below it, and how far past")
{
    // Not in address order by ID, as a build linked in another order is not.
    const auto library = Library::Parse(File(kBuild, {kNone, 0x3000, 0x1000, kNone, 0x2000}));
    REQUIRE(library.has_value());
    const Index index{*library};

    const auto exact = index.At(0x2000);
    REQUIRE(exact.has_value());
    CHECK(exact->id == Id{4});
    CHECK(exact->offset == 0);

    const auto inside = index.At(0x2fff);
    REQUIRE(inside.has_value());
    CHECK(inside->id == Id{4});
    CHECK(inside->offset == 0xfff);

    const auto last = index.At(0x900000);
    REQUIRE(last.has_value());
    CHECK(last->id == Id{1});
    CHECK(last->offset == 0x900000 - 0x3000);

    CHECK_FALSE(index.At(0x0fff).has_value());
}

TEST_CASE("where IDs share an address the lowest answers for it")
{
    // The linker makes one function of several with the same code.
    const auto library = Library::Parse(File(kBuild, {kNone, 0x5000, 0x04001000, 0x04001000, 0x04001000}));
    REQUIRE(library.has_value());
    const Index index{*library};
    const auto hit = index.At(0x1008);
    REQUIRE(hit.has_value());
    CHECK(hit->id == Id{2});
    CHECK(hit->offset == 8);
}

TEST_CASE("the full fingerprint distinguishes builds sharing a link stamp")
{
    CHECK(daoaddr::FileName(kBuild) == "daoaddresses-4eb19d53-009ec0a2-004e3024-00400000.bin");
    auto other = kBuild;
    other.sizeOfImage = 0xa49000;
    other.entryPointRva = 0x9ed2ee;
    CHECK(daoaddr::FileName(other) == "daoaddresses-4eb19d53-00a49000-009ed2ee-00400000.bin");
    CHECK(daoaddr::FileName(kBuild) != daoaddr::FileName(other));
    other = kBuild;
    other.imageBase += 0x1000;
    CHECK(daoaddr::FileName(kBuild) != daoaddr::FileName(other));
}

TEST_CASE("the files packed from the table hold what the table says")
{
    // IDs are forever, so these are too. Read 2026-10-01 from the two
    // builds (dev/BUILDS.md), and each seen in play in both.
    constexpr Id kEntryPoint{25795};
    constexpr Id kSetPaused{10547};
    constexpr Id kClientExoApp{100835};

    const std::filesystem::path folder = DAOADDR_DATA_DIR;
    // The EA app's file is wrapped: the entry point in its headers is the
    // wrapper's, not the game's.
    constexpr BuildInfo kEa{
        .linkStamp = 0x52164c37, .sizeOfImage = 0x96b000, .entryPointRva = 0x1000, .imageBase = 0x400000};
    const auto gog = Library::Load(folder / daoaddr::FileName(kBuild));
    const auto ea = Library::Load(folder / daoaddr::FileName(kEa));
    // Named by link stamp alone until 2026-10-02, and GOG's is Steam's too:
    // pack writes neither now, and takes out one an earlier pack left.
    CHECK_FALSE(std::filesystem::exists(folder / "daoaddresses-4eb19d53.bin"));
    CHECK_FALSE(std::filesystem::exists(folder / "daoaddresses-52164c37.bin"));
    constexpr BuildInfo kSteam{
        .linkStamp = 0x4eb19d53, .sizeOfImage = 0xa49000, .entryPointRva = 0x9ed2ee, .imageBase = 0x400000};
    const auto steam = Library::Load(folder / daoaddr::FileName(kSteam));
    REQUIRE(gog.has_value());
    REQUIRE(ea.has_value());
    REQUIRE(steam.has_value());
    CHECK(steam->Build() == kSteam);
    CHECK(steam->Size() == gog->Size());
    CHECK(steam->Address(kEntryPoint) == 0x008E3024U);
    CHECK(steam->Address(kSetPaused) == 0x005D6740U);
    CHECK(steam->Find(kClientExoApp) == Entry{.rva = 0x8327EC, .isData = true});
    // Steam's engine sections are identical to GOG's apart from PE load
    // configuration. Every GOG ID must retain its address in Steam.
    std::size_t mismatches = 0;
    for (std::uint32_t id = 1; id < gog->Size(); ++id)
    {
        if (const auto rva = gog->Rva(Id{id}); rva && steam->Rva(Id{id}) != rva)
        {
            ++mismatches;
        }
    }
    CHECK(mismatches == 0);

    CHECK(gog->Build() == kBuild);
    CHECK(ea->Build() == kEa);
    CHECK(gog->Size() == ea->Size());
    // Each build has most of the IDs and not all: some things only one has.
    // Not the counts themselves, which grow as the table is filled.
    CHECK(gog->Count() > 100000);
    CHECK(gog->Count() < gog->Size());
    CHECK(ea->Count() > 100000);
    CHECK(ea->Count() < ea->Size());

    CHECK(gog->Address(kEntryPoint) == 0x008E3024U);
    CHECK(ea->Address(kEntryPoint) == 0x008B9584U);
    CHECK(gog->Address(kSetPaused) == 0x005D6740U);
    CHECK(ea->Address(kSetPaused) == 0x004C1770U);
    CHECK(gog->Find(kClientExoApp) == Entry{.rva = 0x8327EC, .isData = true});
    CHECK(ea->Find(kClientExoApp) == Entry{.rva = 0x81ADAC, .isData = true});

    // The return address the game's first SetPaused comes from: the same
    // function and the same distance into it in both builds.
    const auto inGog = Index{*gog}.At(0x005DD34F - 0x400000);
    const auto inEa = Index{*ea}.At(0x004C978F - 0x400000);
    REQUIRE(inGog.has_value());
    REQUIRE(inEa.has_value());
    CHECK(inGog->id == inEa->id);
    CHECK(inGog->offset == inEa->offset);
}
