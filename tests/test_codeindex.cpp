#include "daoaddr/CodeIndex.h"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>
#include <vector>

using daoaddr::BuildInfo;
using daoaddr::CodeIndex;
using daoaddr::CodeRange;

namespace
{

std::vector<std::byte> Bytes(std::string_view text)
{
    const auto *first = reinterpret_cast<const std::byte *>(text.data());
    return {first, first + text.size()};
}

std::string HexOf(std::string_view text)
{
    return daoaddr::ToHex(daoaddr::Sha256(Bytes(text)));
}

constexpr BuildInfo kGog{
    .linkStamp = 0x4eb19d53, .sizeOfImage = 0x9ec0a2, .entryPointRva = 0x4e3024, .imageBase = 0x400000};
constexpr BuildInfo kEa{
    .linkStamp = 0x52164c37, .sizeOfImage = 0x96b000, .entryPointRva = 0x1000, .imageBase = 0x400000};

// "abc" is 3 bytes of code at 0x1000, "abcd" 4 of it, and what the second build has is another's.
std::string Index()
{
    return "DAOCODE 1\n"
           "00001000 00000003 " +
           HexOf("abc") +
           " 4eb19d53 009ec0a2 004e3024 00400000 gog\n"
           "00001000 00000004 " +
           HexOf("abcd") +
           " 52164c37 0096b000 00001000 00400000 ea\n"
           "00001000 00000003 " +
           HexOf("xyz") + " 4eb19d53 00a49000 009ed2ee 00400000 other\n";
}

} // namespace

TEST_CASE("SHA-256 is the standard's")
{
    // FIPS 180-2's examples: the empty message, one block, and a message whose padding needs a second.
    CHECK(HexOf("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(HexOf("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(HexOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    // 55 and 56 bytes are where the length no longer fits the block.
    CHECK(HexOf(std::string(55, 'a')) == "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    CHECK(HexOf(std::string(56, 'a')) == "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    CHECK(HexOf(std::string(64, 'a')) == "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
}

TEST_CASE("code is matched to the build that has it, by its range and its hash")
{
    const auto index = CodeIndex::Parse(Index());
    REQUIRE(index.has_value());
    CHECK(index->Size() == 3);
    // Two distinct lengths, in the order the file has them.
    CHECK(index->Ranges() == std::vector<CodeRange>{{0x1000, 3}, {0x1000, 4}});

    CHECK(index->Match({0x1000, 3}, Bytes("abc")) == kGog);
    CHECK(index->Match({0x1000, 4}, Bytes("abcd")) == kEa);
}

TEST_CASE("code that is nobody's, or the wrong length, or in the wrong place, matches nothing")
{
    const auto index = CodeIndex::Parse(Index());
    REQUIRE(index.has_value());
    CHECK_FALSE(index->Match({0x1000, 3}, Bytes("abd")).has_value());
    CHECK_FALSE(index->Match({0x1000, 3}, Bytes("abcd")).has_value());
    CHECK_FALSE(index->Match({0x2000, 3}, Bytes("abc")).has_value());
    // The bytes of the other range's build, under the first's range.
    CHECK_FALSE(index->Match({0x1000, 4}, Bytes("abc ")).has_value());
}

TEST_CASE("the first build that has a code answers for it")
{
    // The same code twice, as the file never has it (pack keeps the first), would give the first.
    const std::string text = "DAOCODE 1\n"
                             "00001000 00000003 " +
                             HexOf("abc") +
                             " 4eb19d53 009ec0a2 004e3024 00400000 gog\n"
                             "00001000 00000003 " +
                             HexOf("abc") + " 4eb19d53 00a49000 009ed2ee 00400000 steam\n";
    const auto index = CodeIndex::Parse(text);
    REQUIRE(index.has_value());
    CHECK(index->Match({0x1000, 3}, Bytes("abc")) == kGog);
}

TEST_CASE("text that is not an index gives nothing")
{
    CHECK_FALSE(CodeIndex::Parse("").has_value());
    CHECK_FALSE(CodeIndex::Parse("DAOCODE 2\n").has_value());
    CHECK_FALSE(CodeIndex::Parse("not an index\n").has_value());
    const std::string good = "00001000 00000003 " + HexOf("abc") + " 4eb19d53 009ec0a2 004e3024 00400000 gog\n";
    CHECK(CodeIndex::Parse("DAOCODE 1\n" + good).has_value());
    CHECK(CodeIndex::Parse("DAOCODE 1\r\n" + good).has_value());
    // The head and no code is an index of none.
    CHECK(CodeIndex::Parse("DAOCODE 1\n")->Size() == 0);
    // A line that does not read spoils the file: it is not one this wrote.
    CHECK_FALSE(CodeIndex::Parse("DAOCODE 1\n" + good + "00001000 3\n").has_value());
    CHECK_FALSE(
        CodeIndex::Parse("DAOCODE 1\n00001000 00000003 abcd 4eb19d53 009ec0a2 004e3024 00400000 gog\n").has_value());
    CHECK_FALSE(
        CodeIndex::Parse("DAOCODE 1\n00001000 0000000g " + HexOf("abc") + " 4eb19d53 009ec0a2 004e3024 00400000 gog\n")
            .has_value());
    CHECK_FALSE(
        CodeIndex::Parse("DAOCODE 1\n00001000 00000000 " + HexOf("abc") + " 4eb19d53 009ec0a2 004e3024 00400000 gog\n")
            .has_value());
    CHECK_FALSE(CodeIndex::Load("no such file.index").has_value());
}

TEST_CASE("the index packed from the table names GOG's code, which Steam's unpacked image shares")
{
    const auto index = CodeIndex::Load(std::filesystem::path(DAOADDR_DATA_DIR) / daoaddr::CodeIndexFileName());
    REQUIRE(index.has_value());
    // GOG's and Steam's unpacked code are one line, EA's another (data/builds.csv).
    CHECK(index->Size() == 2);
    CHECK(index->Ranges().size() == 2);
    CHECK(index->Ranges().front() == CodeRange{0x1000, 0x6d86aa});
}
