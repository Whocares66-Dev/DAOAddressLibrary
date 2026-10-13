// Which build's file an executable belongs to by its code, whatever its headers say
// (DAOLib #110, DAOAddressLibrary #1).
//
// A build is found first by its four header fields (Library.h, FileName). A repack of the game
// that leaves the code alone and changes the headers (Steamless' output, the Nexus "decrypted
// Steam" exe, a 4GB patch that also drops the relocations) has no file by that name, and its IDs
// are still where a known build's are: an ID depends on the code, and code that is the same at
// the same base has the same data addresses, since the code holds them. So the code index, one
// file beside the build files (tools/addrlib.py pack), says what the code of each known build
// hashes to:
//
//   const auto index = daoaddr::CodeIndex::Load(folder / daoaddr::CodeIndexFileName());
//   for (const auto &range : index->Ranges())
//   {
//       /* read range.length bytes of the exe's file at range.rva, never of its memory, where
//          a loader's own hooks are */
//       if (const auto build = index->Match(range, bytes)) { /* read FileName(*build) */ }
//   }
//
// The code of an exe that is wrapped, as stock Steam's and EA's are, is encrypted on disk and
// hashes to nothing here; those are found by their headers, which come first.
//
// Nothing here touches the process or the operating system: bytes in, answers out.
#pragma once

#include "daoaddr/Library.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace daoaddr
{

using Sha256Digest = std::array<std::uint8_t, 32>;

// The SHA-256 of bytes.
Sha256Digest Sha256(std::span<const std::byte> data);
// A digest as 64 lower-case hex digits, the form data/builds.csv holds it in.
std::string ToHex(const Sha256Digest &digest);

// A run of an image's bytes: where the code of a build is, from the image's base.
struct CodeRange
{
    std::uint32_t rva = 0;
    std::uint32_t length = 0;

    friend bool operator==(const CodeRange &, const CodeRange &) = default;
};

// The code index file's name, beside the build files.
std::string_view CodeIndexFileName();

class CodeIndex
{
  public:
    // The file's text as an index; nothing if it is not one. A line that does not read is a
    // fault in the whole file, not a line to skip.
    static std::optional<CodeIndex> Parse(std::string_view text);
    // The same from a file on disk; nothing if it cannot be read.
    static std::optional<CodeIndex> Load(const std::filesystem::path &file);

    // The distinct ranges the index holds hashes of, to read from an exe and Match: one for
    // each code length of the known builds, nearly always one in all.
    const std::vector<CodeRange> &Ranges() const
    {
        return ranges_;
    }
    // How many distinct codes it names a build for.
    std::size_t Size() const
    {
        return rows_.size();
    }

    // The build whose code these bytes are, the first of the builds that have it; nothing if
    // they are no known build's, or are not `range.length` bytes. Read FileName() of it, and
    // check the file's header says the same, as for any file.
    std::optional<BuildInfo> Match(const CodeRange &range, std::span<const std::byte> code) const;

  private:
    struct Row
    {
        CodeRange range;
        Sha256Digest hash{};
        BuildInfo build;
    };
    std::vector<Row> rows_;
    std::vector<CodeRange> ranges_;
};

} // namespace daoaddr
