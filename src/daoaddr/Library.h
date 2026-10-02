// The address library as a program reads it: one build's file, which says
// where each ID is in that build of DAOrigins.exe.
//
// An ID is a number for a function or a global of the game, given once
// (data/addresses.csv, tools/addrlib.py). It names the thing, not a place:
// each build's linker put it somewhere else, and a build may lack it. A
// program holds IDs and, at start-up, loads the file for the game it finds
// itself in, so a build of the game it has never seen needs a new file and
// nothing rebuilt:
//
//   const BuildInfo build = /* the running exe's four PE header fields */;
//   const auto library = daoaddr::Library::Load(folder / daoaddr::FileName(build));
//   if (!library) { /* no file for this build: touch nothing */ }
//   const auto rva = library->Rva(daoaddr::Id{10547});   // CClientExoApp::SetPaused
//
// and, going the other way, to name an address in a log or a crash:
//
//   const daoaddr::Index index{*library};
//   const auto hit = index.At(rva);   // the ID at or below it, and how far past
//
// The file is the table's column for the build (tools/addrlib.py pack): a
// header, then a 32-bit word per ID from 0 to the highest, at the ID's own
// index. It is small enough to read whole (about 420 KB).
//
// Nothing here touches the process or the operating system: bytes in,
// answers out, and a file that is not one, or is cut short, or is of a
// format this does not read, gives nothing rather than garbage.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace daoaddr
{

// A function's or a global's number. Its own type, so an address cannot be
// passed where an ID is wanted, nor an ID used as an address.
enum class Id : std::uint32_t
{
};

// What identifies the build a file is for, from its headers as they are in
// memory: the same four numbers a program reads from the running exe.
struct BuildInfo
{
    std::uint32_t linkStamp = 0;     // IMAGE_FILE_HEADER::TimeDateStamp
    std::uint32_t sizeOfImage = 0;   // IMAGE_OPTIONAL_HEADER::SizeOfImage
    std::uint32_t entryPointRva = 0; // IMAGE_OPTIONAL_HEADER::AddressOfEntryPoint
    std::uint32_t imageBase = 0;     // IMAGE_OPTIONAL_HEADER::ImageBase, the preferred base

    friend bool operator==(const BuildInfo &, const BuildInfo &) = default;
};

// Where an ID is in the build, and what the table notes about it there.
struct Entry
{
    std::uint32_t rva = 0; // from the image's base
    bool isData = false;   // a global; otherwise code
    // The function is not the same code as in the build its ID came from: a
    // detour at its start still catches it, but an offset into it, or a
    // field offset read out of it, is that other build's.
    bool changed = false;
    // Other IDs are at this address too: the linker made one function of
    // several with the same code, so a detour here catches all their calls.
    bool shared = false;
    // The build has several functions with this code where the ID's own
    // build had one, and this is the one most referred to.
    bool ambiguous = false;

    friend bool operator==(const Entry &, const Entry &) = default;
};

class Library
{
  public:
    // A file's bytes as a library; nothing if they are not one. The bytes
    // are copied: they need not outlive the call.
    static std::optional<Library> Parse(std::span<const std::byte> file);
    // The same from a file on disk; nothing if it cannot be read.
    static std::optional<Library> Load(const std::filesystem::path &file);

    // The build the file is for.
    const BuildInfo &Build() const
    {
        return build_;
    }

    // One more than the highest ID the file knows of, in any build.
    std::size_t Size() const
    {
        return words_.size();
    }
    // How many IDs this build has an address for.
    std::size_t Count() const
    {
        return count_;
    }

    // Where an ID is in this build; nothing if the build lacks it, or the
    // file is older than the ID.
    std::optional<Entry> Find(Id id) const;
    // Its RVA alone, and its address at the image's preferred base.
    std::optional<std::uint32_t> Rva(Id id) const;
    std::optional<std::uint32_t> Address(Id id) const;

  private:
    BuildInfo build_;
    std::vector<std::uint32_t> words_; // by ID: flags in the high 8 bits, the RVA in the low 24, or kNone
    std::size_t count_ = 0;
};

// A library read the other way: from a place in the image to the ID there.
// Built once from a library, which it does not keep.
class Index
{
  public:
    explicit Index(const Library &library);

    struct Hit
    {
        Id id{};
        std::uint32_t offset = 0; // how far past the ID's own address
    };
    // The ID at an RVA, or the nearest below it, with the distance: a
    // return address is its function's ID and an offset. Where IDs share
    // an address, the lowest. Nothing below the first ID. The caller says
    // how far past is still the same thing; the index does not know where a
    // function ends.
    std::optional<Hit> At(std::uint32_t rva) const;

  private:
    std::vector<std::pair<std::uint32_t, std::uint32_t>> places_; // (rva, id), sorted
};

// All four PE fields: Steam and GOG have the same link stamp. Check that
// the loaded Library::Build() equals the requested build before using it.
// There was an overload taking the link stamp alone, for the names GOG's
// and EA's first files had (daoaddresses-4eb19d53.bin); it and those files
// went on 2026-10-02, so that nothing can ask for a file no longer written.
std::string FileName(const BuildInfo &build);

} // namespace daoaddr
