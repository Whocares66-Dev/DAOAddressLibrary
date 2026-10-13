#include "daoaddr/Library.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <fstream>
#include <iterator>

namespace daoaddr
{

namespace
{

// The file, as tools/addrlib.py pack writes it. Everything little-endian.
//
//   0x00  "DAOADDR\0"
//   0x08  format, 1
//   0x0C  link stamp
//   0x10  size of image
//   0x14  entry point RVA
//   0x18  image base
//   0x1C  count: one more than the highest ID
//   0x20  reserved, 0
//   0x24  count words, the word for ID n at index n
//
// A word is kNone for an ID the build has no address for, else the RVA in
// its low 24 bits (the image is under 16 MB) and flags in its high 8.
constexpr std::array<char, 8> kMagic{'D', 'A', 'O', 'A', 'D', 'D', 'R', '\0'};
constexpr std::uint32_t kFormat = 1;
constexpr std::size_t kHeaderBytes = 0x24;
constexpr std::uint32_t kNone = 0xFFFFFFFF;
constexpr std::uint32_t kRvaMask = 0x00FFFFFF;
constexpr std::uint32_t kFlagData = 0x01000000;
constexpr std::uint32_t kFlagChanged = 0x02000000;
constexpr std::uint32_t kFlagShared = 0x04000000;
constexpr std::uint32_t kFlagAmbiguous = 0x08000000;

std::uint32_t WordAt(std::span<const std::byte> bytes, std::size_t offset)
{
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

} // namespace

std::optional<Library> Library::Parse(std::span<const std::byte> file)
{
    if (file.size() < kHeaderBytes || std::memcmp(file.data(), kMagic.data(), kMagic.size()) != 0 ||
        WordAt(file, 0x08) != kFormat)
    {
        return std::nullopt;
    }
    const std::size_t count = WordAt(file, 0x1C);
    // Exactly the words the header promises: a file cut short, or with more
    // after them, is not one this wrote.
    if ((file.size() - kHeaderBytes) / sizeof(std::uint32_t) != count ||
        (file.size() - kHeaderBytes) % sizeof(std::uint32_t) != 0)
    {
        return std::nullopt;
    }
    Library library;
    library.build_ = BuildInfo{
        .linkStamp = WordAt(file, 0x0C),
        .sizeOfImage = WordAt(file, 0x10),
        .entryPointRva = WordAt(file, 0x14),
        .imageBase = WordAt(file, 0x18),
    };
    library.words_.resize(count);
    if (count != 0)
    {
        std::memcpy(library.words_.data(), file.data() + kHeaderBytes, count * sizeof(std::uint32_t));
    }
    library.count_ = library.words_.size() - static_cast<std::size_t>(std::ranges::count(library.words_, kNone));
    return library;
}

std::optional<Library> Library::Load(const std::filesystem::path &file)
{
    std::ifstream in(file, std::ios::binary);
    if (!in)
    {
        return std::nullopt;
    }
    const std::vector<char> text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    return Parse(std::as_bytes(std::span(text)));
}

std::optional<Entry> Library::Find(Id id) const
{
    const auto index = static_cast<std::uint32_t>(id);
    if (index >= words_.size() || words_[index] == kNone)
    {
        return std::nullopt;
    }
    const std::uint32_t word = words_[index];
    return Entry{
        .rva = word & kRvaMask,
        .isData = (word & kFlagData) != 0,
        .changed = (word & kFlagChanged) != 0,
        .shared = (word & kFlagShared) != 0,
        .ambiguous = (word & kFlagAmbiguous) != 0,
    };
}

std::optional<std::uint32_t> Library::Rva(Id id) const
{
    const auto entry = Find(id);
    return entry ? std::optional(entry->rva) : std::nullopt;
}

std::optional<std::uint32_t> Library::Address(Id id) const
{
    const auto entry = Find(id);
    return entry ? std::optional(build_.imageBase + entry->rva) : std::nullopt;
}

Index::Index(const Library &library)
{
    places_.reserve(library.Size());
    for (std::uint32_t id = 0; id < library.Size(); ++id)
    {
        if (const auto rva = library.Rva(Id{id}))
        {
            places_.emplace_back(*rva, id);
        }
    }
    std::ranges::sort(places_);
}

std::optional<Index::Hit> Index::At(std::uint32_t rva) const
{
    // The first place past the RVA; the one before it is at or below.
    const auto after = std::ranges::upper_bound(places_, rva, {}, &std::pair<std::uint32_t, std::uint32_t>::first);
    if (after == places_.begin())
    {
        return std::nullopt;
    }
    // Of the IDs at that address the lowest, which sorted first among them.
    const std::uint32_t at = std::prev(after)->first;
    const auto first = std::ranges::lower_bound(places_, at, {}, &std::pair<std::uint32_t, std::uint32_t>::first);
    return Hit{.id = Id{first->second}, .offset = rva - at};
}

std::optional<std::vector<std::byte>> Retarget(std::span<const std::byte> file, const BuildInfo &build)
{
    if (!Library::Parse(file))
    {
        return std::nullopt;
    }
    std::vector<std::byte> out(file.begin(), file.end());
    const auto put = [&](std::size_t at, std::uint32_t value) { std::memcpy(&out[at], &value, sizeof value); };
    put(0x0C, build.linkStamp);
    put(0x10, build.sizeOfImage);
    put(0x14, build.entryPointRva);
    put(0x18, build.imageBase);
    return out;
}

std::string FileName(const BuildInfo &build)
{
    return std::format("daoaddresses-{:08x}-{:08x}-{:08x}-{:08x}.bin", build.linkStamp, build.sizeOfImage,
                       build.entryPointRva, build.imageBase);
}

} // namespace daoaddr
