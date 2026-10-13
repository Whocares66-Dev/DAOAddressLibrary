#include "daoaddr/CodeIndex.h"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cstring>
#include <fstream>
#include <iterator>

namespace daoaddr
{

namespace
{

constexpr std::string_view kHead = "DAOCODE 1";

constexpr std::array<std::uint32_t, 64> kRound{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// One 64-byte block into the state.
void Block(std::array<std::uint32_t, 8> &state, const std::uint8_t *block)
{
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i)
    {
        w[i] = (std::uint32_t{block[i * 4]} << 24) | (std::uint32_t{block[(i * 4) + 1]} << 16) |
               (std::uint32_t{block[(i * 4) + 2]} << 8) | std::uint32_t{block[(i * 4) + 3]};
    }
    for (std::size_t i = 16; i < 64; ++i)
    {
        const std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = state;
    for (std::size_t i = 0; i < 64; ++i)
    {
        const std::uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const std::uint32_t choose = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + s1 + choose + kRound[i] + w[i];
        const std::uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// A token of a line as a number in hex: all of it, and nothing else.
std::optional<std::uint32_t> Hex32(std::string_view token)
{
    std::uint32_t value = 0;
    const auto [end, error] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (error != std::errc{} || end != token.data() + token.size())
    {
        return std::nullopt;
    }
    return value;
}

std::optional<Sha256Digest> DigestOf(std::string_view hex)
{
    Sha256Digest digest{};
    if (hex.size() != digest.size() * 2)
    {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < digest.size(); ++i)
    {
        unsigned value = 0;
        const auto [end, error] = std::from_chars(hex.data() + (i * 2), hex.data() + (i * 2) + 2, value, 16);
        if (error != std::errc{} || end != hex.data() + (i * 2) + 2)
        {
            return std::nullopt;
        }
        digest[i] = static_cast<std::uint8_t>(value);
    }
    return digest;
}

// The line's fields, split at spaces: rva, length, hash, the build's four fields, its key.
std::vector<std::string_view> Fields(std::string_view line)
{
    std::vector<std::string_view> out;
    while (!line.empty())
    {
        const auto end = std::min(line.find(' '), line.size());
        if (end != 0)
        {
            out.push_back(line.substr(0, end));
        }
        line.remove_prefix(std::min(end + 1, line.size()));
    }
    return out;
}

} // namespace

Sha256Digest Sha256(std::span<const std::byte> data)
{
    std::array<std::uint32_t, 8> state{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(data.data());
    const std::size_t whole = data.size() / 64;
    for (std::size_t i = 0; i < whole; ++i)
    {
        Block(state, bytes + (i * 64));
    }
    // What is left, a 1 bit, zeros, and the length in bits: one block, or two when the length does not fit.
    std::array<std::uint8_t, 128> tail{};
    const std::size_t rest = data.size() - (whole * 64);
    if (rest != 0)
    {
        std::memcpy(tail.data(), bytes + (whole * 64), rest);
    }
    tail[rest] = 0x80;
    const std::size_t used = rest + 1 + 8 <= 64 ? 64 : 128;
    const std::uint64_t bits = static_cast<std::uint64_t>(data.size()) * 8;
    for (std::size_t i = 0; i < 8; ++i)
    {
        tail[used - 1 - i] = static_cast<std::uint8_t>(bits >> (i * 8));
    }
    for (std::size_t at = 0; at < used; at += 64)
    {
        Block(state, tail.data() + at);
    }
    Sha256Digest digest{};
    for (std::size_t i = 0; i < state.size(); ++i)
    {
        digest[(i * 4)] = static_cast<std::uint8_t>(state[i] >> 24);
        digest[(i * 4) + 1] = static_cast<std::uint8_t>(state[i] >> 16);
        digest[(i * 4) + 2] = static_cast<std::uint8_t>(state[i] >> 8);
        digest[(i * 4) + 3] = static_cast<std::uint8_t>(state[i]);
    }
    return digest;
}

std::string ToHex(const Sha256Digest &digest)
{
    constexpr std::string_view kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (const std::uint8_t byte : digest)
    {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0xF]);
    }
    return out;
}

std::string_view CodeIndexFileName()
{
    return "daoaddresses-code.index";
}

std::optional<CodeIndex> CodeIndex::Parse(std::string_view text)
{
    CodeIndex index;
    bool headed = false;
    while (!text.empty())
    {
        const auto end = std::min(text.find('\n'), text.size());
        std::string_view line = text.substr(0, end);
        text.remove_prefix(std::min(end + 1, text.size()));
        if (!line.empty() && line.back() == '\r')
        {
            line.remove_suffix(1);
        }
        if (line.empty())
        {
            continue;
        }
        if (!headed)
        {
            if (line != kHead)
            {
                return std::nullopt;
            }
            headed = true;
            continue;
        }
        const auto fields = Fields(line);
        if (fields.size() != 8)
        {
            return std::nullopt;
        }
        const auto rva = Hex32(fields[0]);
        const auto length = Hex32(fields[1]);
        const auto hash = DigestOf(fields[2]);
        const auto stamp = Hex32(fields[3]);
        const auto size = Hex32(fields[4]);
        const auto entry = Hex32(fields[5]);
        const auto base = Hex32(fields[6]);
        if (!rva || !length || !hash || !stamp || !size || !entry || !base || *length == 0)
        {
            return std::nullopt;
        }
        const CodeRange range{.rva = *rva, .length = *length};
        index.rows_.push_back(
            Row{.range = range,
                .hash = *hash,
                .build =
                    BuildInfo{.linkStamp = *stamp, .sizeOfImage = *size, .entryPointRva = *entry, .imageBase = *base}});
        if (std::ranges::find(index.ranges_, range) == index.ranges_.end())
        {
            index.ranges_.push_back(range);
        }
    }
    if (!headed)
    {
        return std::nullopt;
    }
    return index;
}

std::optional<CodeIndex> CodeIndex::Load(const std::filesystem::path &file)
{
    std::ifstream in(file, std::ios::binary);
    if (!in)
    {
        return std::nullopt;
    }
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    return Parse(text);
}

std::optional<BuildInfo> CodeIndex::Match(const CodeRange &range, std::span<const std::byte> code) const
{
    if (code.size() != range.length)
    {
        return std::nullopt;
    }
    const Sha256Digest hash = Sha256(code);
    const auto row = std::ranges::find_if(rows_, [&](const Row &r) { return r.range == range && r.hash == hash; });
    return row != rows_.end() ? std::optional(row->build) : std::nullopt;
}

} // namespace daoaddr
