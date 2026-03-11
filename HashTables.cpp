#include "HashCommon.h"

#include "UserChoiceLatestHashTables.inc"

namespace UserChoiceLatestHash
{
const U64 kRepeatSentinel = 0xFBFFFFFFFFFFFFFFULL;
const U64 kRepeatTokenA = 0xFE00000000000000ULL;
const U64 kRepeatTokenB = 0xFE00800000000000ULL;
const U64 kRepeatTokenC = 0xFF00000000000000ULL;
const U64 kRepeatTokenD = 0xFE007DFFFFFFFFFFULL;
const U64 kRepeatTokenE = 0xFE00801F7FFFFFFFULL;
const U32 kSeenModulo = 0x2803U;
const U32 kSeenQwordCount = 161U;

static const U8 kProvidedSeedABytes[16] =
{
    0x00, 0x00, 0xFB, 0x69, 0x95, 0xA3, 0xF8, 0x79,
    0x25, 0xEC, 0xE8, 0x3C, 0x05, 0x96, 0xFA, 0x10
};

static const U8 kProvidedSeedBBytes[16] =
{
    0x6D, 0xB9, 0xCE, 0x12, 0x00, 0x00, 0x89, 0x2B,
    0x00, 0x00, 0x9F, 0x5B, 0x01, 0x69, 0x7C, 0x2C
};

DebugData::DebugData()
{
    ZeroMemory(md5_words, sizeof(md5_words));
    ZeroMemory(pair_a, sizeof(pair_a));
    ZeroMemory(pair_b, sizeof(pair_b));
}

EncoderState::EncoderState()
    : entries(4096U, 0ULL),
      count(1ULL),
      last(kRepeatSentinel),
      repeat(0U),
      total_units(0U)
{
    ZeroMemory(seen, sizeof(seen));
    entries[0] = 0ULL;
}

U32 ReadLe32(const U8 *bytes)
{
    return static_cast<U32>(bytes[0])
         | (static_cast<U32>(bytes[1]) << 8)
         | (static_cast<U32>(bytes[2]) << 16)
         | (static_cast<U32>(bytes[3]) << 24);
}

static int HexNibble(wchar_t ch)
{
    if (ch >= L'0' && ch <= L'9')
    {
        return ch - L'0';
    }
    if (ch >= L'a' && ch <= L'f')
    {
        return ch - L'a' + 10;
    }
    if (ch >= L'A' && ch <= L'F')
    {
        return ch - L'A' + 10;
    }
    return -1;
}

bool ParseHexBytes(const wchar_t *text, std::vector<U8> *out)
{
    if (text == NULL || out == NULL)
    {
        return false;
    }

    const size_t len = wcslen(text);
    if ((len & 1U) != 0U)
    {
        return false;
    }

    out->assign(len / 2U, 0U);
    for (size_t i = 0U; i < len; i += 2U)
    {
        const int hi = HexNibble(text[i]);
        const int lo = HexNibble(text[i + 1U]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        (*out)[i / 2U] = static_cast<U8>((hi << 4) | lo);
    }
    return true;
}

bool ParseHexSeed128(const wchar_t *text, U32 out[4])
{
    std::vector<U8> bytes;
    if (!ParseHexBytes(text, &bytes) || bytes.size() != 16U)
    {
        return false;
    }

    for (size_t i = 0U; i < 4U; ++i)
    {
        out[i] = ReadLe32(&bytes[i * 4U]);
    }
    return true;
}

static void LoadSeedWords(const U8 bytes[16], U32 out[4])
{
    for (size_t i = 0U; i < 4U; ++i)
    {
        out[i] = ReadLe32(bytes + (i * 4U));
    }
}

void LoadProvidedSeeds(WorkingSeeds *out)
{
    LoadSeedWords(kProvidedSeedABytes, out->a);
    LoadSeedWords(kProvidedSeedBBytes, out->b);
}

std::wstring ToLowerWide(const std::wstring &value)
{
    std::wstring lowered(value);
    for (size_t i = 0; i < lowered.size(); ++i)
    {
        lowered[i] = static_cast<wchar_t>(towlower(lowered[i]));
    }
    return lowered;
}

static void DecodeHexLiteral(const char *hex, std::vector<U8> *out)
{
    const size_t len = strlen(hex);
    out->assign(len / 2U, 0U);
    for (size_t i = 0U; i < len; i += 2U)
    {
        const char a = hex[i];
        const char b = hex[i + 1U];
        const int hi = (a >= '0' && a <= '9') ? (a - '0') : ((a | 32) - 'a' + 10);
        const int lo = (b >= '0' && b <= '9') ? (b - '0') : ((b | 32) - 'a' + 10);
        (*out)[i / 2U] = static_cast<U8>((hi << 4) | lo);
    }
}

const Tables &GetTables()
{
    static Tables tables;
    static bool initialized = false;
    if (!initialized)
    {
        DecodeHexLiteral(kTokenRegionHex, &tables.token_region);
        DecodeHexLiteral(kLongRewindTableHex, &tables.long_rewind_table);
        DecodeHexLiteral(kFallbackTokenCodeTableHex, &tables.fallback_token_code_table);
        DecodeHexLiteral(kByteClassTableHex, &tables.byte_class_table);
        DecodeHexLiteral(kTokenBitWidthTableHex, &tables.token_bit_width_table);
        DecodeHexLiteral(kShortRewindTableHex, &tables.short_rewind_table);
        initialized = true;
    }
    return tables;
}
} // namespace UserChoiceLatestHash

