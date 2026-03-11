#include "HashCommon.h"

namespace
{
void PrintUsage()
{
    std::wcerr
        << L"usage:\n"
        << L"  UserChoiceLatestHash.exe -debug <canonical_input>\n"
        << L"  UserChoiceLatestHash.exe -verify <assoc>\n";
}
} // namespace

namespace UserChoiceLatestHash
{
void PrintDebugResult(const std::wstring &hash, const DebugData &dbg)
{
    std::wcout << L"hash: " << hash << L"\n";
    std::wcout << L"packed_len_bytes: " << std::hex << (dbg.packed_words.size() * 2U) << std::dec << L"\n";
    std::wcout << L"packed: ";
    for (size_t i = 0; i < dbg.packed_words.size(); ++i)
    {
        wchar_t tmp[8];
        swprintf(tmp, 8, L"%04X", dbg.packed_words[i]);
        std::wcout << tmp;
    }
    std::wcout << L"\n";

    std::wcout << L"md5: ";
    for (size_t i = 0; i < 4U; ++i)
    {
        wchar_t tmp[16];
        swprintf(tmp, 16, L"%08X", dbg.md5_words[i]);
        std::wcout << tmp;
    }
    std::wcout << L"\n";

    std::wcout << L"A0=" << std::hex << dbg.pair_a[0]
               << L" A1=" << dbg.pair_a[1]
               << L" B0=" << dbg.pair_b[0]
               << L" B1=" << dbg.pair_b[1] << std::dec << L"\n";
}

int RunStandaloneCli(int argc, wchar_t **argv)
{
    RunMode mode = kModeVerify;
    WorkingSeeds seeds;
    ZeroMemory(&seeds, sizeof(seeds));

    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    if (wcscmp(argv[1], L"-verify") == 0)
    {
        mode = kModeVerify;
        if (argc < 3)
        {
            PrintUsage();
            return 1;
        }
    }
    else if (wcscmp(argv[1], L"-debug") == 0)
    {
        mode = kModeDebug;
        if (argc < 3)
        {
            PrintUsage();
            return 1;
        }
    }
    else
    {
        PrintUsage();
        return 1;
    }

    if (mode == kModeVerify)
    {
        LoadProvidedSeeds(&seeds);
        AssocContext ctx;
        if (!VerifyCurrentAssociation(argv[2], seeds, &ctx))
        {
            std::wcerr << L"verification context load failed\n";
            return 1;
        }
        return PrintVerificationResult(ctx);
    }

    if (mode == kModeDebug)
    {
        LoadProvidedSeeds(&seeds);
        std::wstring hash;
        DebugData dbg;
        if (!ComputeHash(argv[2], seeds, false, &hash, &dbg))
        {
            std::wcerr << L"debug hash computation failed\n";
            return 1;
        }
        PrintDebugResult(hash, dbg);
        return 0;
    }

    PrintUsage();
    return 1;
}
} // namespace UserChoiceLatestHash

