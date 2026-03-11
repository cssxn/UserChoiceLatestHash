#include "HashCommon.h"

namespace
{
const wchar_t *kSalt3822 =
    L"Copyright (C) Microsoft. All rights reserved {3822B7CA-C2F4-4889-B8CC-4CE39A8FB81C}";
const wchar_t *kSalt97B6 =
    L"Copyright (C) Microsoft. All rights reserved {97B6BCF4-C367-4577-95BE-73BD3053A5E0}";
const wchar_t *kSaltD185 =
    L"Copyright (C) Microsoft. All rights reserved {D185E0A1-E265-4724-AA21-3A17B038D72E}";

bool QueryRegString(HKEY root, const std::wstring &subkey, const wchar_t *value_name, std::wstring *out)
{
    HKEY key = NULL;
    DWORD type = 0;
    DWORD size = 0;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    {
        return false;
    }

    LONG rc = RegQueryValueExW(key, value_name, NULL, &type, NULL, &size);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        RegCloseKey(key);
        return false;
    }

    std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1U, L'\0');
    rc = RegQueryValueExW(key,
                          value_name,
                          NULL,
                          &type,
                          reinterpret_cast<BYTE *>(&buffer[0]),
                          &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS)
    {
        return false;
    }

    *out = &buffer[0];
    return true;
}

bool QueryRegLastWriteTime(HKEY root, const std::wstring &subkey, FILETIME *out)
{
    if (out == NULL)
    {
        return false;
    }

    HKEY key = NULL;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    {
        return false;
    }

    const LONG rc = RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, out);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

bool GetCurrentUserSidString(std::wstring *out)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        return false;
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    std::vector<BYTE> buffer(size, 0U);
    if (!GetTokenInformation(token, TokenUser, &buffer[0], size, &size))
    {
        CloseHandle(token);
        return false;
    }

    TOKEN_USER *user = reinterpret_cast<TOKEN_USER *>(&buffer[0]);
    LPWSTR sid_text = NULL;
    const BOOL ok = ConvertSidToStringSidW(user->User.Sid, &sid_text);
    CloseHandle(token);
    if (!ok || sid_text == NULL)
    {
        return false;
    }

    *out = sid_text;
    LocalFree(sid_text);
    return true;
}

std::wstring StripOuterBraces(const std::wstring &value)
{
    if (value.size() >= 2U && value[0] == L'{' && value[value.size() - 1U] == L'}')
    {
        return value.substr(1U, value.size() - 2U);
    }
    return value;
}

bool FormatTimestampHexFromFileTime(const FILETIME &last_write, std::wstring *out)
{
    SYSTEMTIME st;
    FILETIME normalized;
    if (!FileTimeToSystemTime(&last_write, &st) || !SystemTimeToFileTime(&st, &normalized))
    {
        return false;
    }

    wchar_t buffer[17];
    swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]), L"%08x%08x", normalized.dwHighDateTime, normalized.dwLowDateTime);
    *out = buffer;
    return true;
}

const wchar_t *PrimarySaltForClass(int mod_class)
{
    if (mod_class == 0)
    {
        return kSalt3822;
    }
    if (mod_class == 1)
    {
        return kSalt97B6;
    }
    return kSaltD185;
}

const wchar_t *AlternateSaltForClass(int mod_class)
{
    if (mod_class == 1)
    {
        return kSaltD185;
    }
    if (mod_class == 2)
    {
        return kSalt97B6;
    }
    return NULL;
}

std::wstring BuildCanonicalInput(const UserChoiceLatestHash::AssocContext &ctx, const wchar_t *salt)
{
    std::wstring result;
    if (ctx.mod_class == 0)
    {
        result += salt;
        result += ctx.assoc;
        result += ctx.timestamp_hex;
        result += ctx.machine_id_trimmed;
        result += ctx.progid;
        result += ctx.sid;
    }
    else if (ctx.mod_class == 1)
    {
        result += salt;
        result += ctx.timestamp_hex;
        result += ctx.assoc;
        result += ctx.sid;
        result += ctx.machine_id_trimmed;
        result += ctx.progid;
    }
    else
    {
        result += ctx.sid;
        result += ctx.timestamp_hex;
        result += salt;
        result += ctx.assoc;
        result += ctx.machine_id_trimmed;
        result += ctx.progid;
    }
    return result;
}

bool LoadAssociationContext(const std::wstring &assoc, UserChoiceLatestHash::AssocContext *ctx)
{
    ctx->assoc = assoc;
    ctx->alternate_used = false;
    ctx->mod_class = -1;

    if (!QueryRegString(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\SQMClient",
                        L"MachineID",
                        &ctx->machine_id_raw))
    {
        return false;
    }
    ctx->machine_id_trimmed = StripOuterBraces(ctx->machine_id_raw);
    if (ctx->machine_id_trimmed.empty() || !GetCurrentUserSidString(&ctx->sid))
    {
        return false;
    }

    const bool is_extension = !assoc.empty() && assoc[0] == L'.';
    const std::wstring prefix = is_extension
        ? L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\"
        : L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\";
    const std::wstring base = prefix + assoc;
    const wchar_t *choices[2] = { L"UserChoiceLatest", L"UserChoice" };

    size_t index = 0U;
    for (; index < 2U; ++index)
    {
        std::wstring choice_key = base + L"\\" + choices[index];
        if (QueryRegString(HKEY_CURRENT_USER, choice_key, L"Hash", &ctx->registry_hash))
        {
            ctx->base_key = base;
            ctx->choice_name = choices[index];
            break;
        }
    }
    if (index == 2U)
    {
        return false;
    }

    const std::wstring progid_key = ctx->base_key + L"\\" + ctx->choice_name + L"\\ProgId";
    if (!QueryRegString(HKEY_CURRENT_USER, progid_key, L"ProgId", &ctx->progid)
        && !QueryRegString(HKEY_CURRENT_USER, ctx->base_key + L"\\" + ctx->choice_name, L"ProgId", &ctx->progid))
    {
        return false;
    }

    FILETIME last_write;
    if (!QueryRegLastWriteTime(HKEY_CURRENT_USER, progid_key, &last_write)
        && !QueryRegLastWriteTime(HKEY_CURRENT_USER, ctx->base_key + L"\\" + ctx->choice_name, &last_write))
    {
        return false;
    }

    if (!FormatTimestampHexFromFileTime(last_write, &ctx->timestamp_hex))
    {
        return false;
    }

    ctx->mod_class = static_cast<int>(ctx->machine_id_trimmed[ctx->machine_id_trimmed.size() - 1U] % 3);
    return true;
}
} // namespace

namespace UserChoiceLatestHash
{
bool LooksLikeAssociationToken(const std::wstring &value)
{
    if (value.empty())
    {
        return false;
    }
    if (value.find(L' ') != std::wstring::npos || value.find(L'\\') != std::wstring::npos || value.find(L'/') != std::wstring::npos)
    {
        return false;
    }
    if (value[0] == L'.')
    {
        return true;
    }
    for (size_t i = 0; i < value.size(); ++i)
    {
        const wchar_t ch = value[i];
        if (!(iswalnum(ch) || ch == L'+' || ch == L'-' || ch == L'.'))
        {
            return false;
        }
    }
    return true;
}

bool VerifyCurrentAssociation(const std::wstring &assoc,
                              const UserChoiceLatestHash::WorkingSeeds &seeds,
                              AssocContext *ctx)
{
    if (!LoadAssociationContext(assoc, ctx))
    {
        return false;
    }

    ctx->canonical_primary = BuildCanonicalInput(*ctx, PrimarySaltForClass(ctx->mod_class));
    if (!UserChoiceLatestHash::ComputeHash(ctx->canonical_primary, seeds, false, &ctx->computed_primary, NULL))
    {
        return false;
    }

    const wchar_t *alternate_salt = AlternateSaltForClass(ctx->mod_class);
    if (alternate_salt != NULL)
    {
        ctx->canonical_alternate = BuildCanonicalInput(*ctx, alternate_salt);
        UserChoiceLatestHash::ComputeHash(ctx->canonical_alternate, seeds, false, &ctx->computed_alternate, NULL);
        if (_wcsicmp(ctx->registry_hash.c_str(), ctx->computed_alternate.c_str()) == 0)
        {
            ctx->alternate_used = true;
        }
    }

    return true;
}

int PrintVerificationResult(const AssocContext &ctx)
{
    const std::wstring &effective_hash =
        ctx.alternate_used ? ctx.computed_alternate : ctx.computed_primary;
    const std::wstring &effective_canonical =
        ctx.alternate_used ? ctx.canonical_alternate : ctx.canonical_primary;
    const bool match = _wcsicmp(ctx.registry_hash.c_str(), effective_hash.c_str()) == 0;

    std::wcout
        << L"assoc: " << ctx.assoc << L"\n"
        << L"choice: " << ctx.choice_name << L"\n"
        << L"progid: " << ctx.progid << L"\n"
        << L"machine_id: " << ctx.machine_id_trimmed << L"\n"
        << L"sid: " << ctx.sid << L"\n"
        << L"timestamp: " << ctx.timestamp_hex << L"\n"
        << L"registry_hash: " << ctx.registry_hash << L"\n"
        << L"computed_hash: " << effective_hash << L"\n"
        << L"mod_class: " << ctx.mod_class << L"\n"
        << L"salt_mapping: " << (ctx.alternate_used ? L"alternate" : L"primary") << L"\n"
        << L"match: " << (match ? L"true" : L"false") << L"\n"
        << L"canonical: " << effective_canonical << L"\n";

    if (!ctx.computed_alternate.empty())
    {
        std::wcout << L"computed_hash_alt: " << ctx.computed_alternate << L"\n";
    }

    return match ? 0 : 2;
}
} // namespace UserChoiceLatestHash

