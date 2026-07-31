#include <windows.h>
#include <bcrypt.h>
#include <msi.h>
#include <msiquery.h>
#include <shlobj.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Management.Deployment.h>
#include <winrt/base.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace
{
    using winrt::Windows::ApplicationModel::Package;
    using winrt::Windows::ApplicationModel::PackageVersion;
    using winrt::Windows::Management::Deployment::DeploymentResult;
    using winrt::Windows::Management::Deployment::PackageManager;

    constexpr std::wstring_view package_name{
        L"TheUndeadMonk.Librarian.Development"};
    constexpr std::wstring_view package_publisher{
        L"CN=Librarian Development"};
    constexpr std::array<std::wstring_view, 5> payload_files{
        L"Librarian.IdentityLauncher.exe",
        L"Librarian.Windows.exe",
        L"Librarian.VaultAgent.exe",
        L"Librarian.ChromiumNativeHost.exe",
        L"Librarian.Identity.msix",
    };
    constexpr std::wstring_view payload_hash_manifest_name{
        L"Librarian.PayloadHashes"};
    constexpr std::wstring_view forbidden_provider{
        L"Librarian.PasskeyProvider.exe"};
    using sha256_digest = std::array<std::uint8_t, 32>;

    struct validation_error
    {
        std::wstring message;
    };

    struct file_handle
    {
        HANDLE value{INVALID_HANDLE_VALUE};

        file_handle() = default;

        ~file_handle()
        {
            if (value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(value);
            }
        }

        file_handle(file_handle const&) = delete;
        file_handle& operator=(file_handle const&) = delete;
    };

    struct bcrypt_algorithm_handle
    {
        BCRYPT_ALG_HANDLE value{};

        bcrypt_algorithm_handle() = default;

        ~bcrypt_algorithm_handle()
        {
            if (value != nullptr)
            {
                BCryptCloseAlgorithmProvider(value, 0);
            }
        }

        bcrypt_algorithm_handle(
            bcrypt_algorithm_handle const&) = delete;
        bcrypt_algorithm_handle& operator=(
            bcrypt_algorithm_handle const&) = delete;
    };

    struct bcrypt_hash_handle
    {
        BCRYPT_HASH_HANDLE value{};

        bcrypt_hash_handle() = default;

        ~bcrypt_hash_handle()
        {
            if (value != nullptr)
            {
                BCryptDestroyHash(value);
            }
        }

        bcrypt_hash_handle(bcrypt_hash_handle const&) = delete;
        bcrypt_hash_handle& operator=(
            bcrypt_hash_handle const&) = delete;
    };

    struct payload_hash_entry
    {
        std::filesystem::path file_name;
        sha256_digest hash{};
    };

    struct payload_manifest
    {
        PackageVersion version{};
        std::vector<payload_hash_entry> files;
    };

    struct validation_action_data
    {
        std::filesystem::path install_folder;
        PackageVersion version{};
        sha256_digest manifest_hash{};
    };

    struct wintrust_state
    {
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA data{};

        wintrust_state() = default;

        ~wintrust_state()
        {
            if (data.hWVTStateData != nullptr)
            {
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                static_cast<void>(WinVerifyTrust(
                    reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),
                    &action,
                    &data));
            }
        }

        wintrust_state(wintrust_state const&) = delete;
        wintrust_state& operator=(wintrust_state const&) = delete;
    };

    [[noreturn]] void fail(std::wstring_view message)
    {
        throw validation_error{std::wstring{message}};
    }

    void log_message(
        MSIHANDLE installer,
        INSTALLMESSAGE kind,
        std::wstring_view message)
    {
        PMSIHANDLE record = MsiCreateRecord(0);
        if (record == 0)
        {
            return;
        }

        std::wstring owned{message};
        if (MsiRecordSetStringW(record, 0, owned.c_str()) ==
            ERROR_SUCCESS)
        {
            static_cast<void>(
                MsiProcessMessage(installer, kind, record));
        }
    }

    template <typename Action>
    UINT run_action(
        MSIHANDLE installer,
        std::wstring_view label,
        Action&& action) noexcept
    {
        try
        {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
            action();
            std::wstring success{L"Librarian setup: "};
            success.append(label);
            success.append(L" succeeded.");
            log_message(installer, INSTALLMESSAGE_INFO, success);
            return ERROR_SUCCESS;
        }
        catch (winrt::hresult_error const& error)
        {
            std::wstring message{L"Librarian setup: "};
            message.append(label);
            message.append(L" failed (");
            wchar_t code[11]{};
            static_cast<void>(swprintf_s(
                code,
                L"0x%08X",
                static_cast<unsigned>(error.code().value)));
            message.append(code);
            message.append(L").");
            log_message(installer, INSTALLMESSAGE_ERROR, message);
        }
        catch (validation_error const& error)
        {
            std::wstring message{L"Librarian setup: "};
            message.append(label);
            message.append(L" failed validation: ");
            message.append(error.message);
            log_message(installer, INSTALLMESSAGE_ERROR, message);
        }
        catch (...)
        {
            std::wstring message{L"Librarian setup: "};
            message.append(label);
            message.append(L" failed unexpectedly.");
            log_message(installer, INSTALLMESSAGE_ERROR, message);
        }
        return ERROR_INSTALL_FAILURE;
    }

    void check_bcrypt(NTSTATUS status)
    {
        if (!BCRYPT_SUCCESS(status))
        {
            fail(L"Setup could not verify an installed payload hash.");
        }
    }

    std::filesystem::path current_module_path()
    {
        std::array<wchar_t, 32768U> buffer{};
        DWORD const length = GetModuleFileNameW(
            reinterpret_cast<HMODULE>(&__ImageBase),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (length == 0U || length >= buffer.size())
        {
            fail(L"Setup could not identify its validation module.");
        }
        return std::filesystem::path{
            std::wstring_view{buffer.data(), length}};
    }

    sha256_digest trusted_signer_hash(
        std::filesystem::path const& path,
        std::wstring_view failure_message)
    {
        std::wstring const native_path = path.native();
        WINTRUST_FILE_INFO file_info{};
        file_info.cbStruct = sizeof(file_info);
        file_info.pcwszFilePath = native_path.c_str();

        wintrust_state trust;
        trust.data.cbStruct = sizeof(trust.data);
        trust.data.dwUIChoice = WTD_UI_NONE;
        trust.data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust.data.dwUnionChoice = WTD_CHOICE_FILE;
        trust.data.pFile = &file_info;
        trust.data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust.data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG const status = WinVerifyTrust(
            reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),
            &trust.action,
            &trust.data);
        if (status != ERROR_SUCCESS ||
            trust.data.hWVTStateData == nullptr)
        {
            fail(failure_message);
        }

        HMODULE const wintrust = GetModuleHandleW(L"wintrust.dll");
        if (wintrust == nullptr)
        {
            fail(failure_message);
        }
        using provider_data_function =
            CRYPT_PROVIDER_DATA* (WINAPI*)(HANDLE);
        using signer_function = CRYPT_PROVIDER_SGNR* (WINAPI*)(
            CRYPT_PROVIDER_DATA*, DWORD, BOOL, DWORD);
        auto const provider_data_from_state =
            reinterpret_cast<provider_data_function>(GetProcAddress(
                wintrust,
                "WTHelperProvDataFromStateData"));
        auto const signer_from_chain =
            reinterpret_cast<signer_function>(GetProcAddress(
                wintrust,
                "WTHelperGetProvSignerFromChain"));
        if (provider_data_from_state == nullptr ||
            signer_from_chain == nullptr)
        {
            fail(failure_message);
        }

        CRYPT_PROVIDER_DATA* const provider =
            provider_data_from_state(trust.data.hWVTStateData);
        CRYPT_PROVIDER_SGNR* const signer = provider == nullptr ?
            nullptr :
            signer_from_chain(provider, 0U, FALSE, 0U);
        if (signer == nullptr || signer->csCertChain == 0U ||
            signer->pasCertChain == nullptr ||
            signer->pasCertChain[0].pCert == nullptr)
        {
            fail(failure_message);
        }

        PCCERT_CONTEXT const certificate =
            signer->pasCertChain[0].pCert;
        DWORD const subject_size = CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0U,
            nullptr,
            nullptr,
            0U);
        if (subject_size <= 1U || subject_size > 256U)
        {
            fail(failure_message);
        }
        std::vector<wchar_t> subject(subject_size);
        if (CertGetNameStringW(
                certificate,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0U,
                nullptr,
                subject.data(),
                subject_size) != subject_size ||
            std::wstring_view{subject.data()} != L"Librarian Development")
        {
            fail(failure_message);
        }

        DWORD usage_size = 0U;
        if (!CertGetEnhancedKeyUsage(
                certificate,
                0U,
                nullptr,
                &usage_size) &&
            GetLastError() != CRYPT_E_NOT_FOUND)
        {
            fail(failure_message);
        }
        if (usage_size == 0U || usage_size > 4096U)
        {
            fail(failure_message);
        }
        std::vector<std::uint8_t> usage_buffer(usage_size);
        auto* const usages = reinterpret_cast<PCERT_ENHKEY_USAGE>(
            usage_buffer.data());
        if (!CertGetEnhancedKeyUsage(
                certificate,
                0U,
                usages,
                &usage_size))
        {
            fail(failure_message);
        }
        bool code_signing = false;
        for (DWORD index = 0U; index < usages->cUsageIdentifier; ++index)
        {
            if (std::string_view{usages->rgpszUsageIdentifier[index]} ==
                szOID_PKIX_KP_CODE_SIGNING)
            {
                code_signing = true;
                break;
            }
        }
        if (!code_signing)
        {
            fail(failure_message);
        }

        sha256_digest digest{};
        DWORD digest_size = static_cast<DWORD>(digest.size());
        if (!CertGetCertificateContextProperty(
                certificate,
                CERT_SHA256_HASH_PROP_ID,
                digest.data(),
                &digest_size) ||
            digest_size != digest.size())
        {
            fail(failure_message);
        }
        return digest;
    }

    std::wstring get_property(
        MSIHANDLE installer,
        wchar_t const* name)
    {
        DWORD characters = 0U;
        wchar_t empty[1]{};
        UINT const size_result =
            MsiGetPropertyW(installer, name, empty, &characters);
        if (size_result != ERROR_MORE_DATA &&
            size_result != ERROR_SUCCESS)
        {
            fail(
                L"Windows Installer could not read required custom-action "
                L"data.");
        }

        std::wstring value(
            static_cast<std::size_t>(characters) + 1U,
            L'\0');
        DWORD capacity = characters + 1U;
        UINT const read_result = MsiGetPropertyW(
            installer,
            name,
            value.data(),
            &capacity);
        if (read_result != ERROR_SUCCESS)
        {
            fail(
                L"Windows Installer could not read required custom-action "
                L"data.");
        }
        value.resize(capacity);
        return value;
    }

    std::vector<std::wstring> split_data(
        std::wstring_view data,
        std::size_t expected_fields)
    {
        std::vector<std::wstring> fields;
        std::size_t start = 0U;
        while (start <= data.size())
        {
            std::size_t const separator = data.find(L'|', start);
            std::size_t const end =
                separator == std::wstring_view::npos ?
                    data.size() :
                    separator;
            fields.emplace_back(data.substr(start, end - start));
            if (separator == std::wstring_view::npos)
            {
                break;
            }
            start = separator + 1U;
        }

        if (fields.size() != expected_fields ||
            std::ranges::any_of(
                fields,
                [](std::wstring const& field) {
                    return field.empty();
                }))
        {
            fail(
                L"Windows Installer supplied malformed custom-action data.");
        }
        return fields;
    }

    std::filesystem::path absolute_path(std::wstring const& value)
    {
        std::filesystem::path path{value};
        if (!path.is_absolute())
        {
            fail(L"Setup refused a non-absolute installation path.");
        }
        return path.lexically_normal();
    }

    bool paths_equal(
        std::filesystem::path const& left,
        std::filesystem::path const& right)
    {
        auto comparable = [](std::filesystem::path const& path) {
            std::filesystem::path const normalized =
                path.lexically_normal();
            std::wstring value = normalized.native();
            std::size_t const root_length =
                normalized.root_path().native().size();
            while (value.size() > root_length &&
                   (value.back() == L'\\' || value.back() == L'/'))
            {
                value.pop_back();
            }
            return value;
        };
        std::wstring const normalized_left = comparable(left);
        std::wstring const normalized_right = comparable(right);
        return _wcsicmp(
                   normalized_left.c_str(),
                   normalized_right.c_str()) == 0;
    }

    void reject_reparse_chain(
        std::filesystem::path const& path,
        std::wstring_view failure_message)
    {
        std::filesystem::path current = path.root_path();
        DWORD attributes = GetFileAttributesW(current.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            fail(failure_message);
        }

        for (auto const& part : path.relative_path())
        {
            current /= part;
            attributes = GetFileAttributesW(current.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                fail(failure_message);
            }
        }
    }

    std::filesystem::path required_install_folder()
    {
        PWSTR raw_path = nullptr;
        winrt::check_hresult(SHGetKnownFolderPath(
            FOLDERID_ProgramFilesX64,
            KF_FLAG_DEFAULT,
            nullptr,
            &raw_path));
        std::filesystem::path const program_files{raw_path};
        CoTaskMemFree(raw_path);
        return (program_files / L"Librarian").lexically_normal();
    }

    void validate_install_folder(
        std::filesystem::path const& install_folder)
    {
        if (!paths_equal(
                install_folder,
                required_install_folder()) ||
            !std::filesystem::is_directory(install_folder))
        {
            fail(
                L"Setup requires the protected Program Files Librarian "
                L"folder.");
        }
        reject_reparse_chain(
            install_folder,
            L"Setup refused a redirected installation folder.");
    }

    PackageVersion parse_version(std::wstring_view text)
    {
        std::array<std::uint16_t, 4> parts{};
        std::size_t start = 0U;
        for (std::size_t index = 0U; index < parts.size(); ++index)
        {
            std::size_t const separator = text.find(L'.', start);
            std::size_t const end =
                separator == std::wstring_view::npos ?
                    text.size() :
                    separator;
            if (end == start ||
                (index < parts.size() - 1U &&
                 separator == std::wstring_view::npos) ||
                (index == parts.size() - 1U &&
                 separator != std::wstring_view::npos))
            {
                fail(
                    L"Setup received an invalid four-part product version.");
            }

            unsigned long value = 0U;
            for (wchar_t const character :
                 text.substr(start, end - start))
            {
                if (character < L'0' || character > L'9')
                {
                    fail(
                        L"Setup received an invalid four-part product "
                        L"version.");
                }
                value = value * 10U +
                        static_cast<unsigned long>(character - L'0');
                if (value > UINT16_MAX)
                {
                    fail(
                        L"Setup received an invalid four-part product "
                        L"version.");
                }
            }
            parts[index] = static_cast<std::uint16_t>(value);
            start = end + 1U;
        }

        return PackageVersion{
            .Major = parts[0],
            .Minor = parts[1],
            .Build = parts[2],
            .Revision = parts[3],
        };
    }

    std::uint64_t comparable_version(PackageVersion const& version)
    {
        return (static_cast<std::uint64_t>(version.Major) << 48U) |
               (static_cast<std::uint64_t>(version.Minor) << 32U) |
               (static_cast<std::uint64_t>(version.Build) << 16U) |
               static_cast<std::uint64_t>(version.Revision);
    }

    std::uint8_t parse_hex_digit(wchar_t value)
    {
        if (value >= L'0' && value <= L'9')
        {
            return static_cast<std::uint8_t>(value - L'0');
        }
        if (value >= L'A' && value <= L'F')
        {
            return static_cast<std::uint8_t>(value - L'A' + 10);
        }
        fail(L"Setup received an invalid expected payload hash.");
    }

    sha256_digest parse_sha256(std::wstring_view value)
    {
        if (value.size() != 64U)
        {
            fail(L"Setup received an invalid expected payload hash.");
        }

        sha256_digest digest{};
        for (std::size_t index = 0U; index < digest.size(); ++index)
        {
            digest[index] = static_cast<std::uint8_t>(
                (parse_hex_digit(value[index * 2U]) << 4U) |
                parse_hex_digit(value[index * 2U + 1U]));
        }
        return digest;
    }

    std::size_t parse_manifest_entry_count(std::wstring_view value)
    {
        if (value.empty())
        {
            fail(L"Setup received an invalid payload manifest entry count.");
        }
        std::size_t count = 0U;
        for (wchar_t const character : value)
        {
            if (character < L'0' || character > L'9')
            {
                fail(
                    L"Setup received an invalid payload manifest entry "
                    L"count.");
            }
            count = count * 10U +
                    static_cast<std::size_t>(character - L'0');
            if (count > 256U)
            {
                fail(
                    L"Setup received too many payload manifest entries.");
            }
        }
        if (count == 0U)
        {
            fail(L"Setup received an empty payload manifest.");
        }
        return count;
    }

    std::filesystem::path parse_manifest_file_name(
        std::wstring const& value)
    {
        if (value.empty() || value.size() > 255U ||
            std::ranges::any_of(value, [](wchar_t character) {
                return !((character >= L'A' && character <= L'Z') ||
                         (character >= L'a' && character <= L'z') ||
                         (character >= L'0' && character <= L'9') ||
                         character == L'_' || character == L'-' ||
                         character == L'.');
            }))
        {
            fail(L"Setup received an invalid payload manifest filename.");
        }

        std::filesystem::path const file_name{value};
        std::wstring const extension = file_name.extension().native();
        if (_wcsicmp(extension.c_str(), L".exe") != 0 &&
            _wcsicmp(extension.c_str(), L".dll") != 0 &&
            _wcsicmp(extension.c_str(), L".msix") != 0)
        {
            fail(
                L"Setup received a non-executable payload manifest entry.");
        }
        return file_name;
    }

    std::vector<std::wstring> split_manifest(std::wstring_view contents)
    {
        std::vector<std::wstring> fields;
        std::size_t start = 0U;
        while (start <= contents.size())
        {
            std::size_t const separator = contents.find(L'|', start);
            std::size_t const end =
                separator == std::wstring_view::npos ?
                    contents.size() :
                    separator;
            fields.emplace_back(contents.substr(start, end - start));
            if (separator == std::wstring_view::npos)
            {
                break;
            }
            start = separator + 1U;
        }
        return fields;
    }

    sha256_digest hash_file(std::filesystem::path const& path)
    {
        file_handle file;
        file.value = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file.value == INVALID_HANDLE_VALUE)
        {
            fail(L"Setup could not read an installed payload file.");
        }

        bcrypt_algorithm_handle algorithm;
        check_bcrypt(BCryptOpenAlgorithmProvider(
            &algorithm.value,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0));

        DWORD object_length = 0U;
        DWORD result_length = 0U;
        check_bcrypt(BCryptGetProperty(
            algorithm.value,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length),
            &result_length,
            0));
        if (result_length != sizeof(object_length) ||
            object_length == 0U)
        {
            fail(
                L"Setup could not initialize installed payload hashing.");
        }

        std::vector<UCHAR> hash_object(object_length);
        bcrypt_hash_handle hash;
        check_bcrypt(BCryptCreateHash(
            algorithm.value,
            &hash.value,
            hash_object.data(),
            static_cast<ULONG>(hash_object.size()),
            nullptr,
            0,
            0));

        std::array<UCHAR, 64U * 1024U> buffer{};
        while (true)
        {
            DWORD read = 0U;
            if (!ReadFile(
                    file.value,
                    buffer.data(),
                    static_cast<DWORD>(buffer.size()),
                    &read,
                    nullptr))
            {
                fail(L"Setup could not read an installed payload file.");
            }
            if (read == 0U)
            {
                break;
            }
            check_bcrypt(BCryptHashData(
                hash.value,
                buffer.data(),
                read,
                0));
        }

        sha256_digest digest{};
        check_bcrypt(BCryptFinishHash(
            hash.value,
            reinterpret_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()),
            0));
        return digest;
    }

    payload_manifest read_payload_manifest(
        std::filesystem::path const& install_folder,
        sha256_digest const& expected_manifest_hash)
    {
        std::filesystem::path const path =
            install_folder / payload_hash_manifest_name;
        if (!std::filesystem::is_regular_file(path))
        {
            fail(
                L"Setup refused an invalid payload hash manifest path.");
        }
        reject_reparse_chain(
            path,
            L"Setup refused a redirected payload hash manifest.");
        if (hash_file(path) != expected_manifest_hash)
        {
            fail(
                L"Setup refused a mismatched payload hash manifest.");
        }

        std::ifstream stream{path, std::ios::binary | std::ios::in};
        std::string const contents{
            std::istreambuf_iterator<char>{stream},
            std::istreambuf_iterator<char>{}};
        if (stream.bad() || contents.empty() ||
            contents.size() > 64U * 1024U ||
            std::ranges::any_of(contents, [](unsigned char value) {
                return value < 0x20U || value > 0x7EU;
            }))
        {
            fail(L"Setup refused an invalid payload hash manifest.");
        }

        std::wstring const wide_contents{
            contents.begin(),
            contents.end()};
        std::vector<std::wstring> const fields =
            split_manifest(wide_contents);
        if (fields.size() < 5U || fields[0] != L"v3" ||
            std::ranges::any_of(
                fields,
                [](std::wstring const& field) { return field.empty(); }))
        {
            fail(
                L"Setup received an unsupported payload hash manifest.");
        }

        std::size_t const entry_count =
            parse_manifest_entry_count(fields[2]);
        if (fields.size() != 3U + entry_count * 2U)
        {
            fail(L"Setup received a malformed payload hash manifest.");
        }

        payload_manifest manifest{
            .version = parse_version(fields[1]),
        };
        manifest.files.reserve(entry_count);
        for (std::size_t index = 0U; index < entry_count; ++index)
        {
            std::filesystem::path const file_name =
                parse_manifest_file_name(fields[3U + index * 2U]);
            if (std::ranges::any_of(
                    manifest.files,
                    [&](payload_hash_entry const& entry) {
                        return paths_equal(entry.file_name, file_name);
                    }))
            {
                fail(
                    L"Setup received a duplicate payload manifest entry.");
            }
            manifest.files.push_back(payload_hash_entry{
                .file_name = file_name,
                .hash = parse_sha256(fields[4U + index * 2U]),
            });
        }
        for (std::wstring_view const required : payload_files)
        {
            if (!std::ranges::any_of(
                    manifest.files,
                    [&](payload_hash_entry const& entry) {
                        return paths_equal(
                            entry.file_name,
                            std::filesystem::path{std::wstring{required}});
                    }))
            {
                fail(
                    L"Setup received an incomplete payload hash manifest.");
            }
        }
        return manifest;
    }

    validation_action_data read_validation_action_data(
        MSIHANDLE installer)
    {
        auto const fields = split_data(
            get_property(installer, L"CustomActionData"),
            3U);
        return validation_action_data{
            .install_folder = absolute_path(fields[0]),
            .version = parse_version(fields[1]),
            .manifest_hash = parse_sha256(fields[2]),
        };
    }

    void validate_release_payload(
        validation_action_data const& data)
    {
        validate_install_folder(data.install_folder);
        sha256_digest const setup_signer = trusted_signer_hash(
            current_module_path(),
            L"Setup refused an untrusted validation module.");
        for (std::wstring_view const name : payload_files)
        {
            std::filesystem::path const path =
                data.install_folder / name;
            if (!std::filesystem::is_regular_file(path))
            {
                fail(L"Setup refused an incomplete executable set.");
            }
            reject_reparse_chain(
                path,
                L"Setup refused a redirected executable set.");
            if (trusted_signer_hash(
                    path,
                    L"Setup refused an untrusted payload signature.") !=
                setup_signer)
            {
                fail(L"Setup refused a payload signed by another publisher.");
            }
        }
        if (std::filesystem::exists(
                data.install_folder / forbidden_provider))
        {
            fail(
                L"Setup refused an unexpected passkey provider before "
                L"issue #18.");
        }

        payload_manifest const manifest = read_payload_manifest(
            data.install_folder,
            data.manifest_hash);
        if (comparable_version(manifest.version) !=
            comparable_version(data.version))
        {
            fail(
                L"Setup refused a payload manifest with a mismatched "
                L"version.");
        }
        for (payload_hash_entry const& entry : manifest.files)
        {
            std::filesystem::path const path =
                data.install_folder / entry.file_name;
            if (!std::filesystem::is_regular_file(path))
            {
                fail(
                    L"Setup refused an incomplete executable dependency "
                    L"set.");
            }
            reject_reparse_chain(
                path,
                L"Setup refused a redirected executable dependency set.");
            if (hash_file(path) != entry.hash)
            {
                fail(
                    L"Setup refused a mismatched installed payload file.");
            }
        }
    }

    void check_deployment_result(
        DeploymentResult const& result,
        std::wstring_view operation)
    {
        winrt::hresult const error = result.ExtendedErrorCode();
        if (error.value < 0)
        {
            std::wstring message{operation};
            message.append(L" failed.");
            throw winrt::hresult_error{error, message};
        }
    }
}

extern "C" __declspec(dllexport) UINT __stdcall ValidateIdentityPayload(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity payload validation", [&] {
        validate_release_payload(
            read_validation_action_data(installer));
    });
}

extern "C" __declspec(dllexport) UINT __stdcall
UnregisterCurrentUserIdentity(MSIHANDLE installer)
{
    return run_action(
        installer,
        L"invoking-user identity removal",
        [&] {
            auto const fields = split_data(
                get_property(installer, L"CustomActionData"),
                2U);
            std::filesystem::path const install_folder =
                absolute_path(fields[0]);
            if (!paths_equal(install_folder, required_install_folder()))
            {
                fail(
                    L"Setup refused an unexpected identity removal path.");
            }
            PackageVersion const installed_version =
                parse_version(fields[1]);
            std::uint64_t const installed =
                comparable_version(installed_version);
            PackageManager const manager;
            std::vector<Package> removable_packages;
            for (Package const& package :
                 manager.FindPackagesForUser(
                     L"",
                     winrt::hstring{package_name},
                     winrt::hstring{package_publisher}))
            {
                winrt::hstring external_path;
                try
                {
                    external_path = package.EffectiveExternalPath();
                }
                catch (winrt::hresult_error const&)
                {
                    continue;
                }
                if (!external_path.empty() &&
                    paths_equal(
                        std::filesystem::path{external_path.c_str()},
                        install_folder) &&
                    comparable_version(package.Id().Version()) <= installed)
                {
                    removable_packages.push_back(package);
                }
            }
            if (removable_packages.size() > 1U)
            {
                throw winrt::hresult_error{
                    E_UNEXPECTED,
                    L"Invoking-user identity state is ambiguous."};
            }
            for (Package const& package : removable_packages)
            {
                DeploymentResult const result =
                    manager.RemovePackageAsync(
                        package.Id().FullName()).get();
                check_deployment_result(
                    result,
                    L"Invoking-user identity removal");
            }
        });
}
