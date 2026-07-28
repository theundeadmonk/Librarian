#include <windows.h>
#include <bcrypt.h>
#include <msi.h>
#include <msiquery.h>
#include <sddl.h>
#include <shlobj.h>

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
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using winrt::Windows::ApplicationModel::Package;
    using winrt::Windows::ApplicationModel::PackageVersion;
    using winrt::Windows::Foundation::Uri;
    using winrt::Windows::Management::Deployment::DeploymentResult;
    using winrt::Windows::Management::Deployment::AddPackageOptions;
    using winrt::Windows::Management::Deployment::PackageManager;
    using winrt::Windows::Management::Deployment::RemovalOptions;
    using winrt::Windows::Management::Deployment::StagePackageOptions;

    constexpr std::wstring_view package_name{
        L"TheUndeadMonk.Librarian.Development"};
    constexpr std::wstring_view package_publisher{L"CN=Librarian Development"};
    constexpr std::array<std::wstring_view, 3> required_executables{
        L"Librarian.Windows.exe",
        L"Librarian.VaultAgent.exe",
        L"Librarian.ChromiumNativeHost.exe",
    };
    constexpr std::wstring_view forbidden_provider{
        L"Librarian.PasskeyProvider.exe"};
    constexpr std::wstring_view snapshot_name{
        L"Librarian.Identity.msix.state"};
    constexpr std::wstring_view payload_hash_manifest_name{
        L"Librarian.PayloadHashes"};
    using sha256_digest = std::array<std::uint8_t, 32>;

    struct identity_snapshot
    {
        bool package_present{};
        PackageVersion package_version{};
        bool provisioned{};
        bool invoking_user_registered{};
    };

    struct payload_hashes
    {
        sha256_digest desktop{};
        sha256_digest vault_agent{};
        sha256_digest native_host{};
        sha256_digest identity_package{};
    };

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
        if (MsiRecordSetStringW(record, 0, owned.c_str()) == ERROR_SUCCESS)
        {
            static_cast<void>(MsiProcessMessage(installer, kind, record));
        }
    }

    [[noreturn]] void fail(std::wstring_view message)
    {
        throw std::runtime_error(
            std::filesystem::path{message}.string());
    }

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

        bcrypt_algorithm_handle(bcrypt_algorithm_handle const&) = delete;
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
        bcrypt_hash_handle& operator=(bcrypt_hash_handle const&) = delete;
    };

    void check_bcrypt(NTSTATUS status)
    {
        if (!BCRYPT_SUCCESS(status))
        {
            fail(L"Setup could not verify an installed payload hash.");
        }
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
        if (value >= L'a' && value <= L'f')
        {
            return static_cast<std::uint8_t>(value - L'a' + 10);
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
        for (std::size_t index = 0; index < digest.size(); ++index)
        {
            digest[index] = static_cast<std::uint8_t>(
                (parse_hex_digit(value[index * 2U]) << 4U) |
                parse_hex_digit(value[index * 2U + 1U]));
        }
        return digest;
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

        DWORD object_length = 0;
        DWORD result_length = 0;
        check_bcrypt(BCryptGetProperty(
            algorithm.value,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length),
            &result_length,
            0));
        if (result_length != sizeof(object_length) || object_length == 0U)
        {
            fail(L"Setup could not initialize installed payload hashing.");
        }

        DWORD hash_length = 0;
        check_bcrypt(BCryptGetProperty(
            algorithm.value,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_length),
            sizeof(hash_length),
            &result_length,
            0));
        if (result_length != sizeof(hash_length) ||
            hash_length != static_cast<DWORD>(sha256_digest{}.size()))
        {
            fail(L"Setup could not initialize SHA-256 payload hashing.");
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
            DWORD read = 0;
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

    void verify_file_hash(
        std::filesystem::path const& path,
        sha256_digest const& expected)
    {
        if (hash_file(path) != expected)
        {
            fail(L"Setup refused a mismatched installed payload file.");
        }
    }

    std::wstring get_property(MSIHANDLE installer, wchar_t const* name)
    {
        DWORD characters = 0;
        wchar_t empty[1]{};
        UINT const size_result =
            MsiGetPropertyW(installer, name, empty, &characters);
        if (size_result != ERROR_MORE_DATA && size_result != ERROR_SUCCESS)
        {
            fail(L"Windows Installer could not read required custom-action data.");
        }

        std::wstring value(static_cast<std::size_t>(characters) + 1U, L'\0');
        DWORD capacity = characters + 1U;
        UINT const read_result =
            MsiGetPropertyW(installer, name, value.data(), &capacity);
        if (read_result != ERROR_SUCCESS)
        {
            fail(L"Windows Installer could not read required custom-action data.");
        }
        value.resize(capacity);
        return value;
    }

    std::vector<std::wstring> split_data(
        std::wstring_view data,
        std::size_t expected_fields)
    {
        std::vector<std::wstring> fields;
        std::size_t start = 0;
        while (start <= data.size())
        {
            std::size_t const separator = data.find(L'|', start);
            std::size_t const end =
                separator == std::wstring_view::npos ? data.size() : separator;
            fields.emplace_back(data.substr(start, end - start));
            if (separator == std::wstring_view::npos)
            {
                break;
            }
            start = separator + 1U;
        }

        if (fields.size() != expected_fields ||
            std::ranges::any_of(fields, [](std::wstring const& field) {
                return field.empty();
            }))
        {
            fail(L"Windows Installer supplied malformed custom-action data.");
        }
        return fields;
    }

    std::wstring validate_user_sid(std::wstring const& value)
    {
        if (value.size() < 5U || value.size() > SECURITY_MAX_SID_SIZE * 3U ||
            !value.starts_with(L"S-1-"))
        {
            fail(L"Windows Installer supplied an invalid invoking-user SID.");
        }

        PSID parsed = nullptr;
        if (!ConvertStringSidToSidW(value.c_str(), &parsed) ||
            parsed == nullptr || !IsValidSid(parsed))
        {
            if (parsed != nullptr)
            {
                LocalFree(parsed);
            }
            fail(L"Windows Installer supplied an invalid invoking-user SID.");
        }
        LocalFree(parsed);
        return value;
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
            std::filesystem::path const normalized = path.lexically_normal();
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
        bool allow_missing_leaf,
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
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                if (allow_missing_leaf && paths_equal(current, path))
                {
                    return;
                }
                fail(failure_message);
            }
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
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

    void validate_install_folder(std::filesystem::path const& install_folder)
    {
        if (!paths_equal(install_folder, required_install_folder()))
        {
            fail(
                L"Setup requires the protected Program Files Librarian folder.");
        }
        if (!std::filesystem::is_directory(install_folder))
        {
            fail(L"Setup refused a missing installation folder.");
        }
        reject_reparse_chain(
            install_folder,
            false,
            L"Setup refused a redirected installation folder.");
    }

    void validate_snapshot_path(
        std::filesystem::path const& marker,
        std::filesystem::path const& install_folder,
        bool allow_missing)
    {
        validate_install_folder(install_folder);
        if (!paths_equal(marker.parent_path(), install_folder) ||
            marker.filename().native() != snapshot_name)
        {
            fail(L"Setup refused an unsafe identity rollback marker path.");
        }
        reject_reparse_chain(
            marker,
            allow_missing,
            L"Setup refused a redirected identity rollback marker.");
    }

    void validate_payload(
        std::filesystem::path const& package_path,
        std::filesystem::path const& install_folder)
    {
        validate_install_folder(install_folder);
        if (!paths_equal(package_path.parent_path(), install_folder) ||
            package_path.filename().native() != L"Librarian.Identity.msix" ||
            !std::filesystem::is_regular_file(package_path))
        {
            fail(L"Setup refused an invalid identity package path.");
        }
        reject_reparse_chain(
            package_path,
            false,
            L"Setup refused a redirected identity package.");

        for (std::wstring_view const name : required_executables)
        {
            std::filesystem::path const executable = install_folder / name;
            if (!std::filesystem::is_regular_file(executable))
            {
                fail(L"Setup refused an incomplete executable set.");
            }
            reject_reparse_chain(
                executable,
                false,
                L"Setup refused a redirected executable set.");
        }

        if (std::filesystem::exists(install_folder / forbidden_provider))
        {
            fail(
                L"Setup refused an unexpected passkey provider before issue #18.");
        }
    }

    void validate_release_payload(
        std::filesystem::path const& package_path,
        std::filesystem::path const& install_folder,
        payload_hashes const& hashes)
    {
        validate_payload(package_path, install_folder);
        verify_file_hash(
            install_folder / required_executables[0],
            hashes.desktop);
        verify_file_hash(
            install_folder / required_executables[1],
            hashes.vault_agent);
        verify_file_hash(
            install_folder / required_executables[2],
            hashes.native_host);
        verify_file_hash(package_path, hashes.identity_package);
    }

    payload_hashes read_payload_hashes(
        std::filesystem::path const& manifest_path,
        std::filesystem::path const& install_folder,
        sha256_digest const& expected_manifest_hash)
    {
        validate_install_folder(install_folder);
        if (!paths_equal(manifest_path.parent_path(), install_folder) ||
            manifest_path.filename().native() != payload_hash_manifest_name ||
            !std::filesystem::is_regular_file(manifest_path))
        {
            fail(L"Setup refused an invalid payload hash manifest path.");
        }
        reject_reparse_chain(
            manifest_path,
            false,
            L"Setup refused a redirected payload hash manifest.");

        file_handle manifest;
        manifest.value = CreateFileW(
            manifest_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (manifest.value == INVALID_HANDLE_VALUE)
        {
            fail(L"Setup could not read the payload hash manifest.");
        }

        LARGE_INTEGER manifest_size{};
        if (!GetFileSizeEx(manifest.value, &manifest_size) ||
            manifest_size.QuadPart <= 0 ||
            manifest_size.QuadPart > 384)
        {
            fail(L"Setup refused an invalid payload hash manifest size.");
        }

        std::string contents(
            static_cast<std::size_t>(manifest_size.QuadPart),
            '\0');
        DWORD bytes_read = 0;
        if (!ReadFile(
                manifest.value,
                contents.data(),
                static_cast<DWORD>(contents.size()),
                &bytes_read,
                nullptr) ||
            bytes_read != static_cast<DWORD>(contents.size()))
        {
            fail(L"Setup could not read the payload hash manifest.");
        }

        bcrypt_algorithm_handle algorithm;
        check_bcrypt(BCryptOpenAlgorithmProvider(
            &algorithm.value,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0));
        sha256_digest actual_manifest_hash{};
        check_bcrypt(BCryptHash(
            algorithm.value,
            nullptr,
            0,
            reinterpret_cast<PUCHAR>(contents.data()),
            static_cast<ULONG>(contents.size()),
            reinterpret_cast<PUCHAR>(actual_manifest_hash.data()),
            static_cast<ULONG>(actual_manifest_hash.size())));
        if (actual_manifest_hash != expected_manifest_hash)
        {
            fail(L"Setup refused a mismatched payload hash manifest.");
        }

        if (std::ranges::any_of(contents, [](unsigned char value) {
                return value < 0x20U || value > 0x7EU;
            }))
        {
            fail(L"Setup refused a non-ASCII payload hash manifest.");
        }

        std::wstring const wide_contents(contents.begin(), contents.end());
        auto const fields = split_data(wide_contents, 5);
        if (fields[0] != L"v1")
        {
            fail(L"Setup received an unsupported payload hash manifest.");
        }

        return payload_hashes{
            .desktop = parse_sha256(fields[1]),
            .vault_agent = parse_sha256(fields[2]),
            .native_host = parse_sha256(fields[3]),
            .identity_package = parse_sha256(fields[4]),
        };
    }

    PackageVersion parse_version(std::wstring_view text)
    {
        std::array<std::uint16_t, 4> parts{};
        std::size_t start = 0;
        for (std::size_t index = 0; index < parts.size(); ++index)
        {
            std::size_t const separator = text.find(L'.', start);
            std::size_t const end =
                separator == std::wstring_view::npos ? text.size() : separator;
            if (end == start || (index < parts.size() - 1U &&
                                 separator == std::wstring_view::npos) ||
                (index == parts.size() - 1U &&
                 separator != std::wstring_view::npos))
            {
                fail(L"Setup received an invalid four-part product version.");
            }

            std::wstring const token{text.substr(start, end - start)};
            std::size_t parsed = 0;
            unsigned long const value = std::stoul(token, &parsed, 10);
            if (parsed != token.size() || value > UINT16_MAX)
            {
                fail(L"Setup received an invalid four-part product version.");
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

    struct identity_action_data
    {
        std::filesystem::path package_path;
        std::filesystem::path install_folder;
        PackageVersion version;
        payload_hashes hashes;
    };

    identity_action_data read_identity_action_data(MSIHANDLE installer)
    {
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 3);
        std::filesystem::path const install_folder = absolute_path(fields[0]);
        std::filesystem::path const package_path =
            install_folder / L"Librarian.Identity.msix";
        std::filesystem::path const manifest_path =
            install_folder / payload_hash_manifest_name;

        return identity_action_data{
            .package_path = package_path,
            .install_folder = install_folder,
            .version = parse_version(fields[1]),
            .hashes = read_payload_hashes(
                manifest_path,
                install_folder,
                parse_sha256(fields[2])),
        };
    }

    std::uint64_t comparable_version(PackageVersion const& version)
    {
        return (static_cast<std::uint64_t>(version.Major) << 48U) |
               (static_cast<std::uint64_t>(version.Minor) << 32U) |
               (static_cast<std::uint64_t>(version.Build) << 16U) |
               static_cast<std::uint64_t>(version.Revision);
    }

    std::vector<Package> matching_packages(PackageManager const& manager)
    {
        std::vector<Package> packages;
        for (Package const& package : manager.FindPackages(
                 winrt::hstring{package_name},
                 winrt::hstring{package_publisher}))
        {
            packages.push_back(package);
        }
        return packages;
    }

    void check_deployment_result(
        DeploymentResult const& result,
        std::wstring_view operation)
    {
        winrt::hresult const error = result.ExtendedErrorCode();
        if (FAILED(error.value))
        {
            std::wstring message{operation};
            message.append(L" failed with Windows error ");
            wchar_t code[11]{};
            static_cast<void>(
                swprintf_s(code, L"0x%08X", static_cast<unsigned>(error.value)));
            message.append(code);
            if (!result.ErrorText().empty())
            {
                message.append(L": ");
                message.append(result.ErrorText());
            }
            throw winrt::hresult_error(error, message);
        }
    }

    Package find_exact_package(
        PackageManager const& manager,
        PackageVersion const& expected)
    {
        Package exact{nullptr};
        for (Package const& package : matching_packages(manager))
        {
            PackageVersion const actual = package.Id().Version();
            if (comparable_version(actual) > comparable_version(expected))
            {
                fail(
                    L"Setup refused to replace a newer identity package.");
            }
            if (comparable_version(actual) == comparable_version(expected))
            {
                if (exact)
                {
                    fail(L"Setup found duplicate matching identity packages.");
                }
                exact = package;
            }
        }
        if (!exact)
        {
            fail(L"Windows did not expose the staged identity package.");
        }
        return exact;
    }

    void validate_external_location(
        Package const& package,
        std::filesystem::path const& install_folder)
    {
        winrt::hstring const external_path =
            package.EffectiveExternalPath();
        if (external_path.empty())
        {
            fail(
                L"Setup refused an identity package without an external path.");
        }
        std::filesystem::path const actual =
            absolute_path(external_path.c_str());
        if (!paths_equal(actual, install_folder))
        {
            fail(
                L"Setup refused an identity package from another location.");
        }
        reject_reparse_chain(
            actual,
            false,
            L"Setup refused a redirected identity package location.");
    }

    void reject_newer_packages(
        PackageManager const& manager,
        PackageVersion const& expected)
    {
        for (Package const& package : matching_packages(manager))
        {
            if (comparable_version(package.Id().Version()) >
                comparable_version(expected))
            {
                fail(L"Setup refused to replace a newer identity package.");
            }
        }
    }

    bool exact_package_exists(
        PackageManager const& manager,
        PackageVersion const& expected)
    {
        return std::ranges::any_of(
            matching_packages(manager),
            [&expected](Package const& package) {
                return comparable_version(package.Id().Version()) ==
                       comparable_version(expected);
            });
    }

    bool package_not_found(winrt::hresult const error)
    {
        constexpr HRESULT package_not_found_error =
            static_cast<HRESULT>(0x80073CF1L);
        constexpr HRESULT package_not_registered_error =
            HRESULT_FROM_WIN32(APPMODEL_ERROR_NO_PACKAGE);
        return error.value == package_not_found_error ||
               error.value == package_not_registered_error;
    }

    bool package_is_provisioned(
        PackageManager const& manager,
        Package const& package)
    {
        winrt::hstring const expected = package.Id().FullName();
        return std::ranges::any_of(
            manager.FindProvisionedPackages(),
            [&expected](Package const& candidate) {
                return _wcsicmp(
                           candidate.Id().FullName().c_str(),
                           expected.c_str()) == 0;
            });
    }

    bool package_is_registered_for_user(
        PackageManager const& manager,
        Package const& package,
        std::wstring const& user_sid)
    {
        try
        {
            Package const registered = manager.FindPackageForUser(
                winrt::hstring{user_sid},
                package.Id().FullName());
            return registered != nullptr;
        }
        catch (winrt::hresult_error const& error)
        {
            if (package_not_found(error.code()))
            {
                return false;
            }
            throw;
        }
    }

    identity_snapshot capture_snapshot(
        PackageManager const& manager,
        PackageVersion const& incoming_version,
        std::filesystem::path const& install_folder,
        std::wstring const& user_sid)
    {
        std::vector<Package> const packages = matching_packages(manager);
        if (packages.size() > 1U)
        {
            fail(
                L"Setup refused ambiguous existing identity package state.");
        }
        if (packages.empty())
        {
            return {};
        }

        Package const package = packages.front();
        PackageVersion const version = package.Id().Version();
        if (comparable_version(version) >
            comparable_version(incoming_version))
        {
            fail(L"Setup refused to replace a newer identity package.");
        }
        validate_external_location(package, install_folder);
        return identity_snapshot{
            .package_present = true,
            .package_version = version,
            .provisioned = package_is_provisioned(manager, package),
            .invoking_user_registered =
                package_is_registered_for_user(manager, package, user_sid),
        };
    }

    void deprovision_package_family(
        PackageManager const& manager,
        winrt::hstring const& family_name)
    {
        try
        {
            DeploymentResult const deprovisioned =
                manager.DeprovisionPackageForAllUsersAsync(family_name).get();
            check_deployment_result(
                deprovisioned,
                L"Identity package deprovisioning");
        }
        catch (winrt::hresult_error const& error)
        {
            if (!package_not_found(error.code()))
            {
                throw;
            }
        }
    }

    void remove_package(
        PackageManager const& manager,
        Package const& package)
    {
        winrt::hstring const family_name = package.Id().FamilyName();
        winrt::hstring const full_name = package.Id().FullName();
        deprovision_package_family(manager, family_name);

        try
        {
            DeploymentResult const removed =
                manager
                    .RemovePackageAsync(
                        full_name,
                        RemovalOptions::RemoveForAllUsers)
                    .get();
            check_deployment_result(removed, L"Identity package removal");
        }
        catch (winrt::hresult_error const& error)
        {
            if (!package_not_found(error.code()))
            {
                throw;
            }
        }
    }

    void remove_package_for_current_user(
        PackageManager const& manager,
        Package const& package)
    {
        try
        {
            DeploymentResult const removed =
                manager.RemovePackageAsync(package.Id().FullName()).get();
            check_deployment_result(
                removed,
                L"Invoking-user identity package removal");
        }
        catch (winrt::hresult_error const& error)
        {
            if (!package_not_found(error.code()))
            {
                throw;
            }
        }
    }

    Package ensure_package_staged(
        PackageManager const& manager,
        PackageVersion const& version,
        std::filesystem::path const& package_path,
        std::filesystem::path const& install_folder)
    {
        if (!exact_package_exists(manager, version))
        {
            validate_payload(package_path, install_folder);
            StagePackageOptions const options;
            options.ExternalLocationUri(Uri{install_folder.c_str()});
            DeploymentResult const staged =
                manager
                    .StagePackageByUriAsync(
                        Uri{package_path.c_str()},
                        options)
                    .get();
            check_deployment_result(staged, L"Identity package staging");
        }

        Package const package = find_exact_package(manager, version);
        validate_external_location(package, install_folder);
        return package;
    }

    void register_package_for_current_user(
        PackageManager const& manager,
        PackageVersion const& version,
        std::filesystem::path const& package_path,
        std::filesystem::path const& install_folder)
    {
        validate_payload(package_path, install_folder);
        if (exact_package_exists(manager, version))
        {
            Package const existing = find_exact_package(manager, version);
            validate_external_location(existing, install_folder);
            if (package_is_registered_for_user(manager, existing, L""))
            {
                return;
            }
        }

        AddPackageOptions const options;
        options.ExternalLocationUri(Uri{install_folder.c_str()});
        DeploymentResult const registered =
            manager.AddPackageByUriAsync(
                Uri{package_path.c_str()},
                options).get();
        check_deployment_result(
            registered,
            L"Invoking-user identity package registration");

        Package const package = find_exact_package(manager, version);
        validate_external_location(package, install_folder);
        if (!package_is_registered_for_user(manager, package, L""))
        {
            fail(
                L"Identity package registration did not become visible "
                L"for the invoking user.");
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
        catch (std::exception const&)
        {
            std::wstring message{L"Librarian setup: "};
            message.append(label);
            message.append(L" failed validation.");
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

    void write_snapshot(
        std::filesystem::path const& marker,
        identity_snapshot const& snapshot)
    {
        std::ofstream stream{
            marker,
            std::ios::binary | std::ios::out | std::ios::trunc};
        if (!stream)
        {
            fail(L"Setup could not create its identity rollback marker.");
        }
        stream << "v1|" << (snapshot.package_present ? '1' : '0') << '|'
               << snapshot.package_version.Major << '.'
               << snapshot.package_version.Minor << '.'
               << snapshot.package_version.Build << '.'
               << snapshot.package_version.Revision << '|'
               << (snapshot.provisioned ? '1' : '0') << '|'
               << (snapshot.invoking_user_registered ? '1' : '0');
        stream.flush();
        if (!stream)
        {
            fail(L"Setup could not persist its identity rollback marker.");
        }
    }

    bool parse_snapshot_boolean(std::wstring const& value)
    {
        if (value == L"0")
        {
            return false;
        }
        if (value == L"1")
        {
            return true;
        }
        fail(L"Setup could not parse its identity rollback marker.");
    }

    identity_snapshot read_snapshot(std::filesystem::path const& marker)
    {
        std::ifstream stream{marker, std::ios::binary | std::ios::in};
        std::string const serialized{
            std::istreambuf_iterator<char>{stream},
            std::istreambuf_iterator<char>{}};
        if (stream.bad() || serialized.empty() || serialized.size() > 128U ||
            std::ranges::any_of(serialized, [](char character) {
                return character < 0x20 || character > 0x7E;
            }))
        {
            fail(L"Setup could not read its identity rollback marker.");
        }

        std::wstring const text{serialized.begin(), serialized.end()};
        auto const fields = split_data(text, 5);
        if (fields[0] != L"v1")
        {
            fail(L"Setup found an unsupported identity rollback marker.");
        }

        identity_snapshot const snapshot{
            .package_present = parse_snapshot_boolean(fields[1]),
            .package_version = parse_version(fields[2]),
            .provisioned = parse_snapshot_boolean(fields[3]),
            .invoking_user_registered =
                parse_snapshot_boolean(fields[4]),
        };
        if (!snapshot.package_present &&
            (comparable_version(snapshot.package_version) != 0U ||
             snapshot.provisioned ||
             snapshot.invoking_user_registered))
        {
            fail(L"Setup found inconsistent identity rollback state.");
        }
        return snapshot;
    }

    void remove_snapshot(std::filesystem::path const& marker)
    {
        std::error_code error;
        static_cast<void>(std::filesystem::remove(marker, error));
        if (error)
        {
            fail(L"Setup could not remove its identity rollback marker.");
        }
    }

    void remove_exact_package(
        PackageManager const& manager,
        PackageVersion const& version)
    {
        for (Package const& package : matching_packages(manager))
        {
            if (comparable_version(package.Id().Version()) ==
                comparable_version(version))
            {
                remove_package(manager, package);
            }
        }
    }

    void restore_system_identity(
        PackageManager const& manager,
        identity_snapshot const& snapshot,
        PackageVersion const& incoming_version,
        std::filesystem::path const& package_path,
        std::filesystem::path const& install_folder)
    {
        if (!snapshot.package_present)
        {
            remove_exact_package(manager, incoming_version);
            return;
        }

        if (comparable_version(snapshot.package_version) !=
            comparable_version(incoming_version))
        {
            remove_exact_package(manager, incoming_version);
        }

        Package const previous = ensure_package_staged(
            manager,
            snapshot.package_version,
            package_path,
            install_folder);
        if (snapshot.provisioned &&
            !package_is_provisioned(manager, previous))
        {
            DeploymentResult const provisioned =
                manager
                    .ProvisionPackageForAllUsersAsync(
                        previous.Id().FamilyName())
                    .get();
            check_deployment_result(
                provisioned,
                L"Previous identity package provisioning");
        }
        else
        {
            deprovision_package_family(
                manager,
                previous.Id().FamilyName());
        }
    }

    void restore_current_user_identity(
        PackageManager const& manager,
        identity_snapshot const& snapshot,
        PackageVersion const& incoming_version,
        std::filesystem::path const& package_path,
        std::filesystem::path const& install_folder)
    {
        for (Package const& package : matching_packages(manager))
        {
            std::uint64_t const actual =
                comparable_version(package.Id().Version());
            bool const incoming =
                actual == comparable_version(incoming_version);
            bool const previous =
                snapshot.package_present &&
                actual == comparable_version(snapshot.package_version);
            bool const preserve_previous =
                snapshot.package_present &&
                snapshot.invoking_user_registered &&
                previous;
            if (!preserve_previous && (incoming || previous))
            {
                remove_package_for_current_user(manager, package);
            }
        }

        if (snapshot.package_present &&
            snapshot.invoking_user_registered)
        {
            register_package_for_current_user(
                manager,
                snapshot.package_version,
                package_path,
                install_folder);
        }
    }
}

extern "C" __declspec(dllexport) UINT __stdcall SnapshotIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity snapshot", [&] {
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 4);
        std::filesystem::path const marker = absolute_path(fields[0]);
        std::filesystem::path const install_folder = absolute_path(fields[1]);
        PackageVersion const version = parse_version(fields[2]);
        std::wstring const user_sid = validate_user_sid(fields[3]);
        validate_snapshot_path(marker, install_folder, true);
        PackageManager const manager;
        write_snapshot(
            marker,
            capture_snapshot(
                manager,
                version,
                install_folder,
                user_sid));
    });
}

extern "C" __declspec(dllexport) UINT __stdcall RegisterIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity staging", [&] {
        identity_action_data const data = read_identity_action_data(installer);
        validate_release_payload(
            data.package_path,
            data.install_folder,
            data.hashes);
        PackageManager const manager;
        reject_newer_packages(manager, data.version);
        static_cast<void>(ensure_package_staged(
            manager,
            data.version,
            data.package_path,
            data.install_folder));
    });
}

extern "C" __declspec(dllexport) UINT __stdcall RegisterCurrentUserIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"invoking-user identity registration", [&] {
        identity_action_data const data = read_identity_action_data(installer);
        validate_release_payload(
            data.package_path,
            data.install_folder,
            data.hashes);
        PackageManager const manager;
        register_package_for_current_user(
            manager,
            data.version,
            data.package_path,
            data.install_folder);
        Package const package = find_exact_package(manager, data.version);
        validate_external_location(package, data.install_folder);
    });
}

extern "C" __declspec(dllexport) UINT __stdcall ProvisionIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity provisioning", [&] {
        identity_action_data const data = read_identity_action_data(installer);
        validate_release_payload(
            data.package_path,
            data.install_folder,
            data.hashes);
        PackageManager const manager;
        reject_newer_packages(manager, data.version);
        Package const package = find_exact_package(manager, data.version);
        validate_external_location(package, data.install_folder);
        DeploymentResult const provisioned =
            manager
                .ProvisionPackageForAllUsersAsync(package.Id().FamilyName())
                .get();
        check_deployment_result(
            provisioned,
            L"Identity package provisioning");
    });
}

extern "C" __declspec(dllexport) UINT __stdcall RollbackIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity rollback", [&] {
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 4);
        std::filesystem::path const marker = absolute_path(fields[0]);
        std::filesystem::path const package_path = absolute_path(fields[1]);
        std::filesystem::path const install_folder = absolute_path(fields[2]);
        PackageVersion const version = parse_version(fields[3]);

        validate_snapshot_path(marker, install_folder, false);
        identity_snapshot const snapshot = read_snapshot(marker);
        PackageManager const manager;
        restore_system_identity(
            manager,
            snapshot,
            version,
            package_path,
            install_folder);
    });
}

extern "C" __declspec(dllexport) UINT __stdcall RollbackCurrentUserIdentity(
    MSIHANDLE installer)
{
    return run_action(
        installer,
        L"invoking-user identity rollback",
        [&] {
            auto const fields =
                split_data(
                    get_property(installer, L"CustomActionData"),
                    4);
            std::filesystem::path const marker =
                absolute_path(fields[0]);
            std::filesystem::path const package_path =
                absolute_path(fields[1]);
            std::filesystem::path const install_folder =
                absolute_path(fields[2]);
            PackageVersion const version = parse_version(fields[3]);

            validate_snapshot_path(marker, install_folder, false);
            identity_snapshot const snapshot = read_snapshot(marker);
            PackageManager const manager;
            restore_current_user_identity(
                manager,
                snapshot,
                version,
                package_path,
                install_folder);
        });
}

extern "C" __declspec(dllexport) UINT __stdcall CleanupIdentitySnapshot(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity snapshot cleanup", [&] {
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 2);
        std::filesystem::path const marker = absolute_path(fields[0]);
        std::filesystem::path const install_folder = absolute_path(fields[1]);
        validate_snapshot_path(marker, install_folder, false);
        remove_snapshot(marker);
    });
}

extern "C" __declspec(dllexport) UINT __stdcall UnregisterIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity removal", [&] {
        // This all-user mutation is a checked commit custom action. It runs
        // only after Windows Installer has completed the rollback-capable
        // script, so a failed uninstall never removes another user's
        // pre-existing package registration.
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 1);
        PackageVersion const installed_version = parse_version(fields[0]);
        PackageManager const manager;
        for (Package const& package : matching_packages(manager))
        {
            if (comparable_version(package.Id().Version()) <=
                comparable_version(installed_version))
            {
                remove_package(manager, package);
            }
        }
    });
}
