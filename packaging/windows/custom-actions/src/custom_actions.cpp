#include <windows.h>
#include <msi.h>
#include <msiquery.h>
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
        if (!std::filesystem::is_regular_file(package_path))
        {
            fail(L"Setup refused a missing identity package.");
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

    void remove_package(
        PackageManager const& manager,
        Package const& package)
    {
        winrt::hstring const family_name = package.Id().FamilyName();
        winrt::hstring const full_name = package.Id().FullName();
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
        bool present)
    {
        std::ofstream stream{
            marker,
            std::ios::binary | std::ios::out | std::ios::trunc};
        if (!stream)
        {
            fail(L"Setup could not create its identity rollback marker.");
        }
        stream.put(present ? '1' : '0');
        stream.flush();
        if (!stream)
        {
            fail(L"Setup could not persist its identity rollback marker.");
        }
    }

    bool read_snapshot(std::filesystem::path const& marker)
    {
        std::ifstream stream{marker, std::ios::binary | std::ios::in};
        char value = '\0';
        if (!stream.get(value) || (value != '0' && value != '1'))
        {
            fail(L"Setup could not read its identity rollback marker.");
        }
        return value == '1';
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
}

extern "C" __declspec(dllexport) UINT __stdcall SnapshotIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity snapshot", [&] {
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 3);
        std::filesystem::path const marker = absolute_path(fields[0]);
        std::filesystem::path const install_folder = absolute_path(fields[1]);
        PackageVersion const version = parse_version(fields[2]);
        validate_snapshot_path(marker, install_folder, true);
        PackageManager const manager;
        write_snapshot(marker, exact_package_exists(manager, version));
    });
}

extern "C" __declspec(dllexport) UINT __stdcall RegisterIdentity(
    MSIHANDLE installer)
{
    return run_action(installer, L"identity registration", [&] {
        auto const fields =
            split_data(get_property(installer, L"CustomActionData"), 3);
        std::filesystem::path const package_path = absolute_path(fields[0]);
        std::filesystem::path const install_folder = absolute_path(fields[1]);
        PackageVersion const version = parse_version(fields[2]);

        validate_payload(package_path, install_folder);

        PackageManager const manager;
        reject_newer_packages(manager, version);

        if (!exact_package_exists(manager, version))
        {
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
            split_data(get_property(installer, L"CustomActionData"), 3);
        std::filesystem::path const marker = absolute_path(fields[0]);
        std::filesystem::path const install_folder = absolute_path(fields[1]);
        PackageVersion const version = parse_version(fields[2]);

        validate_snapshot_path(marker, install_folder, false);
        if (!read_snapshot(marker))
        {
            PackageManager const manager;
            for (Package const& package : matching_packages(manager))
            {
                if (comparable_version(package.Id().Version()) ==
                    comparable_version(version))
                {
                    remove_package(manager, package);
                }
            }
        }
        remove_snapshot(marker);
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
