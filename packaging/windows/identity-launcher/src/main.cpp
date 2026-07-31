#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
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
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using winrt::Windows::ApplicationModel::Package;
    using winrt::Windows::ApplicationModel::PackageVersion;
    using winrt::Windows::Foundation::Uri;
    using winrt::Windows::Management::Deployment::AddPackageOptions;
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
    constexpr std::wstring_view payload_manifest_name{
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

    struct payload_manifest
    {
        PackageVersion version{};
        std::array<sha256_digest, payload_files.size()> hashes{};
    };

    [[noreturn]] void fail(std::wstring_view message)
    {
        throw validation_error{std::wstring{message}};
    }

    void check_bcrypt(NTSTATUS status)
    {
        if (!BCRYPT_SUCCESS(status))
        {
            fail(L"Librarian could not verify its installed payload.");
        }
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

    void reject_reparse_chain(std::filesystem::path const& path)
    {
        std::filesystem::path current = path.root_path();
        DWORD attributes = GetFileAttributesW(current.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            fail(L"Librarian refused a redirected installation path.");
        }

        for (auto const& part : path.relative_path())
        {
            current /= part;
            attributes = GetFileAttributesW(current.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                fail(L"Librarian refused a redirected installation path.");
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

    std::filesystem::path module_path()
    {
        std::vector<wchar_t> buffer(512U);
        while (true)
        {
            DWORD const length = GetModuleFileNameW(
                nullptr,
                buffer.data(),
                static_cast<DWORD>(buffer.size()));
            if (length == 0U)
            {
                fail(L"Librarian could not locate its identity launcher.");
            }
            if (length < buffer.size() - 1U)
            {
                return std::filesystem::path{
                    std::wstring{buffer.data(), length}}.lexically_normal();
            }
            if (buffer.size() >= 32768U)
            {
                fail(L"Librarian found an invalid launcher path.");
            }
            buffer.resize(buffer.size() * 2U);
        }
    }

    std::filesystem::path validate_installation()
    {
        std::filesystem::path const launcher = module_path();
        std::filesystem::path const install_folder =
            launcher.parent_path();
        if (!paths_equal(install_folder, required_install_folder()) ||
            launcher.filename().native() != payload_files[0] ||
            !std::filesystem::is_directory(install_folder))
        {
            fail(
                L"Librarian must start from its protected Program Files "
                L"installation.");
        }
        reject_reparse_chain(install_folder);

        for (std::wstring_view const name : payload_files)
        {
            std::filesystem::path const path = install_folder / name;
            if (!std::filesystem::is_regular_file(path))
            {
                fail(L"Librarian found an incomplete installed payload.");
            }
            reject_reparse_chain(path);
        }
        if (std::filesystem::exists(
                install_folder / forbidden_provider))
        {
            fail(
                L"Librarian refused an unexpected passkey provider before "
                L"issue #18.");
        }
        return install_folder;
    }

    std::uint8_t parse_hex_digit(char value)
    {
        if (value >= '0' && value <= '9')
        {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'A' && value <= 'F')
        {
            return static_cast<std::uint8_t>(value - 'A' + 10);
        }
        fail(L"Librarian found an invalid installed payload hash.");
    }

    sha256_digest parse_sha256(std::string_view value)
    {
        if (value.size() != 64U)
        {
            fail(L"Librarian found an invalid installed payload hash.");
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

    PackageVersion parse_version(std::string_view text)
    {
        std::array<std::uint16_t, 4> parts{};
        std::size_t start = 0U;
        for (std::size_t index = 0U; index < parts.size(); ++index)
        {
            std::size_t const separator = text.find('.', start);
            std::size_t const end =
                separator == std::string_view::npos ?
                    text.size() :
                    separator;
            if (end == start ||
                (index < parts.size() - 1U &&
                 separator == std::string_view::npos) ||
                (index == parts.size() - 1U &&
                 separator != std::string_view::npos))
            {
                fail(L"Librarian found an invalid installed version.");
            }

            unsigned long value = 0U;
            for (char const character : text.substr(start, end - start))
            {
                if (character < '0' || character > '9')
                {
                    fail(L"Librarian found an invalid installed version.");
                }
                value = value * 10U +
                        static_cast<unsigned long>(character - '0');
                if (value > UINT16_MAX)
                {
                    fail(L"Librarian found an invalid installed version.");
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

    std::vector<std::string> split_manifest(
        std::string_view contents)
    {
        std::vector<std::string> fields;
        std::size_t start = 0U;
        while (start <= contents.size())
        {
            std::size_t const separator = contents.find('|', start);
            std::size_t const end =
                separator == std::string_view::npos ?
                    contents.size() :
                    separator;
            fields.emplace_back(contents.substr(start, end - start));
            if (separator == std::string_view::npos)
            {
                break;
            }
            start = separator + 1U;
        }
        return fields;
    }

    payload_manifest read_payload_manifest(
        std::filesystem::path const& install_folder)
    {
        std::filesystem::path const path =
            install_folder / payload_manifest_name;
        if (!std::filesystem::is_regular_file(path))
        {
            fail(L"Librarian could not read its payload manifest.");
        }
        reject_reparse_chain(path);

        std::ifstream stream{path, std::ios::binary | std::ios::in};
        std::string const contents{
            std::istreambuf_iterator<char>{stream},
            std::istreambuf_iterator<char>{}};
        if (stream.bad() || contents.empty() || contents.size() > 512U ||
            std::ranges::any_of(contents, [](unsigned char value) {
                return value < 0x20U || value > 0x7EU;
            }))
        {
            fail(L"Librarian refused an invalid payload manifest.");
        }

        std::vector<std::string> const fields = split_manifest(contents);
        if (fields.size() != payload_files.size() + 2U ||
            fields[0] != "v2" ||
            std::ranges::any_of(
                fields,
                [](std::string const& field) { return field.empty(); }))
        {
            fail(L"Librarian refused an unsupported payload manifest.");
        }

        payload_manifest manifest{
            .version = parse_version(fields[1]),
        };
        for (std::size_t index = 0U;
             index < manifest.hashes.size();
             ++index)
        {
            manifest.hashes[index] = parse_sha256(fields[index + 2U]);
        }
        return manifest;
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
            fail(L"Librarian could not read an installed payload file.");
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
        if (result_length != sizeof(object_length) || object_length == 0U)
        {
            fail(L"Librarian could not initialize payload verification.");
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
                fail(L"Librarian could not read an installed payload file.");
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

    payload_manifest validate_payload(
        std::filesystem::path const& install_folder)
    {
        payload_manifest const manifest =
            read_payload_manifest(install_folder);
        for (std::size_t index = 0U;
             index < payload_files.size();
             ++index)
        {
            if (hash_file(install_folder / payload_files[index]) !=
                manifest.hashes[index])
            {
                fail(L"Librarian refused a mismatched installed payload.");
            }
        }
        return manifest;
    }

    std::uint64_t comparable_version(PackageVersion const& version)
    {
        return (static_cast<std::uint64_t>(version.Major) << 48U) |
               (static_cast<std::uint64_t>(version.Minor) << 32U) |
               (static_cast<std::uint64_t>(version.Build) << 16U) |
               static_cast<std::uint64_t>(version.Revision);
    }

    std::vector<Package> current_user_packages(
        PackageManager const& manager)
    {
        std::vector<Package> packages;
        for (Package const& package : manager.FindPackagesForUser(
                 L"",
                 winrt::hstring{package_name},
                 winrt::hstring{package_publisher}))
        {
            packages.push_back(package);
        }
        return packages;
    }

    void validate_external_location(
        Package const& package,
        std::filesystem::path const& install_folder)
    {
        winrt::hstring const external_path =
            package.EffectiveExternalPath();
        if (external_path.empty() ||
            !paths_equal(
                std::filesystem::path{external_path.c_str()},
                install_folder))
        {
            fail(
                L"Librarian refused an identity registered to an unexpected "
                L"external location.");
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

    void ensure_current_user_identity(
        std::filesystem::path const& install_folder,
        PackageVersion const& expected_version)
    {
        PackageManager const manager;
        std::uint64_t const expected =
            comparable_version(expected_version);
        bool exact_registered = false;
        std::vector<Package> unhealthy_exact_packages;
        for (Package const& package : current_user_packages(manager))
        {
            std::uint64_t const actual =
                comparable_version(package.Id().Version());
            if (actual > expected)
            {
                fail(
                    L"Librarian refused to replace a newer registered "
                    L"identity.");
            }
            if (actual == expected)
            {
                validate_external_location(package, install_folder);
                if (package.Status().VerifyIsOK())
                {
                    exact_registered = true;
                }
                else
                {
                    unhealthy_exact_packages.push_back(package);
                }
            }
        }
        if (exact_registered && !unhealthy_exact_packages.empty())
        {
            fail(
                L"Librarian refused ambiguous exact-version identity "
                L"registrations.");
        }
        if (exact_registered)
        {
            return;
        }
        if (unhealthy_exact_packages.size() > 1U)
        {
            fail(
                L"Librarian refused multiple unhealthy exact-version "
                L"identity registrations.");
        }
        for (Package const& package : unhealthy_exact_packages)
        {
            DeploymentResult const result =
                manager.RemovePackageAsync(
                    package.Id().FullName()).get();
            check_deployment_result(
                result,
                L"Unhealthy current-user package identity removal");
        }

        AddPackageOptions const options;
        options.ExternalLocationUri(Uri{install_folder.c_str()});
        DeploymentResult const result =
            manager.AddPackageByUriAsync(
                Uri{(install_folder / L"Librarian.Identity.msix").c_str()},
                options).get();
        check_deployment_result(
            result,
            L"Current-user package identity registration");

        std::vector<Package> const packages =
            current_user_packages(manager);
        auto const exact = std::ranges::find_if(
            packages,
            [expected](Package const& package) {
                return comparable_version(package.Id().Version()) ==
                       expected;
            });
        if (exact == packages.end())
        {
            fail(
                L"Librarian identity registration did not become visible "
                L"for the current user.");
        }
        if (!exact->Status().VerifyIsOK())
        {
            fail(
                L"Librarian identity registration remained unhealthy for "
                L"the current user.");
        }
        validate_external_location(*exact, install_folder);
    }

    void remove_current_user_identity()
    {
        PackageManager const manager;
        for (Package const& package : current_user_packages(manager))
        {
            DeploymentResult const result =
                manager.RemovePackageAsync(package.Id().FullName()).get();
            check_deployment_result(
                result,
                L"Current-user package identity removal");
        }
    }

    void launch_desktop(std::filesystem::path const& install_folder)
    {
        std::filesystem::path const desktop =
            install_folder / L"Librarian.Windows.exe";
        HINSTANCE const result = ShellExecuteW(
            nullptr,
            L"open",
            desktop.c_str(),
            nullptr,
            install_folder.c_str(),
            SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(result) <= 32)
        {
            fail(L"Librarian could not start its desktop application.");
        }
    }

    enum class operation
    {
        launch,
        register_only,
        unregister,
    };

    operation parse_operation()
    {
        int argument_count = 0;
        LPWSTR* arguments = CommandLineToArgvW(
            GetCommandLineW(),
            &argument_count);
        if (arguments == nullptr)
        {
            fail(L"Librarian could not read its launch request.");
        }
        struct argument_guard
        {
            LPWSTR* value;
            ~argument_guard()
            {
                LocalFree(value);
            }
        } const guard{arguments};

        if (argument_count == 1)
        {
            return operation::launch;
        }
        if (argument_count == 2 &&
            wcscmp(arguments[1], L"--register-only") == 0)
        {
            return operation::register_only;
        }
        if (argument_count == 2 &&
            wcscmp(arguments[1], L"--unregister") == 0)
        {
            return operation::unregister;
        }
        fail(L"Librarian received an unsupported launcher argument.");
    }

    void show_failure(std::wstring_view message)
    {
        MessageBoxW(
            nullptr,
            std::wstring{message}.c_str(),
            L"Librarian",
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
    }
}

int WINAPI wWinMain(
    [[maybe_unused]] HINSTANCE instance,
    [[maybe_unused]] HINSTANCE previous_instance,
    [[maybe_unused]] PWSTR command_line,
    [[maybe_unused]] int show_command)
{
    operation requested = operation::launch;
    try
    {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        requested = parse_operation();
        if (requested == operation::unregister)
        {
            remove_current_user_identity();
            return 0;
        }

        std::filesystem::path const install_folder =
            validate_installation();
        payload_manifest const manifest =
            validate_payload(install_folder);
        ensure_current_user_identity(
            install_folder,
            manifest.version);
        if (requested == operation::launch)
        {
            launch_desktop(install_folder);
        }
        return 0;
    }
    catch (validation_error const& error)
    {
        OutputDebugStringW(error.message.c_str());
        if (requested == operation::launch)
        {
            show_failure(error.message);
        }
    }
    catch (winrt::hresult_error const& error)
    {
        wchar_t code[11]{};
        static_cast<void>(swprintf_s(
            code,
            L"0x%08X",
            static_cast<unsigned>(error.code().value)));
        std::wstring message{
            L"Librarian could not update package identity for this Windows "
            L"user ("};
        message.append(code);
        message.append(L"). Close Librarian processes and try again.");
        OutputDebugStringW(message.c_str());
        if (requested == operation::launch)
        {
            show_failure(message);
        }
    }
    catch (...)
    {
        constexpr std::wstring_view message{
            L"Librarian could not prepare its Windows package identity."};
        OutputDebugStringW(message.data());
        if (requested == operation::launch)
        {
            show_failure(message);
        }
    }
    return 1;
}
