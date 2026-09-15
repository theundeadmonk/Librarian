// Compile the transport once, in this test translation unit, to exercise its
// private CBOR decoder and retry policy without exporting production test hooks.
// These tests do not activate apps, open pipes, or read user discovery/vault files.
#include "../../apps/windows/Librarian.Windows/DesktopTransport.cpp"

#include <iostream>

namespace librarian::windows
{
    namespace
    {
        std::wstring const current_package{
            L"TheUndeadMonk.Librarian.Development_0.1.10.0_neutral__wecffq6n18kem"};
        std::wstring const older_package{
            L"TheUndeadMonk.Librarian.Development_0.1.9.0_neutral__wecffq6n18kem"};

        struct descriptor_fixture
        {
            std::wstring package = current_package;
            std::wstring pipe = std::wstring{pipe_prefix} + std::wstring(32U, L'a');
            std::uint64_t pid = 42U;
            std::uint64_t creation = 123U;
            std::uint64_t minimum = 1U;
            std::uint64_t maximum = 1U;
            std::vector<std::uint8_t> nonce = std::vector<std::uint8_t>(32U, 1U);

            secret_bytes encode() const
            {
                cbor_writer writer;
                writer.array(8U);
                writer.unsigned_value(1U);
                auto const pipe_bytes = pipe.empty() ? secret_bytes{} : utf8(pipe);
                writer.text(pipe_bytes.value());
                writer.unsigned_value(pid);
                writer.unsigned_value(creation);
                auto const package_bytes = package.empty() ? secret_bytes{} : utf8(package);
                writer.text(package_bytes.value());
                writer.unsigned_value(minimum);
                writer.unsigned_value(maximum);
                writer.bytes(nonce);
                return writer.take();
            }
        };

        struct discovery_tests
        {
            int failures = 0;

            void check(bool condition, char const* name)
            {
                (condition ? std::cout : std::cerr) << (condition ? "[PASS] " : "[FAIL] ")
                    << name << '\n';
                if (!condition) ++failures;
            }

            template<typename Action>
            void rejects(Action action, transport_error expected, char const* name)
            {
                try { action(); }
                catch (transport_exception const& error)
                {
                    check(error.error() == expected, name);
                    return;
                }
                check(false, name);
            }

            void rejects_descriptor(descriptor_fixture const& fixture,
                transport_error expected, char const* name)
            {
                auto const bytes = fixture.encode();
                rejects([&] { decode_descriptor(bytes.value(), current_package); }, expected, name);
            }
        };

        void test_descriptor_versions(discovery_tests& test)
        {
            descriptor_fixture fixture;
            auto const bytes = fixture.encode();
            auto const endpoint = decode_descriptor(bytes.value(), current_package);
            test.check(endpoint.package_full_name == current_package && endpoint.process_id == fixture.pid &&
                endpoint.creation_time == fixture.creation && endpoint.pipe_name == fixture.pipe,
                "current-package discovery preserves all connection metadata");

            for (auto const* version : {L"0.1.9.0", L"0.1.6.0", L"0.1.0.65535", L"0.0.65535.65535"})
            {
                fixture.package = std::wstring{L"TheUndeadMonk.Librarian.Development_"} + version +
                    L"_neutral__wecffq6n18kem";
                test.rejects_descriptor(fixture, transport_error::unavailable,
                    "a strictly older exact package identity triggers rediscovery, never a connection");
            }

            for (auto const* package : {
                L"TheUndeadMonk.Librarian.Development_0.1.11.0_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.1.10.1_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.2.0.0_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Other_0.1.9.0_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.1.9.0_neutral__8wekyb3d8bbwe",
                L"TheUndeadMonk.Librarian.Development_0.1.9.0_x64__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.1.9.0_neutral_resources_wecffq6n18kem",
                L"theundeadmonk.Librarian.Development_0.1.9.0_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_00.1.9.0_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.1.65536.0_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.1.9_neutral__wecffq6n18kem",
                L"TheUndeadMonk.Librarian.Development_0.1.-1.0_neutral__wecffq6n18kem",
                L"not-a-package", L""})
            {
                fixture.package = package;
                test.rejects_descriptor(fixture, transport_error::invalid,
                    "newer, foreign, noncanonical, and malformed package descriptors remain fatal");
            }
            fixture.package = older_package + std::wstring(1U, L'\0') + L"ignored";
            test.rejects_descriptor(fixture, transport_error::invalid,
                "embedded NUL cannot truncate package-identity validation");
        }

        void test_malformed_old_descriptors(discovery_tests& test)
        {
            descriptor_fixture original;
            original.package = older_package;
            for (int fault = 0; fault < 14; ++fault)
            {
                auto fixture = original;
                switch (fault)
                {
                case 0: fixture.pid = 0U; break;
                case 1: fixture.pid = static_cast<std::uint64_t>(MAXDWORD) + 1U; break;
                case 2: fixture.creation = 0U; break;
                case 3: fixture.minimum = 0U; break;
                case 4: fixture.minimum = 2U; break;
                case 5: fixture.maximum = 0U; break;
                case 6: fixture.nonce.assign(32U, 0U); break;
                case 7: fixture.nonce.resize(31U); break;
                case 8: fixture.nonce.resize(33U); break;
                case 9: fixture.pipe = L"\\\\.\\pipe\\other"; break;
                case 10: fixture.pipe.back() = L'G'; break;
                case 11: fixture.pipe.pop_back(); break;
                case 12: fixture.pipe += L'a'; break;
                case 13: fixture.pipe = std::wstring{pipe_prefix} + std::wstring(32U, L'0'); break;
                }
                test.rejects_descriptor(fixture, transport_error::invalid,
                    "old version never bypasses other discovery schema and metadata checks");
            }

            auto const original_bytes = original.encode();
            for (std::size_t length = 0U; length < original_bytes.size(); ++length)
            {
                test.rejects([&] {
                    decode_descriptor(std::span<std::uint8_t const>{original_bytes.value()}.first(length),
                        current_package);
                }, transport_error::invalid, "every truncated old descriptor remains fatal");
            }
            auto trailing = original.encode();
            trailing.value().push_back(0U);
            test.rejects([&] { decode_descriptor(trailing.value(), current_package); },
                transport_error::invalid, "trailing bytes cannot become stale-version recovery");
            auto wrong_schema = original.encode();
            wrong_schema.value()[1U] = 2U;
            test.rejects([&] { decode_descriptor(wrong_schema.value(), current_package); },
                transport_error::invalid, "unknown descriptor format remains fatal");
        }

        void test_activation_retry(discovery_tests& test)
        {
            for (int scenario = 0; scenario < 7; ++scenario)
            {
                // 0 current, 1 upgraded/recovered, 2 perpetually stale, 3 foreign,
                // 4 cancelled before discovery, 5 cancelled during retry,
                // 6 current discovery but failed peer/handshake authentication.
                std::atomic_bool closed{scenario == 4};
                int attempts = 0;
                int activations = 0;
                int connections = 0;
                int pauses = 0;
                descriptor_fixture fixture;
                if (scenario != 0 && scenario != 6) fixture.package = older_package;
                if (scenario == 3) fixture.package = L"Other_0.1.9.0_neutral__wecffq6n18kem";
                std::optional<transport_error> error;
                try
                {
                    retry_agent_connection(closed, [&] {
                        ++attempts;
                        auto const bytes = fixture.encode();
                        auto const endpoint = decode_descriptor(bytes.value(), current_package);
                        test.check(endpoint.package_full_name == current_package,
                            "only a freshly validated current-package endpoint reaches connection");
                        ++connections;
                        if (scenario == 6) fail(transport_error::invalid);
                        return 42;
                    }, [&] {
                        ++activations;
                        // Models the registered current agent publishing its own endpoint.
                        if (scenario == 1) fixture.package = current_package;
                    }, [&] { return pauses >= 2; }, [&] {
                        ++pauses;
                        if (scenario == 5) closed.store(true);
                    });
                }
                catch (transport_exception const& caught) { error = caught.error(); }
                switch (scenario)
                {
                case 0:
                    test.check(!error && attempts == 1 && connections == 1 && activations == 0,
                        "current discovery connects without unnecessary activation"); break;
                case 1:
                    test.check(!error && attempts == 2 && connections == 1 && activations == 1,
                        "upgrade recovery activates once then reloads before connecting"); break;
                case 2:
                    test.check(error == transport_error::unavailable && attempts == 3 &&
                        connections == 0 && activations == 1,
                        "persistent old discovery expires without connection or repeated activation"); break;
                case 3:
                    test.check(error == transport_error::invalid && attempts == 1 &&
                        connections == 0 && activations == 0,
                        "foreign discovery fails closed without activation"); break;
                case 4:
                    test.check(error == transport_error::cancelled && attempts == 0 && activations == 0,
                        "pre-cancelled startup neither reads discovery nor activates"); break;
                case 5:
                    test.check(error == transport_error::cancelled && attempts == 1 &&
                        connections == 0 && activations == 1,
                        "cancellation during recovery prevents a subsequent connection"); break;
                case 6:
                    test.check(error == transport_error::invalid && attempts == 1 &&
                        connections == 1 && activations == 0,
                        "invalid current peer or handshake remains fatal without activation"); break;
                }
            }
        }
    }

    bool run_desktop_discovery_tests()
    {
        discovery_tests test;
        test_descriptor_versions(test);
        test_malformed_old_descriptors(test);
        test_activation_retry(test);
        return test.failures == 0;
    }
}

bool TestDesktopDiscovery()
{
    return librarian::windows::run_desktop_discovery_tests();
}
