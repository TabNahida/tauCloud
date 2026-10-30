set_project("tauCloud")
set_version("0.0.0")
set_xmakever("3.1.1")
set_languages("cxx20")
set_warnings("allextra")
add_rules("mode.debug", "mode.release", "mode.releasedbg")

option("m0", {default = true, showmenu = true, description = "Build disposable feasibility probes"})
option("m1", {default = true, showmenu = true, description = "Build backend services and CLI"})
if has_config("m1") then
    -- Read only the verified recipe export, never update unrelated global repos.
    set_policy("network.mode", "private")
    add_repositories("taucloud-pinned .deps/recipes")
    package("taucloud-openssl")
        set_base("openssl3")
        add_versions("3.5.9", "e3365bdecdbcd88b2454a89a5ae526f6cc07cc76eca24753034b37680cd271f3")
        set_policy("package.precompiled", false)
    package_end()
    add_requires("taucloud-openssl 3.5.9", "nlohmann_json v3.12.0", "sqlite3 3.51.0+300", "pugixml v1.15", "utf8proc v2.11.3", {system = false})
end
option("sanitizers", {default = false, showmenu = true, description = "ASan and UBSan (Linux)"})

-- Intentionally compile only the locked PACE runtime. Its top-level xmake file
-- sets project-global options and enables unrelated examples/tests by default.
-- Acquisition and source integrity are checked by scripts/run_m0.py.
target("pace_runtime")
    set_kind("static")
    add_files(".deps/pace/src/runtime/*.cpp")
    add_includedirs(".deps/pace/include", {public = true})
    before_build(function ()
        os.vrunv(is_host("windows") and "python" or "python3", {"scripts/fetch_pace.py", "--verify"})
    end)
    if is_plat("windows") then
        add_syslinks("ws2_32", "bcrypt", {public = true})
        add_defines("WIN32_LEAN_AND_MEAN", "NOMINMAX", "_WIN32_WINNT=0x0A00", {public = true})
    else
        add_syslinks("pthread", {public = true})
    end
target_end()

if has_config("sanitizers") and is_plat("linux") then
    -- Applied to all targets, including PACE, through explicit target iteration below.
    for _, name in ipairs({"pace_runtime"}) do
        target(name)
            add_cxxflags("-fsanitize=address,undefined", "-fno-omit-frame-pointer")
        target_end()
    end
    add_cxxflags("-fsanitize=address,undefined", "-fno-omit-frame-pointer")
    add_ldflags("-fsanitize=address,undefined")
end

if has_config("m1") then
    target("taucloud_core")
        set_kind("static")
        add_files("src/*.cpp", ".deps/pace/src/networking/*.cpp", ".deps/pace/src/extensions/tls.cpp", ".deps/pace/src/application/http.cpp", ".deps/pace/src/application/http_url.cpp")
        add_deps("pace_runtime")
        add_includedirs("include", {public = true})
        add_packages("taucloud-openssl", "nlohmann_json", "sqlite3", "pugixml", "utf8proc", {public = true})
        add_defines("PACE_HAS_TLS", "PACE_HAS_HTTP1", {public = true})
        before_build(function ()
            os.vrunv(is_host("windows") and "python" or "python3", {"scripts/fetch_pace.py", "--dependency", "recipes", "--verify"})
        end)
        if is_plat("windows") then add_syslinks("advapi32", "crypt32", "psapi", "iphlpapi", {public = true}) end
    target_end()
    target("taucloud_m1_tests")
        set_kind("binary")
        add_files("tests/m1_core.cpp")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 40})
    target_end()
    target("taucloud_m2_tests")
        set_kind("binary")
        -- Fault hooks exist only in this native adapter object, never service binaries.
        add_files("tests/m2_core.cpp", "src/native_files.cpp")
        add_defines("TAUCLOUD_TEST_IO")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 60})
    target_end()
    target("taucloud_m3_tests")
        set_kind("binary")
        add_files("tests/m3_core.cpp")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 60})
    target_end()
    target("taucloud_m7_tests")
        set_kind("binary")
        add_files("tests/m7_core.cpp", "src/native_files.cpp")
        add_defines("TAUCLOUD_TEST_IO")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 60})
    target_end()
    target("taucloud_m6_tests")
        set_kind("binary")
        add_files("tests/m6_core.cpp")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 60})
    target_end()
    target("taucloud_m5_tests")
        set_kind("binary")
        add_files("tests/m5_core.cpp", "src/native_files.cpp")
        add_defines("TAUCLOUD_TEST_IO")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 60})
    target_end()
    target("taucloud_m4_tests")
        set_kind("binary")
        add_files("tests/m4_core.cpp")
        add_deps("taucloud_core")
        add_tests("default", {run_timeout = 60})
    target_end()
    for _, role in ipairs({"supervisor", "api", "webdav", "ftp", "smb", "nfs", "identity", "file", "file_1", "file_2", "file_3", "protocol", "monitor", "updater", "storage_admin", "helper", "ctl"}) do
        target("taucloud_" .. role)
            set_kind("binary")
            add_files("apps/main.cpp")
            add_defines('TAUCLOUD_ROLE="' .. role .. '"')
            add_deps("taucloud_core")
        target_end()
    end
end
if is_plat("windows") then add_cxxflags("/utf-8") end

if has_config("m0") then
    target("taucloud_m0_runtime")
        set_kind("binary")
        add_files("experiments/m0/runtime.cpp")
        add_includedirs("include")
        add_deps("pace_runtime")
        add_tests("default", {run_timeout = 20})
    target_end()
    target("taucloud_m0_filesystem")
        set_kind("binary")
        add_files("experiments/m0/filesystem.cpp")
        add_tests("default", {run_timeout = 20})
    target_end()
end
