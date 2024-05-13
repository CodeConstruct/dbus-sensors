gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
gmock_dep = dependency('gmock', disabler: true, required: false)
if not gtest_dep.found() or not gmock_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ]
        )
        gmock_dep = gtest_proj.dependency('gmock')
    else
        assert(
            not get_option('tests').enabled(),
            'Googletest is required if tests are enabled'
        )
    endif
endif

dbus_run_session = find_program('dbus-run-session')
phosphor_objmgr_dep = dependency('phosphor-objmgr')
mapper = find_program('mapperx')
mapper_wrapper = find_program('mapper_wrapper')

add_test_setup(
    'openbmc',
    exe_wrapper: [
        dbus_run_session,
        '--',
        mapper_wrapper,
        mapper.full_path()
    ],
    gdb: false,
    is_default: true
)

# 49d4e594e895 ("scripts/unit-test: meson: Support custom valgrind setup")
# https://github.com/openbmc/openbmc-build-scripts/commit/49d4e594e8959cd8764f9c1fd504413ff836c5a7
add_test_setup(
    'valgrind',
    exe_wrapper: [
        dbus_run_session,
        '--',
        mapper_wrapper,
        mapper.full_path(),
        find_program('valgrind'),
        '--error-exitcode=1'
    ],
    gdb: false,
    is_default: false,
    timeout_multiplier: 10,
)

ut_deps_list = [
    gtest_dep,
    gmock_dep,
]

ut_deps_list += default_deps

test(
    'test_utils',
    executable(
        'test_utils',
        'test_Utils.cpp',
        '../src/Utils.cpp',
        dependencies: ut_deps_list,
        implicit_include_directories: false,
        include_directories: '../src',
    )
)

# enable the nvme unit test only for CI docker because the test requires dbus
if get_option('nvme').enabled()
    plugin = shared_library('FakePlugin',
        '../src/NVMeFakePlugin.cpp',
        cpp_args: ['-UBOOST_ASIO_NO_DEPRECATED', '-UBOOST_ASIO_DISABLE_THREADS', '-UBOOST_ASIO_HAS_IO_URING'],
        dependencies: nvme_plugin_dep,
        link_args: ['-Wl,--unresolved-symbols=ignore-in-object-files'],
        implicit_include_directories: false,
        include_directories: '../src',
    )
    plugin_dep = declare_dependency(link_with: plugin)

    test_nvme_bin = executable(
        'test_nvme',
        'test_nvme_mi.cpp',
        '../src/NVMeController.cpp',
        '../src/NVMeDrive.cpp',
        '../src/NVMeError.cpp',
        '../src/NVMePlugin.cpp',
        '../src/NVMeProgress.cpp',
        '../src/NVMeSensor.cpp',
        '../src/NVMeStorage.cpp',
        '../src/NVMeSubsys.cpp',
        '../src/NVMeVolume.cpp',
        cpp_args: ['-UBOOST_ASIO_NO_DEPRECATED', '-UBOOST_ASIO_DISABLE_THREADS', '-UBOOST_ASIO_HAS_IO_URING','-DBUILDDIR='+ meson.current_build_dir(), '-DNVME_UNIT_TEST=1'],
        link_args:['-export-dynamic'],
        dependencies: [ut_deps_list, nvme_deps, nlohmann_json, plugin_dep],
        implicit_include_directories: false,
        include_directories: '../src',
    )
    test('test_nvme',
        test_nvme_bin,
        depends: [ mapper ],
        env:'LD_LIBRARY_PATH=/usr/local/lib')

    test_nvme_recovery_bin = executable('test_nvme_recovery',
        'test_nvme_mi_recovery.cpp',
        'libnvme_mock.cpp',
        'libnvme_mi_mock.cpp',
        '../src/NVMeController.cpp',
        '../src/NVMeDevice.cpp',
        '../src/NVMeDrive.cpp',
        '../src/NVMeError.cpp',
        '../src/NVMeMi.cpp',
        '../src/NVMePlugin.cpp',
        '../src/NVMeProgress.cpp',
        '../src/NVMeSensor.cpp',
        '../src/NVMeStorage.cpp',
        '../src/NVMeSubsys.cpp',
        '../src/NVMeVolume.cpp',
        cpp_args: ['-UBOOST_ASIO_NO_DEPRECATED', '-UBOOST_ASIO_DISABLE_THREADS', '-UBOOST_ASIO_HAS_IO_URING','-DBUILDDIR='+ meson.current_build_dir(), '-DNVME_UNIT_TEST=1'],
        link_args:['-export-dynamic'],
        dependencies: [
            default_deps,
            i2c,
            libnvme.partial_dependency(compile_args: true, includes: true).as_system(),
            libnvme_mi.partial_dependency(compile_args: true, includes: true).as_system(),
            nlohmann_json,
            nvme_dbus_dep,
            pdi_dep,
            plugin_dep,
            threads,
            thresholds_dep,
            ut_deps_list,
            utils_dep,
        ],
        implicit_include_directories: false,
        include_directories: '../src',
    )
    test('test_nvme_recovery',
        test_nvme_recovery_bin,
        depends: [ mapper ],
        env:'LD_LIBRARY_PATH=/usr/local/lib',
    )
endif

