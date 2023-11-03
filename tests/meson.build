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
if get_option('nvme').enabled() and run_command('/usr/bin/bash', '-c', '[ ! -f /.dockerenv ]').returncode() == 1

    setup = files(
        'setup.sh'
    )
    r = run_command('/usr/bin/bash', setup, capture: true, check: false)
    message('stdout: \n', r.stdout().strip())
    message('stderr: \n', r.stderr().strip())
    assert(r.returncode()==0)

    plugin = shared_library('FakePlugin',
        '../src/NVMeFakePlugin.cpp',
        cpp_args: ['-UBOOST_ASIO_NO_DEPRECATED', '-UBOOST_ASIO_DISABLE_THREADS', '-UBOOST_ASIO_HAS_IO_URING'],
        dependencies: nvme_plugin_dep,
        link_args: ['-Wl,--unresolved-symbols=ignore-in-object-files'],
        implicit_include_directories: false,
        include_directories: '../src',
    )

    plugin_dep = declare_dependency(link_with: plugin)

    test(
        'test_nvme',
        executable(
            'test_nvme',
            'test_nvme_mi.cpp',
            '../src/NVMeSensor.cpp',
            '../src/NVMeSubsys.cpp',
            '../src/NVMeController.cpp',
            '../src/NVMeError.cpp',
            '../src/NVMeProgress.cpp',
            '../src/NVMeStorage.cpp',
            '../src/NVMeDrive.cpp',
            '../src/NVMeVolume.cpp',
            '../src/NVMePlugin.cpp',
            cpp_args: ['-UBOOST_ASIO_NO_DEPRECATED', '-UBOOST_ASIO_DISABLE_THREADS', '-UBOOST_ASIO_HAS_IO_URING','-DBUILDDIR='+ meson.current_build_dir()],
            link_args:['-export-dynamic'],
            dependencies: [ut_deps_list, nvme_deps, nlohmann_json, plugin_dep],
            implicit_include_directories: false,
            include_directories: '../src',
        ),
        env:'LD_LIBRARY_PATH=/usr/local/lib'
    )
endif

