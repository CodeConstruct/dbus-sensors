project(
    'dbus-sensors',
    'cpp',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++20'
    ],
    license: 'Apache-2.0',
    version: '0.1',
    meson_version: '>=0.58.0',
)

# Enable io_uring for all daemons with below flags. 
#    '-DBOOST_ASIO_HAS_IO_URING',
#    '-DBOOST_ASIO_DISABLE_EPOLL',
#    '-DBOOST_ASIO_USE_TS_EXECUTOR_AS_DEFAULT',
# Note, there is currently an issue with CPUSensor when used in
# conjunction with io_uring. So it has not been changed to use
# random file access. But we'd like to enable it for all daemons.
# https://github.com/openbmc/dbus-sensors/issues/19

add_project_arguments(
    '-Wno-psabi',
    '-Wuninitialized',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ASIO_NO_DEPRECATED',
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_ALLOW_DEPRECATED_HEADERS',
    '-DBOOST_ASIO_HAS_THREADS',
    '-DBOOST_ASIO_HAS_IO_URING',
    '-DBOOST_ASIO_DISABLE_EPOLL',
    '-DBOOST_ASIO_USE_TS_EXECUTOR_AS_DEFAULT',
    language: 'cpp',
)

cpp = meson.get_compiler('cpp')

build_tests = get_option('tests')
gpiodcxx = dependency('libgpiodcxx',
    default_options: ['bindings=cxx'],
)

# i2c-tools doesn't ship a pkg-config file for libi2c
i2c = meson.get_compiler('cpp').find_library('i2c')

sdbusplus = dependency('sdbusplus', required : false, include_type: 'system')
if not sdbusplus.found()
  sdbusplus_proj = subproject('sdbusplus', required: true)
  sdbusplus = sdbusplus_proj.get_variable('sdbusplus_dep')
  sdbusplus = sdbusplus.as_system('system')
endif

sdbusplus_dep = dependency('sdbusplus')
sdbuspp_gen_meson_prog = find_program('sdbus++-gen-meson', native: true)
sdbusplusplus_prog = find_program('sdbus++', native: true)
sdbusplusplus_depfiles = files()

phosphor_logging_dep = dependency('phosphor-logging')

if cpp.has_header('nlohmann/json.hpp')
    nlohmann_json = declare_dependency()
else
    nlohmann_json = dependency('nlohmann_json')
endif

systemd = dependency('systemd')
systemd_system_unit_dir = systemd.get_variable(
    'systemdsystemunitdir',
    pkgconfig_define: ['prefix', get_option('prefix')])
threads = dependency('threads')

boost = dependency('boost',version : '>=1.79.0', required : false, include_type: 'system', modules: ['coroutine'])
if not boost.found()
  subproject('boost', required: false)
  boost_inc = include_directories('subprojects/boost_1_79_0/', is_system:true)
  boost  = declare_dependency(include_directories : boost_inc)
  boost = boost.as_system('system')
endif

uring = dependency('liburing', required : false, include_type: 'system')
if not uring.found()
  uring_proj = subproject('liburing', required: true)
  uring = uring_proj.get_variable('uring')
  uring = uring.as_system('system')
endif

default_deps = [
    boost,
    nlohmann_json,
    phosphor_logging_dep,
    sdbusplus,
    uring,
]

generated_sources = []
generated_others = []
yaml_sources = []
subdir('gen')
subdir('gen/xyz')

nvme_dbus_includes = include_directories('gen')

# patching the pdi with NVMe interface definitions for CI build
if get_option('build-type') == 'ci'
  phosphor_dbus_interfaces_dep = dependency('pdi')
else
  phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces', 
      required : true,
      fallback : ['phosphor_dbus_interfaces', 'pdi'],
      include_type: 'system'
  )
endif 

nvme_dbus_deps = [
  phosphor_dbus_interfaces_dep,
  sdbusplus_dep,
]

nvme_dbus_lib = static_library(
  'nvme_dbus',
  generated_sources,
  implicit_include_directories: false,
  include_directories: nvme_dbus_includes,
  dependencies: nvme_dbus_deps)

generated_files_headers = []
generated_files_cpp = []
foreach s : generated_sources
    foreach f : s.to_list()
        p = f.full_path()
        if p.endswith('.hpp')
            generated_files_headers += f
        elif p.endswith('.cpp')
            generated_files_cpp += f
        else
            error('Unknown filetype: ' + p)
        endif
    endforeach
endforeach

generated_root = meson.current_build_dir() / 'gen/'
exclude_cpp = []
foreach f : generated_files_cpp
    exclude_cpp += f.full_path().replace(generated_root, '').strip('/')
endforeach

# Install the generated header files.
exclude = exclude_cpp
foreach o : generated_others
    foreach f : o.to_list()
        exclude += f.full_path().replace(generated_root, '').strip('/')
    endforeach
endforeach
install_subdir(
    generated_root,
    exclude_files: exclude,
    install_dir: get_option('includedir')/'nvmed',
    strip_directory: true,
)

nvme_dbus_dep = declare_dependency(
  sources: generated_files_headers,
  include_directories: nvme_dbus_includes,
  link_with: nvme_dbus_lib,
  dependencies: nvme_dbus_deps)

subdir('service_files')
subdir('src')

if not build_tests.disabled()
    subdir('tests')
endif
