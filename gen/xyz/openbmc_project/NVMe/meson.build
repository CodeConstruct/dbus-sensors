# Generated file; do not modify.
subdir('NVMeAdmin')
generated_others += custom_target(
    'xyz/openbmc_project/NVMe/NVMeAdmin__markdown'.underscorify(),
    input: [ '../../../../yaml/xyz/openbmc_project/NVMe/NVMeAdmin.interface.yaml',  ],
    output: [ 'NVMeAdmin.md' ],
    depend_files: sdbusplusplus_depfiles,
    command: [
        sdbuspp_gen_meson_prog, '--command', 'markdown',
        '--output', meson.current_build_dir(),
        '--tool', sdbusplusplus_prog,
        '--directory', meson.current_source_dir() / '../../../../yaml',
        'xyz/openbmc_project/NVMe/NVMeAdmin',
    ],
)

