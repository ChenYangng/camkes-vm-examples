#
# Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.8.2)

project(camkes-vm-cross-connector C)

include(${CAMKES_LOONGARCH_VM_HELPERS_PATH})
find_package(camkes-vm-linux REQUIRED)
include(${CAMKES_VM_LINUX_HELPERS_PATH})
include(${CAMKES_VM_LINUX_MODULE_HELPERS_PATH})
include(${CAMKES_VM_LINUX_SOURCE_HELPERS_PATH})
include(${CAMKES_VM_LINUX_MODULE_HELPERS_PATH})
include(ExternalProject)
include(external-project-helpers)

# Create our CPP Flags based on LOONGARCH VM config variables
if("${KernelLoongarchPlatform}" STREQUAL "3A5000")
    # set(cpp_flags "-DKERNELLoongarchPLATFORM_EXYNOS5422")
    set(linux_repo "https://github.com/foxsen/linux")
    set(linux_tag "loongarch-v2022-03-10-1")
    set(linux_arch "loongarch")
    set(linux_cross_compile "loongarch64-unknown-linux-gnu-")
# if("${KernelLoongarchPlatform}" STREQUAL "exynos5422")
#     set(cpp_flags "-DKERNELLoongarchPLATFORM_EXYNOS5422")
#     set(linux_repo "https://github.com/hardkernel/linux.git")
#     set(linux_tag "4.14.87-153")
#     set(linux_arch "arm")
#     set(linux_cross_compile "arm-linux-gnueabi-")
# elseif("${KernelLoongarchPlatform}" STREQUAL "qemu-arm-virt")
#     set(cpp_flags "-DKERNELLoongarchPLATFORM_QEMU-Loongarch-VIRT")
#     set(linux_repo "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git")
#     set(linux_tag "v4.9.189")
#     set(linux_arch "arm64")
#     set(linux_cross_compile "aarch64-linux-gnu-")
#     include(simulation)
#     set(SIMULATION ON CACHE BOOL "Generate simulation script to run qemu with the proper arguments")
#     if(SIMULATION)
#         GenerateSimulateScript()
#     endif()
endif()

AddToFileServer("bios" "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/loongarch_bios_0310_debug.bin")
AddToFileServer("linux" "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/linux")
AddToFileServer("linux-dtb" "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/linux-dtb")

# set(BUILD_CROSSVM ON)
if(BUILD_CROSSVM)
    set(rootfs_file "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/rootfs.cpio.gz")
    # Checkout and configure linux to build crossvm module
    set(linux_dir "/home/cy/linux")
    set(build_dir "${CMAKE_CURRENT_BINARY_DIR}/linux_out")
    ExternalProject_Add(
        checkout_linux
        SOURCE_DIR
        ${linux_dir}
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
    )
    add_custom_command(
        TARGET checkout_linux POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${build_dir}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${linux_dir} ${build_dir}
        COMMENT "Copying ${linux_dir} to ${build_dir}"
    )
    # ExternalProject_Add(
    #     checkout_linux
    #     GIT_REPOSITORY
    #     ${linux_repo}
    #     GIT_TAG
    #     ${linux_tag}
    #     GIT_SHALLOW
    #     1
    #     GIT_PROGRESS
    #     1
    #     BUILD_COMMAND
    #     ""
    #     INSTALL_COMMAND
    #     ""
    #     CONFIGURE_COMMAND
    #     ""
    #     SOURCE_DIR
    #     ${CMAKE_CURRENT_BINARY_DIR}/linux_out
    # )
    # Linux config and symvers are to be copied to unpacked archive
    set(linux_config "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/linux_configs/config")
    set(linux_symvers "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/linux_configs/Module.symvers")
    # Configure unpacked archive with config and symvers
    ConfigureLinux(
        ${CMAKE_CURRENT_BINARY_DIR}/linux_out
        ${linux_config}
        ${linux_symvers}
        configure_vm_linux
        ARCH
        ${linux_arch}
        CROSS_COMPILE
        ${linux_cross_compile}
        DEPENDS
        checkout_linux
    )

    # Compile CrossVM Dataport Module
    DefineLinuxModule(
        ${CAMKES_VM_LINUX_DIR}/camkes-linux-artifacts/camkes-linux-modules/camkes-connector-modules/connection
        output_module
        output_module_target
        KERNEL_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/linux_out
        ARCH
        ${linux_arch}
        CROSS_COMPILE
        ${linux_cross_compile}
        DEPENDS
        checkout_linux
        configure_vm_linux
    )
    AddFileToOverlayDir(
        "connection.ko"
        ${output_module}
        # "lib/modules/4.14.87/kernel/drivers/vmm"
        "lib/modules/vmm"
        overlay
        DEPENDS
        output_module_target
    )

    # Complile CrossVM Dataport Apps
    ExternalProject_Add(
        dataport-apps
        URL
        file:///${CAMKES_VM_LINUX_DIR}/camkes-linux-artifacts/camkes-linux-apps/camkes-connector-apps/pkgs/dataport
        BINARY_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/dataport_apps
        INSTALL_COMMAND
        ""
        BUILD_ALWAYS
        ON
        EXCLUDE_FROM_ALL
        CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )
    AddExternalProjFilesToOverlay(
        dataport-apps
        ${CMAKE_CURRENT_BINARY_DIR}/dataport_apps
        overlay
        "usr/bin"
        FILES
        dataport_read
        dataport_write
    )

    # Complile CrossVM Event Apps
    ExternalProject_Add(
        event-apps
        URL
        file:///${CAMKES_VM_LINUX_DIR}/camkes-linux-artifacts/camkes-linux-apps/camkes-connector-apps/pkgs/emits_event
        BINARY_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/emits_event_apps
        INSTALL_COMMAND
        ""
        BUILD_ALWAYS
        ON
        EXCLUDE_FROM_ALL
        CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )
    AddExternalProjFilesToOverlay(
        event-apps
        ${CMAKE_CURRENT_BINARY_DIR}/emits_event_apps
        overlay
        "usr/bin"
        FILES
        emits_event_emit
    )

    # Complile CrossVM Consume Event Apps
    ExternalProject_Add(
        consume-event-apps
        URL
        file:///${CAMKES_VM_LINUX_DIR}/camkes-linux-artifacts/camkes-linux-apps/camkes-connector-apps/pkgs/consumes_event
        BINARY_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/consume_event_apps
        INSTALL_COMMAND
        ""
        BUILD_ALWAYS
        ON
        EXCLUDE_FROM_ALL
        CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )
    AddExternalProjFilesToOverlay(
        consume-event-apps
        ${CMAKE_CURRENT_BINARY_DIR}/consume_event_apps
        overlay
        "usr/bin"
        FILES
        consumes_event_wait
    )

    # Add script to initialise dataport module
    AddFileToOverlayDir(
        "S90crossvm_module_init"
        ${CMAKE_CURRENT_SOURCE_DIR}/overlay_files/init_scripts/cross_vm_module_init
        "etc/init.d"
        overlay
    )
else()
    # User pre-configured rootfs file with crossvm modules and apps installed
    set(rootfs_file "${CAMKES_VM_IMAGES_DIR}/${KernelLoongarchPlatform}/rootfs_crossvm.cpio.gz")
endif()

# # Add script to test dataport module
# AddFileToOverlayDir(
#     "S91crossvm_test"
#     ${CMAKE_CURRENT_SOURCE_DIR}/overlay_files/init_scripts/cross_vm_test
#     "etc/init.d"
#     overlay
# )
#
# # Construct new rootfs
# AddOverlayDirToRootfs(
#     overlay
#     ${rootfs_file}
#     "buildroot"
#     "rootfs_install"
#     output_overlayed_rootfs_location
#     rootfs_target
#     GZIP
# )
# AddToFileServer("linux-initrd" ${output_overlayed_rootfs_location} DEPENDS rootfs_target)
AddToFileServer("linux-initrd" "${CAMKES_VM_IMAGES_DIR}/3A5000/rootfs_crossvm.cpio.gz")

AddCamkesCPPFlag(
    cpp_flags
    CONFIG_VARS
    VmEmmc2NoDMA
    VmVUSB
    VmVchan
    Tk1DeviceFwd
    Tk1Insecure
    VmVirtioNetVirtqueue
)

DefineCAmkESVMFileServer()

CAmkESAddImportPath(${KernelLoongarchPlatform})

# Define our VM Component with out cross vm dataports glue code
DeclareCAmkESComponent(VM SOURCES src/cross_vm_connections.c)

# Define our demo component that shares a dataport with the VM
# DeclareCAmkESComponent(CrossvmInit SOURCES components/CrossvmInit/crossvm_init.c components/CrossvmInit/aes/aes_cbc.c)
# DeclareCAmkESComponent(CrossvmInit SOURCES components/CrossvmInit/crossvm_init_rsa.c INCLUDES /home/cy/openssl/include /home/cy/openssl/build/include LIBS /home/cy/openssl/build/libcrypto.a)

# RSA1024
file(GLOB MY_SOURCES "components/CrossvmInit/rsa1024/*.c")
DeclareCAmkESComponent(CrossvmInit SOURCES ${MY_SOURCES} components/CrossvmInit/crossvm_init_rsa_1024.c)

# RSA4096
# file(GLOB MY_SOURCES "components/CrossvmInit/rsa4096/*.c")
# DeclareCAmkESComponent(CrossvmInit SOURCES ${MY_SOURCES} components/CrossvmInit/crossvm_init_rsa_4096.c)

# SHA256
# file(GLOB MY_SOURCES "components/CrossvmInit/sha256/*.c")
# DeclareCAmkESComponent(CrossvmInit SOURCES ${MY_SOURCES} components/CrossvmInit/crossvm_init_sha256.c)

# Declare root server
DeclareCAmkESRootserver(
    vm_cross_connector.camkes
    CPP_FLAGS
    ${cpp_flags}
    CPP_INCLUDES
    ${CAMKES_VM_DIR}/components/VM_LoongArch
)
