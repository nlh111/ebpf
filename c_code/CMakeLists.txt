cmake_minimum_required(VERSION 3.10)

project(HIDS)

get_filename_component(PARENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(zombie_proces_src ${src_dir}/zombie.c)
set(test_rust_ffi_src ${src_dir}/main.c)

add_executable(zombie ${zombie_proces_src})
add_executable(c_test ${test_rust_ffi_src})

if (CMAKE_CONTROL_NAME STREQUAL "ADD")
    target_link_libraries(c_test ${PARENT_DIR}/hids/target/aarch64-unknown-linux-gnu/release/libhids.a
    m pthread dl)
elseif (CMAKE_CONTROL_NAME STREQUAL "XCD")
    target_link_libraries(c_test ${PARENT_DIR}/hids/target/aarch64-linux-android/release/libhids.a
    m dl)
else()
    target_link_libraries(c_test ${PARENT_DIR}/hids/target/release/libhids.a 
    m pthread dl)
endif()
