cmake_minimum_required(VERSION 3.10)

project(msgwindow)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

add_library(msgwindow lib/msg_window.c)
target_include_directories(msgwindow PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/include/"
                          )

add_executable(udp_client app/client.c app/iface_udp.c)
target_link_libraries(udp_client msgwindow)
target_include_directories(udp_client PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/app"
                          )

add_executable(udp_server app/server.c app/iface_udp.c)
target_link_libraries(udp_server msgwindow)
target_include_directories(udp_server PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/app"
                          )