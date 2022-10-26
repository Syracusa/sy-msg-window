cmake_minimum_required(VERSION 3.10)

project(msgwindow)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

add_executable(udp_client client.c iface_udp.c)
target_link_libraries(udp_client msgwindow)
target_include_directories(udp_client PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/include/msgwindow/"
                          )

add_executable(udp_server server.c iface_udp.c)
target_link_libraries(udp_server msgwindow)
target_include_directories(udp_server PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/include/msgwindow/"
                          )

add_executable(serial_client client.c iface_serial.c serial_io.c)
target_link_libraries(serial_client msgwindow)
target_include_directories(serial_client PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/include/msgwindow/"
                          )

add_executable(serial_server server.c iface_serial.c serial_io.c)
target_link_libraries(serial_server msgwindow)
target_include_directories(serial_server PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/include/msgwindow/"
                          )
