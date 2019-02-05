cmake_minimum_required(VERSION 2.8.9)
project(f00d-partial-buster)

option(OPENSSL "Use OpenSSL instead of inbuilt AES-NI" OFF)

if (OPENSSL)
    find_package(OpenSSL REQUIRED)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Ofast -march=native -flto")
add_executable(${PROJECT_NAME} "src/main.cpp" "src/hex.cpp" "src/aes.cpp" "src/workload.cpp" "src/multishotsolver.cpp")

if (OPENSSL)
    target_compile_definitions(${PROJECT_NAME} PRIVATE OPENSSL)
    target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
endif()

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
target_link_libraries(${PROJECT_NAME} pthread)
