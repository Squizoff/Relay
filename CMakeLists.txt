cmake_minimum_required(VERSION 3.16)

project(relay C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -O2)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(SERVER_DIR ${CMAKE_SOURCE_DIR}/server)
set(CLIENT_DIR ${CMAKE_SOURCE_DIR}/client)
set(COMMON_DIR ${CMAKE_SOURCE_DIR}/common)

file(GLOB_RECURSE SERVER_C_SOURCES CONFIGURE_DEPENDS
    "${SERVER_DIR}/*.c"
)

file(GLOB_RECURSE CLIENT_CPP_SOURCES CONFIGURE_DEPENDS
    "${CLIENT_DIR}/*.cpp"
    "${CLIENT_DIR}/*.h"
)

file(GLOB_RECURSE COMMON_C_SOURCES CONFIGURE_DEPENDS
    "${COMMON_DIR}/*.c"
)

file(GLOB_RECURSE PROJECT_HEADERS CONFIGURE_DEPENDS
    "${COMMON_DIR}/*.h"
    "${CLIENT_DIR}/*.h"
    "${SERVER_DIR}/*.h"
)

file(GLOB_RECURSE CLIENT_C_SOURCES CONFIGURE_DEPENDS
    "${CLIENT_DIR}/*.c"
)

set(SERVER_SOURCES
    ${SERVER_C_SOURCES}
    ${COMMON_C_SOURCES}
    ${PROJECT_HEADERS}
)

set(CLIENT_SOURCES
    ${CLIENT_CPP_SOURCES}
    ${CLIENT_C_SOURCES}
    ${COMMON_C_SOURCES}
    ${PROJECT_HEADERS}
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

find_package(Qt6 COMPONENTS Widgets QUIET)
if(Qt6_FOUND)
    set(QT_LIB Qt6::Widgets)
else()
    find_package(Qt5 REQUIRED COMPONENTS Widgets)
    set(QT_LIB Qt5::Widgets)
endif()

add_executable(server ${SERVER_SOURCES})
target_include_directories(server PRIVATE ${COMMON_DIR} ${SERVER_DIR})
target_link_libraries(server PRIVATE OpenSSL::Crypto OpenSSL::SSL)

if(WIN32)
    target_link_libraries(server PRIVATE ws2_32 bcrypt)
endif()

add_executable(client ${CLIENT_SOURCES})
target_include_directories(client PRIVATE
    ${COMMON_DIR}
    ${CLIENT_DIR}
)
target_link_libraries(client PRIVATE
    ${QT_LIB}
    OpenSSL::Crypto
    OpenSSL::SSL
)

if(WIN32)
    target_link_libraries(client PRIVATE ws2_32 bcrypt)
endif()

install(TARGETS server client RUNTIME DESTINATION bin)

add_custom_target(all_targets DEPENDS server client)