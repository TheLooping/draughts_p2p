cmake_minimum_required(VERSION 3.16)
project(draughts_p2p CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(draughts_node
    src/main.cpp
    src/cli.cpp
    src/console.cpp
    src/logger.cpp
    src/base64.cpp
    src/cipher.cpp
    src/config.cpp
    src/ciplc.cpp
    src/draughts_app.cpp
    src/io_layer.cpp
    src/overlay.cpp
    src/protocol.cpp
    src/tlv.cpp
    src/view.cpp
    src/crypto/Crypto.cpp
)

target_include_directories(draughts_node PRIVATE src)

# Use Boost.System in header-only mode (this environment may not ship libboost_system)
target_compile_definitions(draughts_node PRIVATE
    BOOST_ERROR_CODE_HEADER_ONLY
    BOOST_SYSTEM_NO_DEPRECATED
)

target_link_libraries(draughts_node PRIVATE OpenSSL::Crypto pthread)
