cmake_minimum_required(VERSION 3.16)
project(draughts_p2p CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(draughts_node
    src/ChatCore/main.cpp
    src/ChatCore/cli.cpp
    src/ChatCore/console.cpp
    src/ChatCore/logger.cpp
    src/ChatCore/base64.cpp
    src/ChatCore/cipher.cpp
    src/ChatCore/config.cpp
    src/ChatCore/ciplc.cpp
    src/ChatCore/draughts_app.cpp
    src/ChatCore/node.cpp
    src/ChatCore/topod_client.cpp
    src/ChatCore/protocol.cpp
    src/ChatCore/tlv.cpp
    src/ChatCore/crypto/Crypto.cpp
)

target_include_directories(draughts_node PRIVATE src/ChatCore)

# Use Boost.System in header-only mode (this environment may not ship libboost_system)
target_compile_definitions(draughts_node PRIVATE
    BOOST_ERROR_CODE_HEADER_ONLY
    BOOST_SYSTEM_NO_DEPRECATED
)

target_link_libraries(draughts_node PRIVATE OpenSSL::Crypto pthread)

add_custom_command(TARGET draughts_node POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE:draughts_node>
            $<TARGET_FILE_DIR:draughts_node>/ChatCore
)
