cmake_minimum_required(VERSION 3.10)
project(SecureCommunication VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost libraries
find_package(Boost REQUIRED COMPONENTS system)
include_directories(${Boost_INCLUDE_DIRS})

# Set compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/trezor-crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb
    ${CMAKE_CURRENT_SOURCE_DIR}/proto
)

# Compile Protocol Buffers
set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTO_FILES
    ${PROTO_SRC_DIR}/secure_communication.pb.c
)

# Trezor Crypto source files
set(TREZOR_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/trezor-crypto)
set(TREZOR_SRCS
    ${TREZOR_SRC_DIR}/sha2.c
    ${TREZOR_SRC_DIR}/rand.c
    ${TREZOR_SRC_DIR}/memzero.c
    ${TREZOR_SRC_DIR}/bignum.c
    ${TREZOR_SRC_DIR}/ecdsa.c
    ${TREZOR_SRC_DIR}/secp256k1.c
    ${TREZOR_SRC_DIR}/hasher.c
    ${TREZOR_SRC_DIR}/base58.c
    ${TREZOR_SRC_DIR}/address.c
    ${TREZOR_SRC_DIR}/ripemd160.c
    ${TREZOR_SRC_DIR}/sha3.c
    ${TREZOR_SRC_DIR}/blake256.c
    ${TREZOR_SRC_DIR}/blake2b.c
    ${TREZOR_SRC_DIR}/groestl.c
    ${TREZOR_SRC_DIR}/hmac.c
    ${TREZOR_SRC_DIR}/pbkdf2.c
    ${TREZOR_SRC_DIR}/rfc6979.c
    ${TREZOR_SRC_DIR}/hmac_drbg.c
)

# Nanopb source files
set(NANOPB_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/nanopb)
set(NANOPB_SRCS
    ${NANOPB_SRC_DIR}/pb_common.c
    ${NANOPB_SRC_DIR}/pb_encode.c
    ${NANOPB_SRC_DIR}/pb_decode.c
)

# Create library for common code
add_library(common OBJECT
    ${TREZOR_SRCS}
    ${NANOPB_SRCS}
    ${PROTO_FILES}
)

# Common source files
set(COMMON_SRCS
    $<TARGET_OBJECTS:common>
)

# Add client executable
add_executable(client src/client.cpp ${COMMON_SRCS})
target_link_libraries(client ${Boost_LIBRARIES} pthread)

# Add server executable
add_executable(server src/server.cpp ${COMMON_SRCS})
target_link_libraries(server ${Boost_LIBRARIES} pthread)

# Add test executable
add_executable(secure_communication_test src/test.cpp ${COMMON_SRCS})
target_link_libraries(secure_communication_test ${Boost_LIBRARIES} pthread)

# Define rules for generating protocol buffer files (normally this would be done with a custom command)
# For this example, we assume the .pb.c and .pb.h files are already generated

# Build instructions for users
message(STATUS "Build with: cmake -S . -B build && cmake --build build")
message(STATUS "Run server: ./build/server")
message(STATUS "Run client: ./build/client")
message(STATUS "Run test: ./build/secure_communication_test") 