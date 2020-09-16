cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        utils.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR}
        ${OPENSSL_ROOT_DIR}/include)

add_library(utils OBJECT ${SRC})