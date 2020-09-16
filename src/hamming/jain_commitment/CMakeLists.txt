cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        jain_commitment.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR})

add_library(jain_commitment OBJECT ${SRC})

add_dependencies(jain_commitment libntl libgf2x)