cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        rank_commitment.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR})

add_library(rank_commitment OBJECT ${SRC})

add_dependencies(rank_commitment libntl libgf2x)