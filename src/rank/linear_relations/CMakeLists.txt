cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        linear_relations.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR})

add_library(rank_linear_relations OBJECT ${SRC})

add_dependencies(rank_linear_relations libntl libgf2x)