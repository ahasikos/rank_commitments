cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        knowledge_of_valid_opening.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR})

add_library(valid_opening OBJECT ${SRC})

add_dependencies(valid_opening libntl libgf2x)