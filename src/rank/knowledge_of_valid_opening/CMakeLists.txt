cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        knowledge_of_valid_opening.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR})

add_library(rank_knowledge_of_valid_opening OBJECT ${SRC})

add_dependencies(rank_knowledge_of_valid_opening libntl libgf2x)