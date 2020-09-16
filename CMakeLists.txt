cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(CMAKE_CXX_STANDARD 11)

include(ExternalProject)

include(3rdparty/gf2x.cmake)
include(3rdparty/ntl.cmake)

add_subdirectory(src/hamming/jain_commitment)
add_subdirectory(src/hamming/knowledge_of_valid_opening)
add_subdirectory(src/hamming/linear_relations)
add_subdirectory(src/hamming/multiplicative_relations)
add_subdirectory(src/rank/rank_commitment)
add_subdirectory(src/rank/knowledge_of_valid_opening)
add_subdirectory(src/rank/linear_relations)
add_subdirectory(src/rank/multiplicative_relations)
add_subdirectory(src/utils)
add_subdirectory(src/test)

add_library(rankcommitment STATIC
        $<TARGET_OBJECTS:jain_commitment>
        $<TARGET_OBJECTS:valid_opening>
        $<TARGET_OBJECTS:linear_relations>
        $<TARGET_OBJECTS:multiplicative_relations>
        $<TARGET_OBJECTS:rank_commitment>
        $<TARGET_OBJECTS:rank_knowledge_of_valid_opening>
        $<TARGET_OBJECTS:rank_linear_relations>
        $<TARGET_OBJECTS:rank_multiplicative_relations>
        $<TARGET_OBJECTS:utils>)

add_dependencies(rankcommitment libntl libgf2x)
