cmake_minimum_required(VERSION 3.14)
project(rankcommitment)

set(SRC
        test_jain_commitments.cpp
        test_knowledge_of_valid_opening.cpp
        test_linear_relations.cpp
        test_multiplicative_relations.cpp
        test_rank_commitment.cpp
        test_rank_knowledge_of_valid_opening.cpp
        test_rank_linear_relations.cpp
        test_rank_multiplicative_relations.cpp
        test_utils.cpp
        test_functions.cpp
        main.cpp)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${NTL_INCLUDE_DIR})

link_directories(${OPENSSL_ROOT_DIR}/lib)

add_executable(test_rankcommitment ${SRC})

target_link_libraries(test_rankcommitment
        ntl
        gf2x
        crypto
        rankcommitment)

add_dependencies(test_rankcommitment
        libntl)