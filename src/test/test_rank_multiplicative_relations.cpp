#include <rank/multiplicative_relations/multiplicative_relations.h>
#include <rank/rank_commitment/rank_commitment.h>
#include "test_rank_multiplicative_relations.h"
#include "test_params.h"
#include "test_functions.h"

static void generate_keys(
        rank::multiplicative_relations::revealed_values_t *revealed_values,
        rank::multiplicative_relations::private_key_t *private_key,
        rank::multiplicative_relations::public_key_t *public_key) {

    rank::multiplicative_relations::generate_private_key(
            private_key);

    rank::multiplicative_relations::generate_public_key(
            public_key,
            private_key);

    rank::multiplicative_relations::generate_revealed_values(
            revealed_values,
            private_key,
            public_key);

}

static int generate_commitments(
        rank::multiplicative_relations::commitments_t *commitments,
        rank::multiplicative_relations::responses_t *responses,
        rank::multiplicative_relations::revealed_values_t *revealed_values,
        rank::multiplicative_relations::private_key_t *private_key,
        rank::multiplicative_relations::public_key_t *public_key) {

    rank::multiplicative_relations::random_values_t random_values;

    rank::multiplicative_relations::generate_random_values(
            &random_values,
            &revealed_values->matrices);

    ::rank::multiplicative_relations::generate_commitments(
            commitments,
            responses,
            &random_values,
            revealed_values,
            private_key,
            public_key);

    return 0;
}

int test::rank::multiplicative_relations::test_verify_0() {

    ::rank::rank_commitment::context_t context;
    ::rank::multiplicative_relations::commitments_t commitments;
    ::rank::multiplicative_relations::responses_t responses;
    ::rank::multiplicative_relations::revealed_values_t revealed_values;
    ::rank::multiplicative_relations::private_key_t private_key;
    ::rank::multiplicative_relations::public_key_t public_key;

    ::rank::rank_commitment::init(&context);

    ::rank::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &private_key,
            &public_key);

    generate_commitments(
            &commitments,
            &responses,
            &revealed_values,
            &private_key,
            &public_key);

    return ::rank::multiplicative_relations::verify_0(
            responses.r_i_1,
            responses.r_i_2,
            commitments.s_i_0,
            commitments.s_i_1,
            commitments.c_i_0,
            commitments.c_i_1,
            responses.r_i_j_1,
            responses.r_i_j_2,
            commitments.s_i_j_0,
            commitments.s_i_j_1,
            commitments.c_i_j_0,
            commitments.c_i_j_1,
            revealed_values.P_i,
            revealed_values.P_i_j,
            revealed_values.Q_i,
            revealed_values.Q_i_j,
            revealed_values.matrices.R,
            &public_key);
}

int test::rank::multiplicative_relations::test_verify_1() {

    ::rank::rank_commitment::context_t context;
    ::rank::multiplicative_relations::commitments_t commitments;
    ::rank::multiplicative_relations::responses_t responses;
    ::rank::multiplicative_relations::revealed_values_t revealed_values;
    ::rank::multiplicative_relations::private_key_t private_key;
    ::rank::multiplicative_relations::public_key_t public_key;

    ::rank::rank_commitment::init(&context);

    ::rank::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &private_key,
            &public_key);

    generate_commitments(
            &commitments,
            &responses,
            &revealed_values,
            &private_key,
            &public_key);

    return ::rank::multiplicative_relations::verify_1(
            responses.r_i_1,
            responses.r_i_3,
            commitments.s_i_0,
            commitments.s_i_2,
            commitments.c_i_0,
            commitments.c_i_2,
            responses.r_i_j_1,
            responses.r_i_j_3,
            commitments.s_i_j_0,
            commitments.s_i_j_2,
            commitments.c_i_j_0,
            commitments.c_i_j_2,
            revealed_values.P_i,
            revealed_values.P_i_j,
            revealed_values.Q_i,
            revealed_values.Q_i_j,
            revealed_values.matrices.R,
            revealed_values.commitments_i_j,
            &public_key);
}

int test::rank::multiplicative_relations::test_verify_2() {

    ::rank::rank_commitment::context_t context;
    ::rank::multiplicative_relations::commitments_t commitments;
    ::rank::multiplicative_relations::responses_t responses;
    ::rank::multiplicative_relations::revealed_values_t revealed_values;
    ::rank::multiplicative_relations::private_key_t private_key;
    ::rank::multiplicative_relations::public_key_t public_key;

    ::rank::rank_commitment::init(&context);

    ::rank::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &private_key,
            &public_key);

    generate_commitments(
            &commitments,
            &responses,
            &revealed_values,
            &private_key,
            &public_key);

    return ::rank::multiplicative_relations::verify_2(
            responses.r_i_2,
            responses.r_i_3,
            commitments.s_i_1,
            commitments.s_i_2,
            commitments.c_i_1,
            commitments.c_i_2,
            responses.r_i_j_2,
            responses.r_i_j_3,
            commitments.s_i_j_1,
            commitments.s_i_j_2,
            commitments.c_i_j_1,
            commitments.c_i_j_2,
            revealed_values.e_i_j,
            revealed_values.m_prime_i_j,
            &public_key);
}

void test::rank::multiplicative_relations::test_perf() {

    ::rank::rank_commitment::context_t context;
    ::rank::multiplicative_relations::commitments_t commitments;
    ::rank::multiplicative_relations::responses_t responses;
    ::rank::multiplicative_relations::random_values_t random_values;
    ::rank::multiplicative_relations::revealed_values_t revealed_values;
    ::rank::multiplicative_relations::private_key_t private_key;
    ::rank::multiplicative_relations::public_key_t public_key;

    ::rank::rank_commitment::init(&context);

    ::rank::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    ::rank::multiplicative_relations::generate_private_key(
            &private_key);

    ::rank::multiplicative_relations::generate_public_key(
            &public_key,
            &private_key);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::multiplicative_relations::generate_revealed_values(
                    &revealed_values,
                    &private_key,
                    &public_key);
        }
        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    double total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    double operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Rank",
            "MR random_matrices",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::multiplicative_relations::generate_random_values(
                    &random_values,
                    &revealed_values.matrices);
        }

        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Rank",
            "MR random vectors",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::multiplicative_relations::generate_commitments(
                    &commitments,
                    &responses,
                    &random_values,
                    &revealed_values,
                    &private_key,
                    &public_key);
        }

        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Rank",
            "MR proof generation",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::multiplicative_relations::verify_0(
                    responses.r_i_1,
                    responses.r_i_2,
                    commitments.s_i_0,
                    commitments.s_i_1,
                    commitments.c_i_0,
                    commitments.c_i_1,
                    responses.r_i_j_1,
                    responses.r_i_j_2,
                    commitments.s_i_j_0,
                    commitments.s_i_j_1,
                    commitments.c_i_j_0,
                    commitments.c_i_j_1,
                    revealed_values.P_i,
                    revealed_values.P_i_j,
                    revealed_values.Q_i,
                    revealed_values.Q_i_j,
                    revealed_values.matrices.R,
                    &public_key);
        }

        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Rank",
            "MR verify 0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::multiplicative_relations::verify_1(
                    responses.r_i_1,
                    responses.r_i_3,
                    commitments.s_i_0,
                    commitments.s_i_2,
                    commitments.c_i_0,
                    commitments.c_i_2,
                    responses.r_i_j_1,
                    responses.r_i_j_3,
                    commitments.s_i_j_0,
                    commitments.s_i_j_2,
                    commitments.c_i_j_0,
                    commitments.c_i_j_2,
                    revealed_values.P_i,
                    revealed_values.P_i_j,
                    revealed_values.Q_i,
                    revealed_values.Q_i_j,
                    revealed_values.matrices.R,
                    revealed_values.commitments_i_j,
                    &public_key);
        }

        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Rank",
            "MR verify 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::multiplicative_relations::verify_2(
                    responses.r_i_2,
                    responses.r_i_3,
                    commitments.s_i_1,
                    commitments.s_i_2,
                    commitments.c_i_1,
                    commitments.c_i_2,
                    responses.r_i_j_2,
                    responses.r_i_j_3,
                    commitments.s_i_j_1,
                    commitments.s_i_j_2,
                    commitments.c_i_j_1,
                    commitments.c_i_j_2,
                    revealed_values.e_i_j,
                    revealed_values.m_prime_i_j,
                    &public_key);
        }

        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Rank",
            "MR verify 2",
            total_time_in_seconds,
            operation_per_second);
}