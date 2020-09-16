#include "test_multiplicative_relations.h"
#include "test_params.h"
#include "test_functions.h"

#include <hamming/multiplicative_relations/multiplicative_relations.h>
#include <utils/utils.h>

static void generate_keys(
        hamming_metric::multiplicative_relations::revealed_values_t *revealed_values,
        hamming_metric::multiplicative_relations::private_key_t *private_key,
        hamming_metric::multiplicative_relations::public_key_t *public_key) {

    ::hamming_metric::multiplicative_relations::generate_private_key(
            private_key);

    ::hamming_metric::multiplicative_relations::generate_public_key(
            public_key,
            private_key);

    ::hamming_metric::multiplicative_relations::generate_revealed_values(
            revealed_values,
            private_key,
            public_key);
}

static void generate_commitments(
        hamming_metric::multiplicative_relations::responses_t *responses,
        hamming_metric::multiplicative_relations::commitments_t *commitments,
        hamming_metric::multiplicative_relations::revealed_values_t *revealed_values,
        hamming_metric::multiplicative_relations::private_key_t *private_key,
        hamming_metric::multiplicative_relations::public_key_t *public_key) {

    ::hamming_metric::multiplicative_relations::random_values_t random_values;

    ::hamming_metric::multiplicative_relations::generate_random_values(
            &random_values,
            &revealed_values->matrices);

    ::hamming_metric::multiplicative_relations::generate_commitments_and_responses(
            responses,
            commitments,
            &random_values,
            revealed_values,
            public_key,
            private_key);
}

int test::hamming_metric::multiplicative_relations::verify_0() {

    ::hamming_metric::multiplicative_relations::responses_t responses;
    ::hamming_metric::multiplicative_relations::commitments_t commitments;
    ::hamming_metric::multiplicative_relations::private_key_t private_key;
    ::hamming_metric::multiplicative_relations::public_key_t public_key;
    ::hamming_metric::multiplicative_relations::revealed_values_t revealed_values;

    ::hamming_metric::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &private_key,
            &public_key);

    ::generate_commitments(
            &responses,
            &commitments,
            &revealed_values,
            &private_key,
            &public_key);

    return ::hamming_metric::multiplicative_relations::verify_0(
            commitments.c_i_0,
            commitments.r_i_0,
            responses.t_i_0,
            commitments.c_i_1,
            commitments.r_i_1,
            responses.t_i_1,
            commitments.c_i_j_0,
            commitments.r_i_j_0,
            responses.t_i_j_0,
            commitments.c_i_j_1,
            commitments.r_i_j_1,
            responses.t_i_j_1,
            revealed_values.P_i,
            revealed_values.P_i_j,
            revealed_values.matrices.R,
            &public_key);
}

int test::hamming_metric::multiplicative_relations::verify_1() {

    ::hamming_metric::multiplicative_relations::responses_t responses;
    ::hamming_metric::multiplicative_relations::commitments_t commitments;
    ::hamming_metric::multiplicative_relations::private_key_t private_key;
    ::hamming_metric::multiplicative_relations::public_key_t public_key;
    ::hamming_metric::multiplicative_relations::revealed_values_t revealed_values;

    ::hamming_metric::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &private_key,
            &public_key);

    ::generate_commitments(
            &responses,
            &commitments,
            &revealed_values,
            &private_key,
            &public_key);

    return ::hamming_metric::multiplicative_relations::verify_1(
            commitments.c_i_0,
            commitments.r_i_0,
            responses.t_i_0,
            commitments.c_i_2,
            commitments.r_i_2,
            responses.t_i_2,
            commitments.c_i_j_0,
            commitments.r_i_j_0,
            responses.t_i_j_0,
            commitments.c_i_j_2,
            commitments.r_i_j_2,
            responses.t_i_j_2,
            revealed_values.P_i,
            revealed_values.P_i_j,
            revealed_values.matrices.R,
            revealed_values.matrices._R,
            revealed_values.commitments_i_j,
            &public_key);
}

int test::hamming_metric::multiplicative_relations::verify_2() {

    ::hamming_metric::multiplicative_relations::responses_t responses;
    ::hamming_metric::multiplicative_relations::commitments_t commitments;
    ::hamming_metric::multiplicative_relations::private_key_t private_key;
    ::hamming_metric::multiplicative_relations::public_key_t public_key;
    ::hamming_metric::multiplicative_relations::revealed_values_t revealed_values;

    ::hamming_metric::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &private_key,
            &public_key);

    ::generate_commitments(
            &responses,
            &commitments,
            &revealed_values,
            &private_key,
            &public_key);

    return ::hamming_metric::multiplicative_relations::verify_2(
            commitments.c_i_1,
            commitments.r_i_1,
            responses.t_i_1,
            commitments.c_i_2,
            commitments.r_i_2,
            responses.t_i_2,
            commitments.c_i_j_1,
            commitments.r_i_j_1,
            responses.t_i_j_1,
            commitments.c_i_j_2,
            commitments.r_i_j_2,
            responses.t_i_j_2,
            revealed_values.e_i_j,
            revealed_values.m_prime_i_j,
            &public_key);
}

void test::hamming_metric::multiplicative_relations::test_perf() {

    ::hamming_metric::multiplicative_relations::responses_t responses;
    ::hamming_metric::multiplicative_relations::commitments_t commitments;
    ::hamming_metric::multiplicative_relations::random_values_t random_values;
    ::hamming_metric::multiplicative_relations::private_key_t private_key;
    ::hamming_metric::multiplicative_relations::public_key_t public_key;
    ::hamming_metric::multiplicative_relations::revealed_values_t revealed_values;

    ::hamming_metric::multiplicative_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    ::hamming_metric::multiplicative_relations::generate_private_key(
            &private_key);

    ::hamming_metric::multiplicative_relations::generate_public_key(
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
            ::hamming_metric::multiplicative_relations::generate_revealed_values(
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
            "Hamming",
            "MR random_matrices",
            total_time_in_seconds,
            operation_per_second);
    
    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::multiplicative_relations::generate_random_values(
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
            "Hamming",
            "MR random vectors",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::multiplicative_relations::generate_commitments_and_responses(
                    &responses,
                    &commitments,
                    &random_values,
                    &revealed_values,
                    &public_key,
                    &private_key);
        }

        lap = clock() - start;
        total_time += lap;
        total_iterations += iterations;

        iterations <<= 1;

    } while (lap < TESTRUN_LEN * CLOCKS_PER_SEC);

    total_time_in_seconds = (double) total_time / (double) CLOCKS_PER_SEC;
    operation_per_second = total_time_in_seconds / total_iterations;

    test::test_functions::print_ops(
            "Hamming",
            "MR proof generation",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::multiplicative_relations::verify_0(
                    commitments.c_i_0,
                    commitments.r_i_0,
                    responses.t_i_0,
                    commitments.c_i_1,
                    commitments.r_i_1,
                    responses.t_i_1,
                    commitments.c_i_j_0,
                    commitments.r_i_j_0,
                    responses.t_i_j_0,
                    commitments.c_i_j_1,
                    commitments.r_i_j_1,
                    responses.t_i_j_1,
                    revealed_values.P_i,
                    revealed_values.P_i_j,
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
            "Hamming",
            "MR verify 0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::multiplicative_relations::verify_1(
                    commitments.c_i_0,
                    commitments.r_i_0,
                    responses.t_i_0,
                    commitments.c_i_2,
                    commitments.r_i_2,
                    responses.t_i_2,
                    commitments.c_i_j_0,
                    commitments.r_i_j_0,
                    responses.t_i_j_0,
                    commitments.c_i_j_2,
                    commitments.r_i_j_2,
                    responses.t_i_j_2,
                    revealed_values.P_i,
                    revealed_values.P_i_j,
                    revealed_values.matrices.R,
                    revealed_values.matrices._R,
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
            "Hamming",
            "MR verify 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::multiplicative_relations::verify_2(
                    commitments.c_i_1,
                    commitments.r_i_1,
                    responses.t_i_1,
                    commitments.c_i_2,
                    commitments.r_i_2,
                    responses.t_i_2,
                    commitments.c_i_j_1,
                    commitments.r_i_j_1,
                    responses.t_i_j_1,
                    commitments.c_i_j_2,
                    commitments.r_i_j_2,
                    responses.t_i_j_2,
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
            "Hamming",
            "MR verify 2",
            total_time_in_seconds,
            operation_per_second);
}