#include "test_linear_relations.h"
#include "test_params.h"
#include "test_functions.h"
#include <hamming/linear_relations/linear_relations.h>
#include <utils/utils.h>

static void generate_keys(
        hamming_metric::linear_relations::revealed_values_t *revealed_values,
        hamming_metric::linear_relations::public_key_t *public_key,
        hamming_metric::linear_relations::private_key_t *private_key) {

    hamming_metric::linear_relations::generate_revealed_values(
            revealed_values);

    hamming_metric::linear_relations::generate_private_key(
            private_key,
            &revealed_values->matrices);

    hamming_metric::linear_relations::generate_public_key(
            public_key,
            private_key);
}

static void generate_commitments(
        hamming_metric::linear_relations::responses_t *responses,
        hamming_metric::linear_relations::commitments_t *commitments,
        hamming_metric::linear_relations::revealed_values_t *revealed_values,
        hamming_metric::linear_relations::public_key_t *public_key,
        hamming_metric::linear_relations::private_key_t *private_key) {

    hamming_metric::linear_relations::random_values_t random_values;

    hamming_metric::linear_relations::generate_random_values(
            &random_values,
            &revealed_values->matrices);

    hamming_metric::linear_relations::generate_commitments_and_responses(
            responses,
            commitments,
            &random_values,
            revealed_values,
            public_key,
            private_key);
}

int test::hamming_metric::linear_relations::test_verify_0() {

    ::hamming_metric::linear_relations::responses_t responses;
    ::hamming_metric::linear_relations::commitments_t commitments;
    ::hamming_metric::linear_relations::revealed_values_t revealed_values;
    ::hamming_metric::linear_relations::public_key_t public_key;
    ::hamming_metric::linear_relations::private_key_t private_key;

    ::hamming_metric::linear_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &public_key,
            &private_key);

    generate_commitments(
            &responses,
            &commitments,
            &revealed_values,
            &public_key,
            &private_key);

    return ::hamming_metric::linear_relations::verify_0(
            commitments.c0,
            commitments.r0,
            responses.t0,
            commitments.c1,
            commitments.r1,
            responses.t1,
            revealed_values.P,
            revealed_values.matrices.x_0,
            revealed_values.matrices.x_1,
            &public_key);
}

int test::hamming_metric::linear_relations::test_verify_1() {

    ::hamming_metric::linear_relations::responses_t responses;
    ::hamming_metric::linear_relations::commitments_t commitments;
    ::hamming_metric::linear_relations::revealed_values_t revealed_values;
    ::hamming_metric::linear_relations::public_key_t public_key;
    ::hamming_metric::linear_relations::private_key_t private_key;

    ::hamming_metric::linear_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &public_key,
            &private_key);

    generate_commitments(
            &responses,
            &commitments,
            &revealed_values,
            &public_key,
            &private_key);

    return ::hamming_metric::linear_relations::verify_1(
            commitments.c0,
            commitments.r0,
            responses.t0,
            commitments.c2,
            commitments.r2,
            responses.t2,
            revealed_values.P,
            revealed_values.matrices.x_0,
            revealed_values.matrices.x_1,
            &public_key);
}

int test::hamming_metric::linear_relations::test_verify_2() {

    ::hamming_metric::linear_relations::responses_t responses;
    ::hamming_metric::linear_relations::commitments_t commitments;
    ::hamming_metric::linear_relations::revealed_values_t revealed_values;
    ::hamming_metric::linear_relations::public_key_t public_key;
    ::hamming_metric::linear_relations::private_key_t private_key;

    ::hamming_metric::linear_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    generate_keys(
            &revealed_values,
            &public_key,
            &private_key);

    generate_commitments(
            &responses,
            &commitments,
            &revealed_values,
            &public_key,
            &private_key);

    return ::hamming_metric::linear_relations::verify_2(
            commitments.c1,
            commitments.r1,
            responses.t1,
            commitments.c2,
            commitments.r2,
            responses.t2,
            &public_key);
}

void test::hamming_metric::linear_relations::test_perf() {

    ::hamming_metric::linear_relations::responses_t responses;
    ::hamming_metric::linear_relations::commitments_t commitments;
    ::hamming_metric::linear_relations::random_values_t random_values;
    ::hamming_metric::linear_relations::revealed_values_t revealed_values;
    ::hamming_metric::linear_relations::public_key_t public_key;
    ::hamming_metric::linear_relations::private_key_t private_key;

    ::hamming_metric::linear_relations::initialize_commitments_and_responses(
            &commitments,
            &responses);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::linear_relations::generate_revealed_values(
                    &revealed_values);
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
            "LR random_matrices",
            total_time_in_seconds,
            operation_per_second);

    ::hamming_metric::linear_relations::generate_private_key(
            &private_key,
            &revealed_values.matrices);

    ::hamming_metric::linear_relations::generate_public_key(
            &public_key,
            &private_key);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::linear_relations::generate_random_values(
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
            "LR random vectors",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::linear_relations::generate_commitments_and_responses(
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
            "LR proof generation",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::linear_relations::verify_0(
                    commitments.c0,
                    commitments.r0,
                    responses.t0,
                    commitments.c1,
                    commitments.r1,
                    responses.t1,
                    revealed_values.P,
                    revealed_values.matrices.x_0,
                    revealed_values.matrices.x_1,
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
            "LR verify 0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::linear_relations::verify_1(
                    commitments.c0,
                    commitments.r0,
                    responses.t0,
                    commitments.c2,
                    commitments.r2,
                    responses.t2,
                    revealed_values.P,
                    revealed_values.matrices.x_0,
                    revealed_values.matrices.x_1,
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
            "LR verify 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::linear_relations::verify_2(
                    commitments.c1,
                    commitments.r1,
                    responses.t1,
                    commitments.c2,
                    commitments.r2,
                    responses.t2,
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
            "LR verify 2",
            total_time_in_seconds,
            operation_per_second);
}