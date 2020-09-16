#include <rank/linear_relations/linear_relations.h>
#include <rank/rank_commitment/rank_commitment.h>
#include "test_rank_linear_relations.h"
#include "test_params.h"
#include "test_functions.h"

static void generate_keys(
        rank::linear_relations::revealed_values_t *revealed_values,
        rank::linear_relations::private_key_t *private_key,
        rank::linear_relations::public_key_t *public_key) {

    rank::linear_relations::generate_revealed_values(
            revealed_values);

    rank::linear_relations::generate_private_key(
            private_key,
            &revealed_values->matrices);

    rank::linear_relations::generate_public_key(
            public_key,
            private_key);

}


static int generate_commitments(
        rank::linear_relations::commitments_t *commitments,
        rank::linear_relations::responses_t *responses,
        rank::linear_relations::revealed_values_t *revealed_values,
        rank::linear_relations::private_key_t *private_key,
        rank::linear_relations::public_key_t *public_key) {

    ::rank::linear_relations::random_values_t random_values;

    ::rank::linear_relations::generate_random_values(
            &random_values,
            &revealed_values->matrices);

    ::rank::linear_relations::generate_commitments_and_responses(
            commitments,
            responses,
            &random_values,
            revealed_values,
            private_key,
            public_key);

    return 0;
}

int test::rank::linear_relations::test_verify_0() {

    ::rank::rank_commitment::context_t context;
    ::rank::linear_relations::private_key_t private_key;
    ::rank::linear_relations::public_key_t public_key;
    ::rank::linear_relations::commitments_t commitments;
    ::rank::linear_relations::responses_t responses;
    ::rank::linear_relations::revealed_values_t revealed_values;

    ::rank::linear_relations::initalized_commitments_and_responses(
            &commitments,
            &responses);

    ::rank::rank_commitment::init(&context);

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

   return ::rank::linear_relations::verify_0(
           commitments.s0,
           commitments.s1,
           commitments.c0,
           commitments.c1,
           responses.r1,
           responses.r2,
           revealed_values.P,
           revealed_values.Q,
           revealed_values.matrices.x_0,
           revealed_values.matrices.x_1,
           &public_key);

}

int test::rank::linear_relations::test_verify_1() {

    ::rank::rank_commitment::context_t context;
    ::rank::linear_relations::private_key_t private_key;
    ::rank::linear_relations::public_key_t public_key;
    ::rank::linear_relations::commitments_t commitments;
    ::rank::linear_relations::responses_t responses;
    ::rank::linear_relations::revealed_values_t revealed_values;

    ::rank::linear_relations::initalized_commitments_and_responses(
            &commitments,
            &responses);

    ::rank::rank_commitment::init(&context);

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

    return ::rank::linear_relations::verify_1(
            commitments.s0,
            commitments.s2,
            commitments.c0,
            commitments.c2,
            responses.r1,
            responses.r3,
            revealed_values.P,
            revealed_values.Q,
            revealed_values.matrices.x_0,
            revealed_values.matrices.x_1,
            &public_key);
}

int test::rank::linear_relations::test_verify_2() {

    ::rank::rank_commitment::context_t context;
    ::rank::linear_relations::private_key_t private_key;
    ::rank::linear_relations::public_key_t public_key;
    ::rank::linear_relations::commitments_t commitments;
    ::rank::linear_relations::responses_t responses;
    ::rank::linear_relations::revealed_values_t revealed_values;

    ::rank::linear_relations::initalized_commitments_and_responses(
            &commitments,
            &responses);

    ::rank::rank_commitment::init(&context);

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

    return ::rank::linear_relations::verify_2(
            commitments.s1,
            commitments.s2,
            commitments.c1,
            commitments.c2,
            responses.r2,
            responses.r3,
            &public_key);
}

void test::rank::linear_relations::test_perf() {

    ::rank::rank_commitment::context_t context;
    ::rank::linear_relations::private_key_t private_key;
    ::rank::linear_relations::public_key_t public_key;
    ::rank::linear_relations::random_values_t random_values;
    ::rank::linear_relations::commitments_t commitments;
    ::rank::linear_relations::responses_t responses;
    ::rank::linear_relations::revealed_values_t revealed_values;

    ::rank::linear_relations::initalized_commitments_and_responses(
            &commitments,
            &responses);

    ::rank::rank_commitment::init(&context);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::linear_relations::generate_revealed_values(
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
            "Rank",
            "LR random_matrices",
            total_time_in_seconds,
            operation_per_second);

    ::rank::linear_relations::generate_private_key(
            &private_key,
            &revealed_values.matrices);

    ::rank::linear_relations::generate_public_key(
            &public_key,
            &private_key);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::linear_relations::generate_random_values(
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
            "LR random vectors",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::linear_relations::generate_commitments_and_responses(
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
            "LR proof generation",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::linear_relations::verify_0(
                    commitments.s0,
                    commitments.s1,
                    commitments.c0,
                    commitments.c1,
                    responses.r1,
                    responses.r2,
                    revealed_values.P,
                    revealed_values.Q,
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
            "Rank",
            "LR verify 0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::linear_relations::verify_1(
                    commitments.s0,
                    commitments.s2,
                    commitments.c0,
                    commitments.c2,
                    responses.r1,
                    responses.r3,
                    revealed_values.P,
                    revealed_values.Q,
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
            "Rank",
            "LR verify 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::linear_relations::verify_2(
                    commitments.s1,
                    commitments.s2,
                    commitments.c1,
                    commitments.c2,
                    responses.r2,
                    responses.r3,
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
            "LR verify 2",
            total_time_in_seconds,
            operation_per_second);

}
