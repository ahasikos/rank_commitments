#include "test_rank_knowledge_of_valid_opening.h"
#include "test_params.h"
#include "test_functions.h"
#include <rank/knowledge_of_valid_opening/knowledge_of_valid_opening.h>
#include <rank/rank_commitment/rank_commitment.h>
#include <NTL/GF2XFactoring.h>
#include <utils/utils.h>

static void generate_keys(
        rank::knowledge_of_valid_opening::private_key_t *private_key,
        rank::knowledge_of_valid_opening::public_key_t *public_key
) {

    ::rank::knowledge_of_valid_opening::generate_private_key(
            private_key);
    ::rank::knowledge_of_valid_opening::generate_public_key(
            public_key,
            private_key);
}

static void generate_commitments(
        rank::knowledge_of_valid_opening::commitments_t *commitments,
        rank::knowledge_of_valid_opening::responses_t *responses,
        rank::knowledge_of_valid_opening::revealed_values_t *revealed_values,
        rank::knowledge_of_valid_opening::private_key_t *private_key,
        rank::knowledge_of_valid_opening::public_key_t *public_key) {

    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            revealed_values);

    ::rank::knowledge_of_valid_opening::generate_commitments_and_responses(
            commitments,
            responses,
            &random_values,
            revealed_values,
            private_key,
            public_key);
}

int test::rank::knowledge_of_valid_opening::test_verify_0() {
    ::rank::rank_commitment::context_t context;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::responses_t responses;

    ::rank::rank_commitment::init(&context);

    generate_keys(
            &private_key,
            &public_key);

    generate_commitments(
            &commitments,
            &responses,
            &revealed_values,
            &private_key,
            &public_key);

    return ::rank::knowledge_of_valid_opening::verify_0(
            commitments.c0,
            commitments.s0,
            commitments.c1,
            commitments.s1,
            responses.r1,
            responses.r2,
            revealed_values.P,
            revealed_values.Q,
            public_key.G);
}

int test::rank::knowledge_of_valid_opening::test_verify_1() {
    ::rank::rank_commitment::context_t context;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::responses_t responses;

    ::rank::rank_commitment::init(&context);

    generate_keys(
            &private_key,
            &public_key);

    generate_commitments(
            &commitments,
            &responses,
            &revealed_values,
            &private_key,
            &public_key);

    return ::rank::knowledge_of_valid_opening::verify_1(
            commitments.c0,
            commitments.s0,
            commitments.c2,
            commitments.s2,
            responses.r1,
            responses.r3,
            public_key.commitment,
            revealed_values.P,
            revealed_values.Q,
            public_key.G);
}

int test::rank::knowledge_of_valid_opening::test_verify_2() {
    ::rank::rank_commitment::context_t context;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::responses_t responses;

    ::rank::rank_commitment::init(&context);

    generate_keys(
            &private_key,
            &public_key);

    generate_commitments(
            &commitments,
            &responses,
            &revealed_values,
            &private_key,
            &public_key);

    return ::rank::knowledge_of_valid_opening::verify_2(
            commitments.c1,
            commitments.s1,
            commitments.c2,
            commitments.s2,
            responses.r2,
            responses.r3,
            public_key.G);
}

static void test_perf_random_matrices() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::generate_revealed_values(
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
            "KVO test_perf_random_matrices",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_response_encode_commit_0() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::responses_t responses;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::generate_response_0(
                    responses.r1,
                    random_values.u,
                    random_values.f,
                    public_key.G);
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
            "KVO test_perf_response_0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;
    NTL::vec_GF2 encoded;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::encode(
                    encoded,
                    revealed_values.P,
                    revealed_values.Q,
                    responses.r1);
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
            "KVO test_perf_encode_0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::commit(
                    commitments.c0,
                    commitments.s0,
                    encoded,
                    public_key.G);
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
            "KVO test_perf_commit_0",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_response_encode_commit_1() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::responses_t responses;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::generate_response_1(
                    responses.r2,
                    random_values.f,
                    revealed_values.P,
                    revealed_values.Q);
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
            "KVO test_perf_response_1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;
    NTL::vec_GF2 encoded;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::encode(
                    encoded,
                    responses.r2);
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
            "KVO test_perf_encode_1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::commit(
                    commitments.c1,
                    commitments.s1,
                    encoded,
                    public_key.G);
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
            "KVO test_perf_commit_1",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_response_encode_commit_2() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::responses_t responses;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::generate_response_2(
                    responses.r3,
                    private_key.e,
                    random_values.f,
                    revealed_values.P,
                    revealed_values.Q);
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
            "KVO test_perf_response_2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;
    NTL::vec_GF2 encoded;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::encode(
                    encoded,
                    responses.r3);
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
            "KVO test_perf_encode_2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::knowledge_of_valid_opening::commit(
                    commitments.c2,
                    commitments.s2,
                    encoded,
                    public_key.G);
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
            "KVO test_perf_commit_2",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_verify_0() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::responses_t responses;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::rank::knowledge_of_valid_opening::generate_commitments_and_responses(
            &commitments,
            &responses,
            &random_values,
            &revealed_values,
            &private_key,
            &public_key);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _r1 = utils::encode(revealed_values.P, revealed_values.Q, responses.r1, MI);
            ::rank::rank_commitment::verify_proof(
                    commitments.c0,
                    commitments.s0,
                    _r1,
                    public_key.G);
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
            "KVO test_perf_verify_0 verification 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;
    NTL::vec_GF2 encoded;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _r2 = utils::encode_2(responses.r2, MI);
            ::rank::rank_commitment::verify_proof(
                    commitments.c1,
                    commitments.s1,
                    _r2,
                    public_key.G);
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
            "KVO test_perf_verify_0 verification 2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            NTL::vec_GF2E pi_inv;
            ::rank::knowledge_of_valid_opening::calculate_pi_inv(
                    pi_inv,
                    revealed_values.P,
                    revealed_values.Q,
                    responses.r2);

            auto sum = responses.r1 + pi_inv;

            NTL::vec_GF2E result;
            utils::solve_equation(
                    result,
                    public_key.G,
                    sum);
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
            "KVO test_perf_verify_0 verification 3",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_verify_1() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::responses_t responses;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::rank::knowledge_of_valid_opening::generate_commitments_and_responses(
            &commitments,
            &responses,
            &random_values,
            &revealed_values,
            &private_key,
            &public_key);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _r1 = utils::encode(revealed_values.P, revealed_values.Q, responses.r1, MI);
            ::rank::rank_commitment::verify_proof(
                    commitments.c0,
                    commitments.s0,
                    _r1,
                    public_key.G);
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
            "KVO test_perf_verify_1 verification 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;
    NTL::vec_GF2 encoded;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _r3 = utils::encode_2(responses.r3, MI);
            ::rank::rank_commitment::verify_proof(
                    commitments.c2,
                    commitments.s2,
                    _r3,
                    public_key.G);
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
            "KVO test_perf_verify_1 verification 2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            NTL::vec_GF2E pi_inv_r3;
            ::rank::knowledge_of_valid_opening::calculate_pi_inv(
                    pi_inv_r3,
                    revealed_values.P,
                    revealed_values.Q,
                    responses.r3);

            auto sum = responses.r1 + pi_inv_r3 + public_key.commitment;

            NTL::vec_GF2E result;
            utils::solve_equation(
                    result,
                    public_key.G,
                    sum);
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
            "KVO test_perf_verify_1 verification 3",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_verify_2() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::knowledge_of_valid_opening::responses_t responses;
    ::rank::knowledge_of_valid_opening::commitments_t commitments;
    ::rank::knowledge_of_valid_opening::public_key_t public_key;
    ::rank::knowledge_of_valid_opening::private_key_t private_key;
    ::rank::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::rank::knowledge_of_valid_opening::random_values_t random_values;

    ::rank::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::rank::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::rank::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::rank::knowledge_of_valid_opening::generate_commitments_and_responses(
            &commitments,
            &responses,
            &random_values,
            &revealed_values,
            &private_key,
            &public_key);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _r2 = utils::encode_2(responses.r2, MI);
            ::rank::rank_commitment::verify_proof(
                    commitments.c1,
                    commitments.s1,
                    _r2,
                    public_key.G);
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
            "KVO test_perf_verify_2 verification 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _r3 = utils::encode_2(responses.r3, MI);
            ::rank::rank_commitment::verify_proof(
                    commitments.c2,
                    commitments.s2,
                    _r3,
                    public_key.G);
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
            "KVO test_perf_verify_2 verification 2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();
        for (i = 0; i < iterations; i++) {
            auto r2_plus_r3 = responses.r2 + responses.r3;
            utils::rank_of_vector(r2_plus_r3);
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
            "KVO test_perf_verify_2 verification 3",
            total_time_in_seconds,
            operation_per_second);
}

void test::rank::knowledge_of_valid_opening::test_perf() {
    test_perf_random_matrices();
    test_perf_response_encode_commit_0();
    test_perf_response_encode_commit_1();
    test_perf_response_encode_commit_2();
    test_perf_verify_0();
    test_perf_verify_1();
    test_perf_verify_2();
}