#include "test_knowledge_of_valid_opening.h"
#include <utils/utils.h>
#include "test_params.h"
#include "test_functions.h"
#include <hamming/knowledge_of_valid_opening/knowledge_of_valid_opening.h>
#include <NTL/vec_GF2.h>
#include <hamming/jain_commitment/jain_commitment.h>

static void generate_keys(
        ::hamming_metric::knowledge_of_valid_opening::revealed_values_t *revealed_values,
        ::hamming_metric::knowledge_of_valid_opening::public_key_t *public_key,
        ::hamming_metric::knowledge_of_valid_opening::private_key_t *private_key) {

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            public_key,
            private_key);

}

static void generate_commitments(
        ::hamming_metric::knowledge_of_valid_opening::responses_t *responses,
        ::hamming_metric::knowledge_of_valid_opening::commitments_t *commitments,
        ::hamming_metric::knowledge_of_valid_opening::revealed_values_t *revealed_values,
        ::hamming_metric::knowledge_of_valid_opening::public_key_t *public_key,
        ::hamming_metric::knowledge_of_valid_opening::private_key_t *private_key) {

    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_commitments_and_responses(
            responses,
            commitments,
            &random_values,
            revealed_values,
            public_key,
            private_key);
}

int test::hamming_metric::knowledge_of_valid_opening::test_verify_0() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;

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

    if (::hamming_metric::knowledge_of_valid_opening::verify_0(
            commitments.c0,
            commitments.r0,
            responses.t0,
            commitments.c1,
            commitments.r1,
            responses.t1,
            revealed_values.P,
            &public_key) != 0) {
        std::cout << "Error: test_verify_0" << std::endl;
        return 1;
    }

    return 0;
}

int test::hamming_metric::knowledge_of_valid_opening::test_verify_1() {
    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;

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

    if (::hamming_metric::knowledge_of_valid_opening::verify_1(
            commitments.c0,
            commitments.r0,
            responses.t0,
            commitments.c2,
            commitments.r2,
            responses.t2,
            revealed_values.P,
            &public_key) != 0) {
        std::cout << "Error: test_verify_1" << std::endl;
        return 1;
    }

    return 0;
}

int test::hamming_metric::knowledge_of_valid_opening::test_verify_2() {
    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;

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

    if (::hamming_metric::knowledge_of_valid_opening::verify_2(
            commitments.c1,
            commitments.r1,
            responses.t1,
            commitments.c2,
            commitments.r2,
            responses.t2,
            &public_key) != 0) {
        std::cout << "Error: test_verify_2" << std::endl;
        return 1;
    }

    return 0;
}

static void test_perf_random_matrices() {

    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
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
            "KVO test_perf_random_matrices",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_response_encode_commit_0() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::generate_response_0(
                    responses.t0,
                    random_values.v,
                    public_key.A,
                    random_values.f);
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
            ::hamming_metric::knowledge_of_valid_opening::encode(
                    encoded,
                    responses.t0);
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
            "KVO test_perf_encode_0",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::commit(
                    commitments.c0,
                    commitments.r0,
                    encoded,
                    public_key.A);
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
            "KVO test_perf_commit_0",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_response_encode_commit_1() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::generate_response_1(
                    responses.t1,
                    revealed_values.P,
                    random_values.f);
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
            ::hamming_metric::knowledge_of_valid_opening::encode(
                    encoded,
                    responses.t1);
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
            "KVO test_perf_encode_1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::commit(
                    commitments.c1,
                    commitments.r1,
                    encoded,
                    public_key.A);
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
            "KVO test_perf_commit_1",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_response_encode_commit_2() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::generate_response_2(
                    responses.t2,
                    revealed_values.P,
                    random_values.f,
                    private_key.e);
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
            ::hamming_metric::knowledge_of_valid_opening::encode(
                    encoded,
                    responses.t2);
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
            "KVO test_perf_encode_2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::knowledge_of_valid_opening::commit(
                    commitments.c2,
                    commitments.r2,
                    encoded,
                    public_key.A);
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
            "KVO test_perf_commit_2",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_verify_0() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_commitments_and_responses(
            &responses,
            &commitments,
            &random_values,
            &revealed_values,
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
            auto _t0 = utils::encode_binary_vector(responses.t0, JAIN_V);
            ::hamming_metric::commitment::verify(
                    commitments.c0,
                    public_key.A,
                    commitments.r0,
                    _t0);
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
            "KVO test_perf_verify_0 verification 1",
            total_time_in_seconds,
            operation_per_second);


    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _t1 = utils::encode_binary_vector(responses.t1, JAIN_V);
            ::hamming_metric::commitment::verify(
                    commitments.c1,
                    public_key.A,
                    commitments.r1,
                    _t1);
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
            "KVO test_perf_verify_0 verification 2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto sum = responses.t0 + (NTL::inv(revealed_values.P) * responses.t1);
            NTL::vec_GF2 result;
            ::utils::solve_equation(
                    result,
                    public_key.A,
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
            "Hamming",
            "KVO test_perf_verify_0 verification 3",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_verify_1() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_commitments_and_responses(
            &responses,
            &commitments,
            &random_values,
            &revealed_values,
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
            auto _t0 = utils::encode_binary_vector(responses.t0, JAIN_V);
            ::hamming_metric::commitment::verify(
                    commitments.c0,
                    public_key.A,
                    commitments.r0,
                    _t0);
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
            "KVO test_perf_verify_1 verification 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _t2 = utils::encode_binary_vector(responses.t2, JAIN_V);
            ::hamming_metric::commitment::verify(
                    commitments.c2,
                    public_key.A,
                    commitments.r2,
                    _t2);
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
            "KVO test_perf_verify_1 verification 2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto sum = responses.t0 + public_key.commitment + (NTL::inv(revealed_values.P) * responses.t2);
            NTL::vec_GF2 result;
            ::utils::solve_equation(
                    result,
                    public_key.A,
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
            "Hamming",
            "KVO test_perf_verify_1 verification 3",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_verify_2() {

    ::hamming_metric::knowledge_of_valid_opening::responses_t responses;
    ::hamming_metric::knowledge_of_valid_opening::commitments_t commitments;
    ::hamming_metric::knowledge_of_valid_opening::public_key_t public_key;
    ::hamming_metric::knowledge_of_valid_opening::private_key_t private_key;
    ::hamming_metric::knowledge_of_valid_opening::revealed_values_t revealed_values;
    ::hamming_metric::knowledge_of_valid_opening::random_values_t random_values;

    ::hamming_metric::knowledge_of_valid_opening::generate_private_key(
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_public_key(
            &public_key,
            &private_key);

    ::hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
            &revealed_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_random_values(
            &random_values);

    ::hamming_metric::knowledge_of_valid_opening::generate_commitments_and_responses(
            &responses,
            &commitments,
            &random_values,
            &revealed_values,
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
            auto _t1 = utils::encode_binary_vector(responses.t1, JAIN_V);
            ::hamming_metric::commitment::verify(
                    commitments.c1,
                    public_key.A,
                    commitments.r1,
                    _t1);
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
            "KVO test_perf_verify_2 verification 1",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto _t2 = utils::encode_binary_vector(responses.t2, JAIN_V);
            ::hamming_metric::commitment::verify(
                    commitments.c2,
                    public_key.A,
                    commitments.r2,
                    _t2);
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
            "KVO test_perf_verify_2 verification 2",
            total_time_in_seconds,
            operation_per_second);

    total_time = 0;
    iterations = 0x100;
    total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            NTL::weight(responses.t1 + responses.t2);
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
            "KVO test_perf_verify_2 verification 3",
            total_time_in_seconds,
            operation_per_second);
}

void test::hamming_metric::knowledge_of_valid_opening::test_perf() {
    test_perf_random_matrices();
    test_perf_response_encode_commit_0();
    test_perf_response_encode_commit_1();
    test_perf_response_encode_commit_2();
    test_perf_verify_0();
    test_perf_verify_1();
    test_perf_verify_2();
}

