#include "test_jain_commitments.h"
#include <hamming/jain_commitment/jain_commitment.h>

#include <NTL/vec_GF2.h>
#include <NTL/mat_GF2.h>
#include <utils/utils.h>
#include "test_params.h"
#include "test_functions.h"

int test::hamming_metric::commitment::test_verify() {

    NTL::vec_GF2 c, r, m;
    ::hamming_metric::commitment::public_key_t public_key;

    {
        ::utils::generate_random_binary_vector(
                m,
                JAIN_V);
        ::utils::generate_random_binary_vector(
                r,
                JAIN_L);
        ::hamming_metric::commitment::generate_public_key(
                &public_key);
    }

    ::hamming_metric::commitment::generate_commitment(
            c,
            &public_key,
            r,
            m);

    return ::hamming_metric::commitment::verify(
            c,
            &public_key,
            r,
            m);
}

static void test_perf_generate_vector_of_weight_w() {

    NTL::vec_GF2 e;

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::utils::generate_vector_of_weight_w(
                    e,
                    JAIN_K,
                    W);
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
            "Generate vector of weight w",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_generate_random_binary_matrix_A() {

    NTL::mat_GF2 A;

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            utils::generate_random_binary_matrix(
                    A,
                    JAIN_K,
                    JAIN_L + JAIN_V);
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
            "Generate random binary matrix A",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_generate_commitment() {

    NTL::mat_GF2 A;
    NTL::vec_GF2 c, r, m, e;

    ::utils::generate_random_binary_vector(
            m,
            JAIN_V);

    ::utils::generate_random_binary_vector(
            r,
            JAIN_L);

    utils::generate_random_binary_matrix(
            A,
            JAIN_K,
            JAIN_L + JAIN_V);

    ::utils::generate_vector_of_weight_w(
            e,
            JAIN_K,
            W);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::hamming_metric::commitment::generate_commitment(
                    c,
                    A,
                    r,
                    m,
                    e);
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
            "Generate commitment",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_recover_e_from_c() {

    NTL::mat_GF2 A;
    NTL::vec_GF2 c, r, m;

    ::utils::generate_random_binary_vector(
            m,
            JAIN_V);

    ::utils::generate_random_binary_vector(
            r,
            JAIN_L);

    utils::generate_random_binary_matrix(
            A,
            JAIN_K,
            JAIN_L + JAIN_V);

    ::hamming_metric::commitment::generate_commitment(
            c,
            A,
            r,
            m);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            NTL::vec_GF2 _r(r);
            _r.append(m);
            auto e = (A * _r) + c;
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
            "Recover e from c",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_calculate_weight_of_vector() {

    NTL::vec_GF2 e;

    ::utils::generate_vector_of_weight_w(
            e,
            JAIN_K,
            W);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            NTL::weight(e);
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
            "Calculate weight of vector",
            total_time_in_seconds,
            operation_per_second);
}

void test::hamming_metric::commitment::test_perf() {

    test_perf_generate_vector_of_weight_w();
    test_perf_generate_random_binary_matrix_A();
    test_perf_generate_commitment();
    test_perf_recover_e_from_c();
    test_perf_calculate_weight_of_vector();
}
