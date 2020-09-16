#include "test_rank_commitment.h"
#include <rank/rank_commitment/rank_commitment.h>
#include <utils/utils.h>
#include "test_params.h"
#include "test_functions.h"

int test::rank::test_rank_commitment() {

    NTL::vec_GF2 m, s;
    NTL::vec_GF2E e, c;

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    ::rank::rank_commitment::public_key_t public_key;
    ::rank::rank_commitment::generate_public_key(
            &public_key);


    ::utils::generate_random_binary_vector(
            m,
            MI);
    ::utils::generate_random_binary_vector(
            s,
            PI);
    ::utils::generate_vector_of_specific_rank(
            e,
            EN,
            RHO);

    ::rank::rank_commitment::generate_commitment(
            c,
            s,
            m,
            public_key.G,
            e);


    if (::rank::rank_commitment::verify_proof(
            c,
            s,
            m,
            public_key.G) != 0) {
        return 1;
    }

    return 0;
}

static void test_perf_generate_vector_of_rank_rho() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    NTL::vec_GF2E e;

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::utils::generate_vector_of_specific_rank(
                    e,
                    EN,
                    RHO);
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
            "Generate vector of rank rho",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_generate_random_binary_matrix_G() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    NTL::mat_GF2E G;

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::utils::generate_random_matrix_gf2e(
                    G,
                    K,
                    EN);
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
            "Generate matrix G",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_generate_commitment() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    NTL::mat_GF2E G;
    NTL::vec_GF2 s, m;
    NTL::vec_GF2E c, e;

    ::utils::generate_random_binary_vector(
            m,
            MI);

    ::utils::generate_random_binary_vector(
            s,
            PI);

    ::utils::generate_random_matrix_gf2e(
            G,
            K,
            EN);

    ::utils::generate_vector_of_specific_rank(
            e,
            EN,
            RHO);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            ::rank::rank_commitment::generate_commitment(
                    c,
                    s,
                    m,
                    G,
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
            "Rank",
            "Generate commitment c",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_recover_e_from_c() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    NTL::mat_GF2E G;
    NTL::vec_GF2 s, m;
    NTL::vec_GF2E c;

    ::utils::generate_random_binary_vector(
            m,
            MI);

    ::utils::generate_random_binary_vector(
            s,
            PI);

    ::utils::generate_random_matrix_gf2e(
            G,
            K,
            EN);

    ::rank::rank_commitment::generate_commitment_without_e(
            c,
            s,
            m,
            G);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            auto s_m = utils::gf2e_from_two_gf2(s, m);
            auto e = (s_m * G) + c;
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
            "Recover e from c",
            total_time_in_seconds,
            operation_per_second);
}

static void test_perf_calculate_rank_of_vector() {

    ::rank::rank_commitment::context_t context;
    ::rank::rank_commitment::init(&context);

    NTL::vec_GF2E e;

    utils::generate_vector_of_specific_rank(
            e,
            EN,
            RHO);

    clock_t start, lap, total_time;
    total_time = 0;
    int i;

    uint iterations = 0x100;
    int total_iterations = iterations;

    do {
        start = clock();

        for (i = 0; i < iterations; i++) {
            utils::rank_of_vector(e);
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
            "Calculate rank of vector",
            total_time_in_seconds,
            operation_per_second);
}

void test::rank::test_perf() {

    test_perf_generate_vector_of_rank_rho();
    test_perf_generate_random_binary_matrix_G();
    test_perf_generate_commitment();
    test_perf_recover_e_from_c();
    test_perf_calculate_rank_of_vector();
}
