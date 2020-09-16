#include <string>
#include <iostream>
#include "test_knowledge_of_valid_opening.h"
#include "test_jain_commitments.h"
#include "test_linear_relations.h"
#include "test_multiplicative_relations.h"
#include "test_rank_commitment.h"
#include "test_rank_knowledge_of_valid_opening.h"
#include "test_rank_linear_relations.h"
#include "test_rank_multiplicative_relations.h"
#include "test_utils.h"

void print_test_res(const char *test, int res, int *total_erros) {
    if(res) {
        std::cout << test << "... failed" << std::endl;
    } else {
        std::cout << test << "... success" << std::endl;
    }

    *total_erros += res;
}

void print_total_error(const std::string &test, int res, int *total_erros) {
    if(res) {
        std::cout << test << "... failed" << std::endl;
    } else {
        std::cout << test << "... success" << std::endl;
    }

    *total_erros += res;
}

int main()
{
    int i = 0;
    int total_errors = 0;

    i = test::hamming_metric::commitment::test_verify();
    print_test_res("hamming_metric::commitment::test_verify", i, &total_errors);

    i = test::hamming_metric::knowledge_of_valid_opening::test_verify_0();
    print_test_res("hamming_metric::knowledge_of_valid_opening::test_verify_0", i, &total_errors);

    i = test::hamming_metric::knowledge_of_valid_opening::test_verify_1();
    print_test_res("hamming_metric::knowledge_of_valid_opening::test_verify_1", i, &total_errors);

    i = test::hamming_metric::knowledge_of_valid_opening::test_verify_2();
    print_test_res("hamming_metric::knowledge_of_valid_opening::test_verify_2", i, &total_errors);

    i = test::hamming_metric::linear_relations::test_verify_0();
    print_test_res("hamming_metric::linear_relations::test_verify_0()", i, &total_errors);

    i = test::hamming_metric::linear_relations::test_verify_1();
    print_test_res("hamming_metric::linear_relations::test_verify_1()", i, &total_errors);

    i = test::hamming_metric::linear_relations::test_verify_2();
    print_test_res("hamming_metric::linear_relations::test_verify_2()", i, &total_errors);

    i = test::hamming_metric::multiplicative_relations::verify_0();
    print_test_res("hamming_metric::multiplicative_relations::verify_0()", i, &total_errors);

    i = test::hamming_metric::multiplicative_relations::verify_1();
    print_test_res("hamming_metric::multiplicative_relations::verify_1()", i, &total_errors);

    i = test::hamming_metric::multiplicative_relations::verify_2();
    print_test_res("hamming_metric::multiplicative_relations::verify_2()", i, &total_errors);

    i = test::rank::test_rank_commitment();
    print_test_res("rank::test_rank_commitment()", i, &total_errors);

    i = test::rank::knowledge_of_valid_opening::test_verify_0();
    print_test_res("rank::knowledge_of_valid_opening::test_verify_0()", i, &total_errors);

    i = test::rank::knowledge_of_valid_opening::test_verify_1();
    print_test_res("rank::knowledge_of_valid_opening::test_verify_1()", i, &total_errors);

    i = test::rank::knowledge_of_valid_opening::test_verify_2();
    print_test_res("rank::knowledge_of_valid_opening::test_verify_2()", i, &total_errors);

    i = test::rank::linear_relations::test_verify_0();
    print_test_res("rank::linear_relations::test_verify_0()", i, &total_errors);

    i = test::rank::linear_relations::test_verify_1();
    print_test_res("rank::linear_relations::test_verify_1()", i, &total_errors);

    i = test::rank::linear_relations::test_verify_2();
    print_test_res("rank::linear_relations::test_verify_2()", i, &total_errors);

    i = test::rank::multiplicative_relations::test_verify_0();
    print_test_res("rank::multiplicative_relations::test_verify_0()", i, &total_errors);

    i = test::rank::multiplicative_relations::test_verify_1();
    print_test_res("rank::multiplicative_relations::test_verify_1()", i, &total_errors);

    i = test::rank::multiplicative_relations::test_verify_2();
    print_test_res("rank::multiplicative_relations::test_verify_2()", i, &total_errors);

    i = test::utils::test_gf2x_from_gf2();
    print_test_res("test::utils::test_gf2x_from_gf2", i, &total_errors);

    i = test::utils::test_gf2_from_gf2x();
    print_test_res("test::utils::test_gf2_from_gf2x", i, &total_errors);

    i = test::utils::test_gf2x_from_matgf2();
    print_test_res("test::utils::test_gf2x_from_matgf2", i, &total_errors);

    i = test::utils::test_gf2x_from_gf2e();
    print_test_res("test::utils::test_gf2x_from_gf2e", i, &total_errors);

    i = test::utils::test_gf2_from_gf2e();
    print_test_res("test::utils::test_gf2e_from_gf2x", i, &total_errors);

    i = test::utils::test_gf2e_from_gf2x();
    print_test_res("test::utils::test_gf2e_from_vec_gf2", i, &total_errors);

    i = test::utils::test_gf2e_from_two_gf2();
    print_test_res("test::utils::test_gf2e_from_two_gf2", i, &total_errors);

    i = test::utils::test_gf2e_from_vec_gf2();
    print_test_res("test::utils::test_gf2e_from_vec_gf2", i, &total_errors);

    i = test::utils::test_mat_gf2_from_vec_gf2e();
    print_test_res("test::utils::test_mat_gf2_from_vec_gf2e", i, &total_errors);

    test::hamming_metric::commitment::test_perf();
    test::hamming_metric::knowledge_of_valid_opening::test_perf();
    test::hamming_metric::linear_relations::test_perf();
    test::hamming_metric::multiplicative_relations::test_perf();

    test::rank::test_perf();
    test::rank::knowledge_of_valid_opening::test_perf();
    test::rank::linear_relations::test_perf();
    test::rank::multiplicative_relations::test_perf();

    return 0;

}
