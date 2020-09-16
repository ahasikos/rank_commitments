#ifndef UTILS_H_
#define UTILS_H_

#include <NTL/vec_GF2.h>
#include <NTL/GF2X.h>
#include <NTL/mat_GF2.h>
#include <NTL/vec_GF2E.h>
#include <NTL/mat_GF2E.h>

namespace utils{
    NTL::GF2X gf2x_from_gf2(const NTL::Vec<NTL::GF2> &in);
    NTL::Vec<NTL::GF2> gf2_from_gf2x(const NTL::GF2X &in, int len);
    NTL::GF2X gf2x_from_matgf2(const NTL::mat_GF2 &in);
    NTL::GF2X gf2x_from_gf2e(const NTL::vec_GF2E &in);
    NTL::vec_GF2 gf2_from_gf2e(const NTL::vec_GF2E &in);
    NTL::vec_GF2E gf2e_from_gf2x(const NTL::GF2X &in, int length);
    NTL::vec_GF2E gf2e_from_vec_gf2(const NTL::vec_GF2 &in);
    NTL::vec_GF2 encode(const NTL::mat_GF2 &P, const NTL::mat_GF2 &Q, const NTL::vec_GF2E &V, int size);
    NTL::vec_GF2 encode_2(const NTL::vec_GF2E &V, int size);
    NTL::vec_GF2E gf2e_from_two_gf2(const NTL::vec_GF2 &first, const NTL::vec_GF2 &second);
    NTL::Vec<NTL::GF2> encode_binary_vector(const NTL::Vec<NTL::GF2> &in, int size);

    void sample_messages(
            NTL::vec_GF2 &m_1,
            NTL::vec_GF2 &m_2,
            NTL::vec_GF2 &m_3,
            int size);

    void create_random_permutation(
            std::vector<uint> &permutation,
            int size);

    void create_permutation_matrix(
            NTL::mat_GF2 &P,
            const std::vector<uint> &permutation);

    void create_permutation_matrix(
            NTL::mat_GF2 &P,
            int size);

    void generate_relation_matrix(
            NTL::mat_GF2 &_R,
            NTL::Vec<NTL::mat_GF2> &R,
            const NTL::Vec<NTL::vec_GF2> &m_tilde,
            const NTL::Vec<NTL::vec_GF2> &m,
            int size);

    NTL::mat_GF2 mat_gf2_from_vec_gf2e(const NTL::vec_GF2E &v);

    int gauss_row_reduced_echelon_form(
            NTL::mat_GF2 &M);

    int gauss_row_reduced_echelon_form_gf2e(
            NTL::mat_GF2E &M);

    int convert_matrix_to_rref_and_check_solutions(
            NTL::mat_GF2 &M);

    int convert_matrix_to_rref_and_check_solutions(
            NTL::mat_GF2E &M);

    void generate_random_matrix_gf2e(
            NTL::mat_GF2E &g,
            int num_of_rows,
            int num_of_cols);

    void generate_random_square_invertible_matrix(
            NTL::mat_GF2 &M,
            int size);

    void generate_random_binary_matrix(
            NTL::mat_GF2 &A,
            int num_of_rows,
            int num_of_cols);

    void generate_random_binary_vector_gf2e(
            NTL::vec_GF2E &v,
            int length);

    void generate_vector_of_specific_rank(
            NTL::vec_GF2E &e,
            int length,
            int rank);

    void generate_random_binary_vector(
            NTL::vec_GF2 &v,
            int length);

    void generate_vector_of_weight_w(
            NTL::vec_GF2 &e,
            int length,
            int weight);

    int solve_equation(
            NTL::vec_GF2 &res,
            const NTL::mat_GF2 &M,
            const NTL::vec_GF2 &v);

    int solve_equation(
            NTL::vec_GF2E &res,
            const NTL::mat_GF2E &M,
            const NTL::vec_GF2E &v);

    int rank_of_vector(
            NTL::vec_GF2E &v);

    std::vector<uint> shuffle(
            const std::vector<uint> &input,
            int array_size);
}

#endif //UTILS_H_
