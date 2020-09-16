#ifndef MULTIPLICATIVE_RELATIONS_H
#define MULTIPLICATIVE_RELATIONS_H

#include <NTL/vec_GF2.h>
#include <NTL/mat_GF2.h>

namespace hamming_metric {

    namespace multiplicative_relations {

        typedef struct {
            NTL::mat_GF2 _R;
            NTL::Vec<NTL::mat_GF2> R;
        } multiplicative_relation_matrices_t;

        typedef struct {
            NTL::mat_GF2 A;
            NTL::Vec<NTL::vec_GF2> commitments_i;
        } public_key_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> m;
            NTL::Vec<NTL::vec_GF2> e;
        } private_key_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> t_i_0;
            NTL::Vec<NTL::vec_GF2> t_i_1;
            NTL::Vec<NTL::vec_GF2> t_i_2;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> t_i_j_0;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> t_i_j_1;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> t_i_j_2;
        } responses_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> c_i_0;
            NTL::Vec<NTL::vec_GF2> r_i_0;
            NTL::Vec<NTL::vec_GF2> c_i_1;
            NTL::Vec<NTL::vec_GF2> r_i_1;
            NTL::Vec<NTL::vec_GF2> c_i_2;
            NTL::Vec<NTL::vec_GF2> r_i_2;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> c_i_j_0;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> r_i_j_0;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> c_i_j_1;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> r_i_j_1;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> c_i_j_2;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> r_i_j_2;
        } commitments_t;

        typedef struct {
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> commitments_i_j;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> e_i_j;
            NTL::Vec<NTL::mat_GF2> P_i;
            NTL::Vec<NTL::Vec<NTL::mat_GF2>> P_i_j;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> m_prime_i_j;
            multiplicative_relation_matrices_t matrices;
        } revealed_values_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> u_i;
            NTL::Vec<NTL::vec_GF2> f_i;
            NTL::Vec<NTL::vec_GF2> v_i;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> u_i_j;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> f_i_j;
            NTL::Vec<NTL::Vec<NTL::vec_GF2>> v_i_j;
        } random_values_t;

        void initialize_commitments_and_responses(
                commitments_t *commitments,
                responses_t *responses);

        void generate_private_key(
                private_key_t *private_key);

        void generate_public_key(
                public_key_t *public_key,
                const private_key_t *private_key);

        void generate_random_values(
                random_values_t *random_values,
                const multiplicative_relation_matrices_t *matrices);

        void generate_revealed_values(
                revealed_values_t *revealed_values,
                const private_key_t *private_key,
                const public_key_t *public_key);

        void generate_m_prime_i_j_from_m_prime_i(NTL::Vec<NTL::Vec<NTL::vec_GF2>> &m_prime_i_j, const NTL::Vec<NTL::vec_GF2> &m_prime_i);

        void generate_commitments_and_responses(
                responses_t *responses,
                commitments_t *commitments,
                const random_values_t *random_values,
                const revealed_values_t *revealed_values,
                const public_key_t *public_key,
                const private_key_t *private_key);

        int verify_0(
                const NTL::Vec<NTL::vec_GF2> &c_i_0,
                const NTL::Vec<NTL::vec_GF2> &r_i_0,
                const NTL::Vec<NTL::vec_GF2> &t_i_0,
                const NTL::Vec<NTL::vec_GF2> &c_i_1,
                const NTL::Vec<NTL::vec_GF2> &r_i_1,
                const NTL::Vec<NTL::vec_GF2> &t_i_1,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_0,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_0,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_0,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_1,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_1,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_1,
                const NTL::Vec<NTL::mat_GF2> &P_i,
                const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &P_i_j,
                const NTL::Vec<NTL::mat_GF2> &R,
                const public_key_t *public_key);

        int verify_1(
                const NTL::Vec<NTL::vec_GF2> &c_i_0,
                const NTL::Vec<NTL::vec_GF2> &r_i_0,
                const NTL::Vec<NTL::vec_GF2> &t_i_0,
                const NTL::Vec<NTL::vec_GF2> &c_i_2,
                const NTL::Vec<NTL::vec_GF2> &r_i_2,
                const NTL::Vec<NTL::vec_GF2> &t_i_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_0,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_0,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_0,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_2,
                const NTL::Vec<NTL::mat_GF2> &P_i,
                const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &P_i_j,
                const NTL::Vec<NTL::mat_GF2> &R,
                const NTL::mat_GF2 &_R,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &commitments_i_j,
                const public_key_t *public_key);

        int verify_2(
                const NTL::Vec<NTL::vec_GF2> &c_i_1,
                const NTL::Vec<NTL::vec_GF2> &r_i_1,
                const NTL::Vec<NTL::vec_GF2> &t_i_1,
                const NTL::Vec<NTL::vec_GF2> &c_i_2,
                const NTL::Vec<NTL::vec_GF2> &r_i_2,
                const NTL::Vec<NTL::vec_GF2> &t_i_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_1,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_1,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_1,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_2,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &e_i_j,
                const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &m_prime_i_j,
                const public_key_t *public_key);
    }
}

#endif //MULTIPLICATIVE_RELATIONS_H
