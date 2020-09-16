#ifndef LINEAR_RELATIONS_H
#define LINEAR_RELATIONS_H

#include <NTL/vec_GF2.h>
#include <hamming/jain_commitment/jain_commitment.h>

namespace hamming_metric {

    namespace linear_relations {

        typedef struct {
            NTL::mat_GF2 x_0;
            NTL::mat_GF2 x_1;
        } linear_relation_matrices_t;

        typedef struct {
            NTL::mat_GF2 A;
            NTL::Vec<NTL::vec_GF2> commitments;
        } public_key_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> m;
            NTL::Vec<NTL::vec_GF2> e;
        } private_key_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> t0;
            NTL::Vec<NTL::vec_GF2> t1;
            NTL::Vec<NTL::vec_GF2> t2;
        } responses_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> c0;
            NTL::Vec<NTL::vec_GF2> r0;
            NTL::Vec<NTL::vec_GF2> c1;
            NTL::Vec<NTL::vec_GF2> r1;
            NTL::Vec<NTL::vec_GF2> c2;
            NTL::Vec<NTL::vec_GF2> r2;
        } commitments_t;

        typedef struct {
            linear_relation_matrices_t matrices;
            NTL::Vec<NTL::mat_GF2> P;
        } revealed_values_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> v;
            NTL::Vec<NTL::vec_GF2> u;
            NTL::Vec<NTL::vec_GF2> f;
            NTL::Vec<NTL::vec_GF2> u_v;
        } random_values_t;

        void initialize_commitments_and_responses(
                commitments_t *commitments,
                responses_t *responses);

        void generate_private_key(
                private_key_t *private_key,
                const linear_relation_matrices_t *matrices);

        void generate_public_key(
                public_key_t *public_key,
                const private_key_t *private_key);

        void generate_random_values(
                random_values_t *random_values,
                const linear_relation_matrices_t *matrices);

        void generate_revealed_values(
                revealed_values_t *revealed_values);

        void generate_commitments_and_responses(
                responses_t *responses,
                commitments_t *commitments,
                const random_values_t *random_values,
                const revealed_values_t *revealed_values,
                const public_key_t *public_key,
                const private_key_t *private_key);

        int verify_0(
                const NTL::Vec<NTL::vec_GF2> &c0,
                const NTL::Vec<NTL::vec_GF2> &r0,
                const NTL::Vec<NTL::vec_GF2> &t0,
                const NTL::Vec<NTL::vec_GF2> &c1,
                const NTL::Vec<NTL::vec_GF2> &r1,
                const NTL::Vec<NTL::vec_GF2> &t1,
                const NTL::Vec<NTL::mat_GF2> &P,
                const NTL::mat_GF2 &x_0,
                const NTL::mat_GF2 &x_1,
                const public_key_t *public_key);

        int verify_1(
                const NTL::Vec<NTL::vec_GF2> &c0,
                const NTL::Vec<NTL::vec_GF2> &r0,
                const NTL::Vec<NTL::vec_GF2> &t0,
                const NTL::Vec<NTL::vec_GF2> &c2,
                const NTL::Vec<NTL::vec_GF2> &r2,
                const NTL::Vec<NTL::vec_GF2> &t2,
                const NTL::Vec<NTL::mat_GF2> &P,
                const NTL::mat_GF2 &x_0,
                const NTL::mat_GF2 &x_1,
                const public_key_t *public_key);

        int verify_2(
                const NTL::Vec<NTL::vec_GF2> &c1,
                const NTL::Vec<NTL::vec_GF2> &r1,
                const NTL::Vec<NTL::vec_GF2> &t1,
                const NTL::Vec<NTL::vec_GF2> &c2,
                const NTL::Vec<NTL::vec_GF2> &r2,
                const NTL::Vec<NTL::vec_GF2> &t2,
                const public_key_t *public_key);
    }
}

#endif //LINEAR_RELATIONS_H
