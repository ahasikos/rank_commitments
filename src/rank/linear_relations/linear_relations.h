#ifndef LINEAR_RELATIONS_H_
#define LINEAR_RELATIONS_H_

#include <NTL/mat_GF2E.h>
#include <NTL/mat_GF2.h>

namespace rank {
    namespace linear_relations {

        typedef struct {
            NTL::mat_GF2 x_0;
            NTL::mat_GF2 x_1;
        } linear_relation_matrices_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2> m;
            NTL::Vec<NTL::vec_GF2E> e;
        } private_key_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2E> commitments;
            NTL::mat_GF2E G;
        } public_key_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2E> c0;
            NTL::Vec<NTL::vec_GF2> s0;
            NTL::Vec<NTL::vec_GF2E> c1;
            NTL::Vec<NTL::vec_GF2> s1;
            NTL::Vec<NTL::vec_GF2E> c2;
            NTL::Vec<NTL::vec_GF2> s2;
        } commitments_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2E> r1;
            NTL::Vec<NTL::vec_GF2E> r2;
            NTL::Vec<NTL::vec_GF2E> r3;
        } responses_t;

        typedef struct {
            NTL::Vec<NTL::mat_GF2> P;
            NTL::Vec<NTL::mat_GF2> Q;
            linear_relation_matrices_t matrices;
        } revealed_values_t;

        typedef struct {
            NTL::Vec<NTL::vec_GF2E> f;
            NTL::Vec<NTL::vec_GF2> v;
            NTL::Vec<NTL::vec_GF2> u;
            NTL::Vec<NTL::vec_GF2> u_v;
        } random_values_t;

        void generate_revealed_values(
                revealed_values_t *revealed_values);

        void initalized_commitments_and_responses(
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

        void generate_commitments_and_responses(
                commitments_t *commitments,
                responses_t *responses,
                const random_values_t *random_values,
                const revealed_values_t *revealed_values,
                const private_key_t *private_key,
                const public_key_t *public_key);

        int verify_0(
                const NTL::Vec<NTL::vec_GF2> &s0,
                const NTL::Vec<NTL::vec_GF2> &s1,
                const NTL::Vec<NTL::vec_GF2E> &c0,
                const NTL::Vec<NTL::vec_GF2E> &c1,
                const NTL::Vec<NTL::vec_GF2E> &r1,
                const NTL::Vec<NTL::vec_GF2E> &r2,
                const NTL::Vec<NTL::mat_GF2> &P,
                const NTL::Vec<NTL::mat_GF2> &Q,
                const NTL::mat_GF2 &x_0,
                const NTL::mat_GF2 &x_1,
                const public_key_t *public_key);

        int verify_1(
                const NTL::Vec<NTL::vec_GF2> &s0,
                const NTL::Vec<NTL::vec_GF2> &s2,
                const NTL::Vec<NTL::vec_GF2E> &c0,
                const NTL::Vec<NTL::vec_GF2E> &c2,
                const NTL::Vec<NTL::vec_GF2E> &r1,
                const NTL::Vec<NTL::vec_GF2E> &r3,
                const NTL::Vec<NTL::mat_GF2> &P,
                const NTL::Vec<NTL::mat_GF2> &Q,
                const NTL::mat_GF2 &x_0,
                const NTL::mat_GF2 &x_1,
                const public_key_t *public_key);

        int verify_2(
                const NTL::Vec<NTL::vec_GF2> &s1,
                const NTL::Vec<NTL::vec_GF2> &s2,
                const NTL::Vec<NTL::vec_GF2E> &c1,
                const NTL::Vec<NTL::vec_GF2E> &c2,
                const NTL::Vec<NTL::vec_GF2E> &r2,
                const NTL::Vec<NTL::vec_GF2E> &r3,
                const public_key_t *public_key);
    }
}

#endif //LINEAR_RELATIONS_H_
