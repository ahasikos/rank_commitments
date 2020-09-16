#ifndef KNOWLEDGE_OF_VALID_OPENING_H_
#define KNOWLEDGE_OF_VALID_OPENING_H_

#include <NTL/mat_GF2.h>
#include <NTL/mat_GF2E.h>
#include <NTL/vec_GF2E.h>

namespace rank {
    namespace knowledge_of_valid_opening {

        typedef struct {
            NTL::vec_GF2 m;
            NTL::vec_GF2E e;
        } private_key_t;

        typedef struct {
            NTL::vec_GF2E commitment;
            NTL::mat_GF2E G;
        } public_key_t;

        typedef struct {
            NTL::vec_GF2E c0;
            NTL::vec_GF2 s0;
            NTL::vec_GF2E c1;
            NTL::vec_GF2 s1;
            NTL::vec_GF2E c2;
            NTL::vec_GF2 s2;
        } commitments_t;

        typedef struct {
            NTL::vec_GF2E r1;
            NTL::vec_GF2E r2;
            NTL::vec_GF2E r3;
        } responses_t;

        typedef struct {
            NTL::mat_GF2 P;
            NTL::mat_GF2 Q;
        } revealed_values_t;

        typedef struct {
            NTL::vec_GF2E u;
            NTL::vec_GF2E f;
        } random_values_t;

        void generate_private_key(
                private_key_t *private_key);

        void generate_public_key(
                public_key_t *public_key,
                const private_key_t *private_key);

        void generate_random_values(
                random_values_t *random_values);

        void generate_revealed_values(
                revealed_values_t *revealed_values);

        void generate_phi(NTL::mat_GF2 &m, const NTL::vec_GF2E &v);

        void generate_phi_inv(NTL::vec_GF2E &v, const NTL::mat_GF2 &m);

        void calculate_pi(
                NTL::vec_GF2E &p,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::vec_GF2E &u);

        void calculate_pi_inv(
                NTL::vec_GF2E &p,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::vec_GF2E &u);

        void encode(
                NTL::vec_GF2 &out,
                const NTL::vec_GF2E &v);

        void encode(
                NTL::vec_GF2 &out,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::vec_GF2E &v);

        void commit(
                NTL::vec_GF2E &c,
                NTL::vec_GF2 &s,
                const NTL::vec_GF2 &m,
                const NTL::mat_GF2E &G);

        void generate_response_0(
                NTL::vec_GF2E &r,
                const NTL::vec_GF2E &u,
                const NTL::vec_GF2E &f,
                const NTL::mat_GF2E &G);

        void generate_commitment_0_and_response_0(
                NTL::vec_GF2E &c0,
                NTL::vec_GF2 &s0,
                NTL::vec_GF2E &r1,
                const NTL::vec_GF2E &u,
                const NTL::vec_GF2E &f,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::mat_GF2E &G);

        void generate_response_1(
                NTL::vec_GF2E &r,
                const NTL::vec_GF2E &f,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q);

        void generate_commitment_1_and_response_1(
                NTL::vec_GF2E &c1,
                NTL::vec_GF2 &s1,
                NTL::vec_GF2E &r2,
                const NTL::vec_GF2E &f,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::mat_GF2E &G);

        void generate_response_2(
                NTL::vec_GF2E &r,
                const NTL::vec_GF2E &e,
                const NTL::vec_GF2E &f,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q);

        void generate_commitment_2_and_response_2(
                NTL::vec_GF2E &c2,
                NTL::vec_GF2 &s2,
                NTL::vec_GF2E &r3,
                const NTL::vec_GF2E &e,
                const NTL::vec_GF2E &f,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::mat_GF2E &G);

        void generate_commitments_and_responses(
                commitments_t *commitments,
                responses_t *responses,
                const random_values_t *random_values,
                const revealed_values_t *revealed_values,
                const private_key_t *private_key,
                const public_key_t *public_key);

        int verify_0(
                const NTL::vec_GF2E &c0,
                const NTL::vec_GF2 &s0,
                const NTL::vec_GF2E &c1,
                const NTL::vec_GF2 &s1,
                const NTL::vec_GF2E &r1,
                const NTL::vec_GF2E &r2,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::mat_GF2E &G);

        int verify_1(
                const NTL::vec_GF2E &c0,
                const NTL::vec_GF2 &s0,
                const NTL::vec_GF2E &c2,
                const NTL::vec_GF2 &s2,
                const NTL::vec_GF2E &r1,
                const NTL::vec_GF2E &r3,
                const NTL::vec_GF2E &commitment,
                const NTL::mat_GF2 &P,
                const NTL::mat_GF2 &Q,
                const NTL::mat_GF2E &G);

        int verify_2(
                const NTL::vec_GF2E &c1,
                const NTL::vec_GF2 &s1,
                const NTL::vec_GF2E &c2,
                const NTL::vec_GF2 &s2,
                const NTL::vec_GF2E &r2,
                const NTL::vec_GF2E &r3,
                const NTL::mat_GF2E &G);

    }
}

#endif //KNOWLEDGE_OF_VALID_OPENING_H_
