#ifndef KNOWLEDGE_OF_VALID_OPENING_H
#define KNOWLEDGE_OF_VALID_OPENING_H

#include <hamming/hamming_parameters.h>

#include <NTL/vec_GF2.h>
#include <NTL/mat_GF2.h>

namespace hamming_metric {
    namespace knowledge_of_valid_opening {

        typedef struct {
            NTL::mat_GF2 A;
            NTL::vec_GF2 commitment;
        } public_key_t;

        typedef struct {
            NTL::vec_GF2 e;
            NTL::vec_GF2 m;
        } private_key_t;

        typedef struct {
            NTL::vec_GF2 c0;
            NTL::vec_GF2 r0;
            NTL::vec_GF2 c1;
            NTL::vec_GF2 r1;
            NTL::vec_GF2 c2;
            NTL::vec_GF2 r2;
        } commitments_t;

        typedef struct {
            NTL::vec_GF2 t0;
            NTL::vec_GF2 t1;
            NTL::vec_GF2 t2;
        } responses_t;

        typedef struct {
            NTL::mat_GF2 P;
        } revealed_values_t;

        typedef struct {
            NTL::vec_GF2 v;
            NTL::vec_GF2 f;
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

        void generate_commitments_and_responses(
                responses_t *responses,
                commitments_t *commitments,
                const random_values_t *random_values,
                const revealed_values_t *revealed_values,
                const public_key_t *public_key,
                const private_key_t *private_key);

        void encode(
                NTL::vec_GF2 &out,
                const NTL::vec_GF2 &v);

        void commit(
                NTL::vec_GF2 &c,
                NTL::vec_GF2 &r,
                const NTL::vec_GF2 &v,
                const NTL::mat_GF2 &A);

        void generate_response_0(
                NTL::vec_GF2 &t0,
                const NTL::vec_GF2 &n,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &f);

        void generate_commitment_and_response_0(
                NTL::vec_GF2 &c0,
                NTL::vec_GF2 &r0,
                NTL::vec_GF2 &t0,
                const NTL::vec_GF2 &n,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &f);

        void generate_response_1(
                NTL::vec_GF2 &t1,
                const NTL::mat_GF2 &P,
                const NTL::vec_GF2 &f);

        void generate_commitment_and_response_1(
                NTL::vec_GF2 &c1,
                NTL::vec_GF2 &r1,
                NTL::vec_GF2 &t1,
                const NTL::mat_GF2 &A,
                const NTL::mat_GF2 &P,
                const NTL::vec_GF2 &f);

        void generate_response_2(
                NTL::vec_GF2 &t2,
                const NTL::mat_GF2 &P,
                const NTL::vec_GF2 &f,
                const NTL::vec_GF2 &e);

        void generate_commitment_and_response_2(
                NTL::vec_GF2 &c2,
                NTL::vec_GF2 &r2,
                NTL::vec_GF2 &t2,
                const NTL::mat_GF2 &A,
                const NTL::mat_GF2 &P,
                const NTL::vec_GF2 &f,
                const NTL::vec_GF2 &e);

        int verify_0(
                const NTL::vec_GF2 &c0,
                const NTL::vec_GF2 &r0,
                const NTL::vec_GF2 &t0,
                const NTL::vec_GF2 &c1,
                const NTL::vec_GF2 &r1,
                const NTL::vec_GF2 &t1,
                const NTL::mat_GF2 &P,
                const public_key_t *public_key);

        int verify_1(
                const NTL::vec_GF2 &c0,
                const NTL::vec_GF2 &r0,
                const NTL::vec_GF2 &t0,
                const NTL::vec_GF2 &c2,
                const NTL::vec_GF2 &r2,
                const NTL::vec_GF2 &t2,
                const NTL::mat_GF2 &P,
                const public_key_t *public_key);

        int verify_2(
                const NTL::vec_GF2 &c1,
                const NTL::vec_GF2 &r1,
                const NTL::vec_GF2 &t1,
                const NTL::vec_GF2 &c2,
                const NTL::vec_GF2 &r2,
                const NTL::vec_GF2 &t2,
                const public_key_t *public_key);
    }
}

#endif //KNOWLEDGE_OF_VALID_OPENING_H
