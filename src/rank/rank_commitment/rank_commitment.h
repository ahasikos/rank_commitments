#ifndef RANK_COMMITMENT_H_
#define RANK_COMMITMENT_H_

#include <NTL/GF2X.h>
#include <NTL/mat_GF2E.h>
#include <NTL/mat_GF2.h>
#include <rank/rank_params.h>

namespace rank {
    namespace rank_commitment {
        typedef struct {
            NTL::GF2X irred_poly;
            int is_init;
        } context_t;

        void init(
                context_t *context);

        typedef struct {
            NTL::mat_GF2E G;
        } public_key_t;

        void generate_public_key(
                public_key_t *public_key);

        void generate_commitment(
                NTL::vec_GF2E &c,
                const NTL::vec_GF2 &s,
                const NTL::vec_GF2 &m,
                const NTL::mat_GF2E &g,
                const NTL::vec_GF2E &e);

        void generate_commitment_without_e(
                NTL::vec_GF2E &c,
                const NTL::vec_GF2 &s,
                const NTL::vec_GF2 &m,
                const NTL::mat_GF2E &g);

        int verify_proof(
                const NTL::vec_GF2E &c,
                const NTL::vec_GF2 &s,
                const NTL::vec_GF2 &m,
                const NTL::mat_GF2E &g);
    }
}

#endif //RANK_COMMITMENT_H_
