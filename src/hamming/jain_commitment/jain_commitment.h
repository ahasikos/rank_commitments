#ifndef JAIN_COMMITMENT_H
#define JAIN_COMMITMENT_H

#include <hamming/hamming_parameters.h>
#include <NTL/mat_GF2.h>
#include <vector>

namespace hamming_metric {
    namespace commitment {

        typedef struct {
            NTL::mat_GF2 A;
        } public_key_t;

        void generate_public_key(
                public_key_t *public_key);

        void calculate_y(
                NTL::vec_GF2 &y,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &r,
                const NTL::vec_GF2 &m,
                const NTL::vec_GF2 &e);

        void generate_commitment(
                NTL::vec_GF2 &commitment,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &r,
                const NTL::vec_GF2 &m,
                const NTL::vec_GF2 &e);

        void generate_commitment(
                NTL::vec_GF2 &commitment,
                const public_key_t *public_key,
                const NTL::vec_GF2 &r,
                const NTL::vec_GF2 &m);

        void generate_commitment(
                NTL::vec_GF2 &c,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &r,
                const NTL::vec_GF2 &m);

        void generate_commitment(
                NTL::vec_GF2 &c,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &m);

        int verify(
                const NTL::vec_GF2 &commitment,
                const public_key_t *public_key,
                const NTL::vec_GF2 &r,
                const NTL::vec_GF2 &m);

        int verify(
                const NTL::vec_GF2 &c,
                const NTL::mat_GF2 &A,
                const NTL::vec_GF2 &r,
                const NTL::vec_GF2 &m);
    }
}


#endif //JAIN_COMMITMENT_H
