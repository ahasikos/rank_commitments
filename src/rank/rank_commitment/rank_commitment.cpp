#include "rank_commitment.h"
#include <NTL/GF2E.h>
#include <NTL/GF2XFactoring.h>
#include <utils/utils.h>

void rank::rank_commitment::init(rank_commitment::context_t *context) {
    context->irred_poly = NTL::BuildIrred_GF2X(EM);
    NTL::GF2E::init(context->irred_poly);

    context->is_init = 1;
}

void rank::rank_commitment::generate_public_key(
        public_key_t *public_key) {

    utils::generate_random_matrix_gf2e(
            public_key->G,
            K,
            EN);
}

void rank::rank_commitment::generate_commitment(
        NTL::vec_GF2E &c,
        const NTL::vec_GF2 &s,
        const NTL::vec_GF2 &m,
        const NTL::mat_GF2E &g,
        const NTL::vec_GF2E &e) {

    auto s_m = utils::gf2e_from_two_gf2(s, m);
    c = (s_m * g) + e;
}

void rank::rank_commitment::generate_commitment_without_e(
        NTL::vec_GF2E &c,
        const NTL::vec_GF2 &s,
        const NTL::vec_GF2 &m,
        const NTL::mat_GF2E &g) {

    auto s_m = utils::gf2e_from_two_gf2(s, m);

    NTL::vec_GF2E e;
    utils::generate_vector_of_specific_rank(
            e,
            EN,
            RHO);

    c = (s_m * g) + e;
}

int rank::rank_commitment::verify_proof(
        const NTL::vec_GF2E &c,
        const NTL::vec_GF2 &s,
        const NTL::vec_GF2 &m,
        const NTL::mat_GF2E &g) {

    auto s_m = utils::gf2e_from_two_gf2(s, m);
    auto e = (s_m * g) + c;

    if (utils::rank_of_vector(e) != RHO) {
        return 1;
    }

    return 0;
}