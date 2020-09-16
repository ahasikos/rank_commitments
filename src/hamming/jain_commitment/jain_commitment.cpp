#include "jain_commitment.h"
#include <utils/utils.h>

void hamming_metric::commitment::generate_public_key(
        hamming_metric::commitment::public_key_t *public_key) {

    utils::generate_random_binary_matrix(
            public_key->A,
            JAIN_K,
            JAIN_L + JAIN_V);
}

void hamming_metric::commitment::calculate_y(
        NTL::vec_GF2 &y,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &r,
        const NTL::vec_GF2 &m,
        const NTL::vec_GF2 &e) {

    NTL::vec_GF2 r_(r);
    NTL::append(r_, m);

    y = (A * r_) + e;
}

void hamming_metric::commitment::generate_commitment(
        NTL::vec_GF2 &commitment,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &r,
        const NTL::vec_GF2 &m,
        const NTL::vec_GF2 &e) {

    NTL::vec_GF2 r_(r);
    NTL::append(r_, m);

    commitment = (A * r_) + e;
}

void hamming_metric::commitment::generate_commitment(
        NTL::vec_GF2 &commitment,
        const public_key_t *public_key,
        const NTL::vec_GF2 &r,
        const NTL::vec_GF2 &m) {

    hamming_metric::commitment::generate_commitment(
        commitment,
        public_key->A,
        r,
        m);
}

void hamming_metric::commitment::generate_commitment(
        NTL::vec_GF2 &c,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &r,
        const NTL::vec_GF2 &m) {

    NTL::vec_GF2 e;
    utils::generate_vector_of_weight_w(
            e,
            JAIN_K,
            W);

    calculate_y(
            c,
            A,
            r,
            m,
            e);
}

void hamming_metric::commitment::generate_commitment(
        NTL::vec_GF2 &c,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &m) {

    NTL::vec_GF2 e;
    utils::generate_vector_of_weight_w(
            e,
            JAIN_K,
            W);

    c = (A * m) + e;
}

int hamming_metric::commitment::verify(
        const NTL::vec_GF2 &commitment,
        const public_key_t *public_key,
        const NTL::vec_GF2 &r,
        const NTL::vec_GF2 &m) {

    return verify(
            commitment,
            public_key->A,
            r,
            m);

}

int hamming_metric::commitment::verify(
        const NTL::vec_GF2 &c,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &r,
        const NTL::vec_GF2 &m) {

    NTL::vec_GF2 r_(r);
    NTL::append(r_, m);

    auto e = (A * r_) + c;

    if (NTL::weight(e) != W) {
        return 1;
    }

    return 0;
}

