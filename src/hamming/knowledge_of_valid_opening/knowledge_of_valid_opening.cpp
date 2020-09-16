#include "knowledge_of_valid_opening.h"
#include <NTL/GF2X.h>
#include <utils/utils.h>
#include <hamming/jain_commitment/jain_commitment.h>

void hamming_metric::knowledge_of_valid_opening::generate_public_key(
        public_key_t * public_key,
        const private_key_t *private_key) {

    NTL::vec_GF2 r;
    utils::generate_random_binary_matrix(
            public_key->A,
            JAIN_K,
            JAIN_L + JAIN_V);

    utils::generate_random_binary_vector(
            r,
            JAIN_L);

    hamming_metric::commitment::generate_commitment(
            public_key->commitment,
            public_key->A,
            r,
            private_key->m,
            private_key->e);
}

void hamming_metric::knowledge_of_valid_opening::generate_private_key(
        private_key_t * private_key) {

    private_key->e.kill();
    private_key->m.kill();

    utils::generate_random_binary_vector(
            private_key->m,
            JAIN_V);

    utils::generate_vector_of_weight_w(
            private_key->e,
            JAIN_K,
            W);
}

void hamming_metric::knowledge_of_valid_opening::generate_random_values(
        random_values_t *random_values) {

    ::utils::generate_random_binary_vector(
            random_values->v,
            JAIN_L + JAIN_V);

    ::utils::generate_random_binary_vector(
            random_values->f,
            JAIN_K);
}

void hamming_metric::knowledge_of_valid_opening::generate_revealed_values(
        revealed_values_t *revealed_values) {

    utils::create_permutation_matrix(
            revealed_values->P,
            JAIN_K);
}

void hamming_metric::knowledge_of_valid_opening::generate_commitments_and_responses(
        responses_t *responses,
        commitments_t *commitments,
        const random_values_t *random_values,
        const revealed_values_t *revealed_values,
        const public_key_t *public_key,
        const private_key_t *private_key) {

    ::hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_0(
            commitments->c0,
            commitments->r0,
            responses->t0,
            random_values->v,
            public_key->A,
            random_values->f);

    ::hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_1(
            commitments->c1,
            commitments->r1,
            responses->t1,
            public_key->A,
            revealed_values->P,
            random_values->f);

    ::hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_2(
            commitments->c2,
            commitments->r2,
            responses->t2,
            public_key->A,
            revealed_values->P,
            random_values->f,
            private_key->e);
}

void hamming_metric::knowledge_of_valid_opening::encode(
        NTL::vec_GF2 &out,
        const NTL::vec_GF2 &v) {

    out = utils::encode_binary_vector(v, JAIN_V);
}

void hamming_metric::knowledge_of_valid_opening::commit(
        NTL::vec_GF2 &c,
        NTL::vec_GF2 &r,
        const NTL::vec_GF2 &v,
        const NTL::mat_GF2 &A) {

    utils::generate_random_binary_vector(
            r,
            JAIN_L);

    hamming_metric::commitment::generate_commitment(
            c,
            A,
            r,
            v);
}

void hamming_metric::knowledge_of_valid_opening::generate_response_0(
        NTL::vec_GF2 &t0,
        const NTL::vec_GF2 &n,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &f) {

    t0 = (A * n) + f;
}

void hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_0(
        NTL::vec_GF2 &c0,
        NTL::vec_GF2 &r0,
        NTL::vec_GF2 &t0,
        const NTL::vec_GF2 &n,
        const NTL::mat_GF2 &A,
        const NTL::vec_GF2 &f) {

    generate_response_0(
            t0,
            n,
            A,
            f);

    NTL::vec_GF2 encoded;
    encode(
            encoded,
            t0);

    commit(
            c0,
            r0,
            encoded,
            A);

}

void hamming_metric::knowledge_of_valid_opening::generate_response_1(
        NTL::vec_GF2 &t1,
        const NTL::mat_GF2 &P,
        const NTL::vec_GF2 &f) {

    t1 = P * f;
}

void hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_1(
        NTL::vec_GF2 &c1,
        NTL::vec_GF2 &r1,
        NTL::vec_GF2 &t1,
        const NTL::mat_GF2 &A,
        const NTL::mat_GF2 &P,
        const NTL::vec_GF2 &f) {

    generate_response_1(
            t1,
            P,
            f);

    NTL::vec_GF2 encoded;
    encode(
            encoded,
           t1);

    commit(
            c1,
           r1,
           encoded,
           A);
}

void hamming_metric::knowledge_of_valid_opening::generate_response_2(
        NTL::vec_GF2 &t2,
        const NTL::mat_GF2 &P,
        const NTL::vec_GF2 &f,
        const NTL::vec_GF2 &e) {

    t2 = P * (f + e);
}

void hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_2(
        NTL::vec_GF2 &c2,
        NTL::vec_GF2 &r2,
        NTL::vec_GF2 &t2,
        const NTL::mat_GF2 &A,
        const NTL::mat_GF2 &P,
        const NTL::vec_GF2 &f,
        const NTL::vec_GF2 &e) {

    generate_response_2(
            t2,
            P,
            f,
            e);

    NTL::vec_GF2 encoded;
    encode(
            encoded,
           t2);

    commit(
            c2,
           r2,
           encoded,
           A);
}

int hamming_metric::knowledge_of_valid_opening::verify_0(
        const NTL::vec_GF2 &c0,
        const NTL::vec_GF2 &r0,
        const NTL::vec_GF2 &t0,
        const NTL::vec_GF2 &c1,
        const NTL::vec_GF2 &r1,
        const NTL::vec_GF2 &t1,
        const NTL::mat_GF2 &P,
        const public_key_t *public_key) {

    auto _t0 = utils::encode_binary_vector(t0, JAIN_V);
    auto _t1 = utils::encode_binary_vector(t1, JAIN_V);

    if (hamming_metric::commitment::verify(
            c0,
            public_key->A,
            r0,
            _t0) != 0) {
        std::cout << "Knowledge of valid opening. Verification failed on ch = 0 and c0" << std::endl;
        return 1;
    }

    if (hamming_metric::commitment::verify(
            c1,
            public_key->A,
            r1,
            _t1) != 0) {
        std::cout << "Knowledge of valid opening. Verification failed on ch = 0 and c1" << std::endl;
        return 1;
    }

    auto sum = t0 + (NTL::inv(P) * t1);

    NTL::vec_GF2 result;
    if(utils::solve_equation(
            result,
            public_key->A,
            sum) != 0) {
        std::cout << "No solutions" << std::endl;
        return 1;
    }

    return 0;
}

int hamming_metric::knowledge_of_valid_opening::verify_1(
        const NTL::vec_GF2 &c0,
        const NTL::vec_GF2 &r0,
        const NTL::vec_GF2 &t0,
        const NTL::vec_GF2 &c2,
        const NTL::vec_GF2 &r2,
        const NTL::vec_GF2 &t2,
        const NTL::mat_GF2 &P,
        const public_key_t *public_key) {

    auto _t0 = utils::encode_binary_vector(t0, JAIN_V);
    auto _t2 = utils::encode_binary_vector(t2, JAIN_V);

    if (hamming_metric::commitment::verify(
            c0,
            public_key->A,
            r0,
            _t0) != 0) {
        std::cout << "Knowledge of valid opening. Verification failed on ch = 1 and c0" << std::endl;
        return 1;
    }

    if (hamming_metric::commitment::verify(
            c2,
            public_key->A,
            r2,
            _t2) != 0) {
        std::cout << "Knowledge of valid opening. Verification failed on ch = 1 and c2" << std::endl;
        return 1;
    }

    auto sum = t0 + public_key->commitment + (NTL::inv(P) * t2);

    NTL::vec_GF2 result;
    if(utils::solve_equation(
            result,
            public_key->A,
            sum) != 0) {
        std::cout << "No solutions" << std::endl;
        return 1;
    }

    return 0;
}

int hamming_metric::knowledge_of_valid_opening::verify_2(
        const NTL::vec_GF2 &c1,
        const NTL::vec_GF2 &r1,
        const NTL::vec_GF2 &t1,
        const NTL::vec_GF2 &c2,
        const NTL::vec_GF2 &r2,
        const NTL::vec_GF2 &t2,
        const public_key_t *public_key) {

    auto _t1 = utils::encode_binary_vector(t1, JAIN_V);
    auto _t2 = utils::encode_binary_vector(t2, JAIN_V);

    if (hamming_metric::commitment::verify(
            c1,
            public_key->A,
            r1,
            _t1) != 0) {
        std::cout << "Knowledge of valid opening. Verification failed on ch = 2 and c1" << std::endl;
        return 1;
    }

    if (hamming_metric::commitment::verify(
            c2,
            public_key->A,
            r2,
            _t2) != 0) {
        std::cout << "Knowledge of valid opening. Verification failed on ch = 2 and c2" << std::endl;
        return 1;
    }

    if (NTL::weight(t1 + t2) != W) {
        return 1;
    }

    return 0;
}