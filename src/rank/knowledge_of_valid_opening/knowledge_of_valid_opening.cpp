#include "knowledge_of_valid_opening.h"
#include <rank/rank_params.h>
#include <rank/rank_commitment/rank_commitment.h>
#include <utils/utils.h>

void rank::knowledge_of_valid_opening::generate_private_key(
        private_key_t *private_key) {

    utils::generate_random_binary_vector(
            private_key->m,
            MI);
    utils::generate_vector_of_specific_rank(
            private_key->e,
            EN,
            RHO);

}

void rank::knowledge_of_valid_opening::generate_public_key(
        public_key_t *public_key,
        const private_key_t *private_key) {

    utils::generate_random_matrix_gf2e(
            public_key->G,
            K,
            EN);

    NTL::vec_GF2 s;
    utils::generate_random_binary_vector(
            s,
            PI);

    rank::rank_commitment::generate_commitment(
            public_key->commitment,
            s,
            private_key->m,
            public_key->G,
            private_key->e);
}

void rank::knowledge_of_valid_opening::generate_random_values(
        random_values_t *random_values) {

    utils::generate_random_binary_vector_gf2e(
            random_values->u,
            K);

    utils::generate_random_binary_vector_gf2e(
            random_values->f,
            EN);
}

void rank::knowledge_of_valid_opening::generate_revealed_values(
        revealed_values_t *revealed_values) {

    utils::generate_random_square_invertible_matrix(
            revealed_values->P,
            EN);
    utils::generate_random_square_invertible_matrix(
            revealed_values->Q,
            EM);
}

void rank::knowledge_of_valid_opening::generate_phi(
        NTL::mat_GF2 &m,
        const NTL::vec_GF2E &v) {

    m.SetDims(EM, v.length());
    for (int i = 0; i < v.length(); i++) {
        for (int j = 0; j < EM; j++) {
            m[j][i] = v[i]._GF2E__rep[j];
        }
    }
}

void rank::knowledge_of_valid_opening::generate_phi_inv(
        NTL::vec_GF2E &v,
        const NTL::mat_GF2 &m) {

    v = NTL::random_vec_GF2E(m.NumCols());

    for (int i = 0; i < m.NumCols(); i++) {
        for (int j = 0; j < m.NumRows(); j++) {
            v[i]._GF2E__rep[j] = m[j][i];
        }
    }
}

void rank::knowledge_of_valid_opening::calculate_pi(
        NTL::vec_GF2E &p,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::vec_GF2E &u) {

    NTL::mat_GF2 phi_u;
    generate_phi(phi_u, u);

    auto tmp = Q * phi_u * P;

    generate_phi_inv(p, tmp);
}

void rank::knowledge_of_valid_opening::calculate_pi_inv(
        NTL::vec_GF2E &p,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::vec_GF2E &u) {

    NTL::mat_GF2 phi_u;
    generate_phi(phi_u, u);

    auto tmp = NTL::inv(Q) * phi_u * NTL::inv(P);

    generate_phi_inv(p, tmp);
}

void rank::knowledge_of_valid_opening::encode(
        NTL::vec_GF2 &out,
        const NTL::vec_GF2E &v) {

    out = utils::encode_2(v, MI);
}

void rank::knowledge_of_valid_opening::encode(
        NTL::vec_GF2 &out,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::vec_GF2E &v) {

    out = utils::encode(P, Q, v, MI);
}

void rank::knowledge_of_valid_opening::commit(
        NTL::vec_GF2E &c,
        NTL::vec_GF2 &s,
        const NTL::vec_GF2 &m,
        const NTL::mat_GF2E &G
        ) {

    utils::generate_random_binary_vector(
            s,
            PI);

    rank::rank_commitment::generate_commitment_without_e(
            c,
            s,
            m,
            G);
}

void rank::knowledge_of_valid_opening::generate_response_0(
        NTL::vec_GF2E &r,
        const NTL::vec_GF2E &u,
        const NTL::vec_GF2E &f,
        const NTL::mat_GF2E &G) {

    r = (u * G) + f;
}

void rank::knowledge_of_valid_opening::generate_commitment_0_and_response_0(
        NTL::vec_GF2E &c0,
        NTL::vec_GF2 &s0,
        NTL::vec_GF2E &r1,
        const NTL::vec_GF2E &u,
        const NTL::vec_GF2E &f,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::mat_GF2E &G) {

    generate_response_0(
            r1,
            u,
            f,
            G);

    NTL::vec_GF2 encoded;
    encode(
            encoded,
            P,
            Q,
            r1);

    commit(
            c0,
            s0,
            encoded,
            G);
}

void rank::knowledge_of_valid_opening::generate_response_1(
        NTL::vec_GF2E &r,
        const NTL::vec_GF2E &f,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q) {

    rank::knowledge_of_valid_opening::calculate_pi(
            r,
            P,
            Q,
            f);
}

void rank::knowledge_of_valid_opening::generate_commitment_1_and_response_1(
        NTL::vec_GF2E &c1,
        NTL::vec_GF2 &s1,
        NTL::vec_GF2E &r2,
        const NTL::vec_GF2E &f,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::mat_GF2E &G) {

    generate_response_1(
            r2,
            f,
            P,
            Q);

    NTL::vec_GF2 encoded;
    encode(
            encoded,
            r2);

    commit(
            c1,
            s1,
            encoded,
            G);
}

void rank::knowledge_of_valid_opening::generate_response_2(
        NTL::vec_GF2E &r,
        const NTL::vec_GF2E &e,
        const NTL::vec_GF2E &f,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q) {

    rank::knowledge_of_valid_opening::calculate_pi(
            r,
            P,
            Q,
            e + f);
}

void rank::knowledge_of_valid_opening::generate_commitment_2_and_response_2(
        NTL::vec_GF2E &c2,
        NTL::vec_GF2 &s2,
        NTL::vec_GF2E &r3,
        const NTL::vec_GF2E &e,
        const NTL::vec_GF2E &f,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::mat_GF2E &G) {

    generate_response_2(
            r3,
            e,
            f,
            P,
            Q);

    NTL::vec_GF2 encoded;
    encode(
            encoded,
            r3);

    commit(
            c2,
            s2,
            encoded,
            G);
}

void rank::knowledge_of_valid_opening::generate_commitments_and_responses(
        commitments_t *commitments,
        responses_t *responses,
        const random_values_t *random_values,
        const revealed_values_t *revealed_values,
        const private_key_t *private_key,
        const public_key_t *public_key) {

    ::rank::knowledge_of_valid_opening::generate_commitment_0_and_response_0(
            commitments->c0,
            commitments->s0,
            responses->r1,
            random_values->u,
            random_values->f,
            revealed_values->P,
            revealed_values->Q,
            public_key->G);

    ::rank::knowledge_of_valid_opening::generate_commitment_1_and_response_1(
            commitments->c1,
            commitments->s1,
            responses->r2,
            random_values->f,
            revealed_values->P,
            revealed_values->Q,
            public_key->G);

    ::rank::knowledge_of_valid_opening::generate_commitment_2_and_response_2(
            commitments->c2,
            commitments->s2,
            responses->r3,
            private_key->e,
            random_values->f,
            revealed_values->P,
            revealed_values->Q,
            public_key->G);
}

int rank::knowledge_of_valid_opening::verify_0(
        const NTL::vec_GF2E &c0,
        const NTL::vec_GF2 &s0,
        const NTL::vec_GF2E &c1,
        const NTL::vec_GF2 &s1,
        const NTL::vec_GF2E &r1,
        const NTL::vec_GF2E &r2,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::mat_GF2E &G) {

    auto commitment_input = utils::encode(P, Q, r1, MI);

    if (rank::rank_commitment::verify_proof(
            c0,
            s0,
            commitment_input,
            G) != 0) {
        std::cout << "Verification 1 for ch = 0 failed" << std::endl;
        return 1;
    }

    commitment_input = utils::encode_2(r2, MI);

    if (rank::rank_commitment::verify_proof(
            c1,
            s1,
            commitment_input,
            G) != 0) {
        std::cout << "Verification 2 for ch = 0 failed" << std::endl;
        return 1;
    }

    NTL::vec_GF2E pi_inv;
    calculate_pi_inv(
            pi_inv,
            P,
            Q,
            r2);

    auto sum = r1 + pi_inv;

    NTL::vec_GF2E result;
    if(utils::solve_equation(
            result,
            G,
            sum) != 0) {
        std::cout << "No solutions" << std::endl;
        return 1;
    }

    return 0;
}

int rank::knowledge_of_valid_opening::verify_1(
        const NTL::vec_GF2E &c0,
        const NTL::vec_GF2 &s0,
        const NTL::vec_GF2E &c2,
        const NTL::vec_GF2 &s2,
        const NTL::vec_GF2E &r1,
        const NTL::vec_GF2E &r3,
        const NTL::vec_GF2E &commitment,
        const NTL::mat_GF2 &P,
        const NTL::mat_GF2 &Q,
        const NTL::mat_GF2E &G) {

    auto _r1 = utils::encode(P, Q, r1, MI);
    if (rank::rank_commitment::verify_proof(
            c0,
            s0,
            _r1,
            G) != 0) {
        std::cout << "Verification 1 for ch = 1 failed" << std::endl;
        return 1;
    }

    auto _r3 = utils::encode_2(r3, MI);
    if (rank::rank_commitment::verify_proof(
            c2,
            s2,
            _r3,
            G) != 0) {
        std::cout << "Verification 2 for ch = 1 failed" << std::endl;
        return 1;
    }

    NTL::vec_GF2E pi_inv_r3;
    calculate_pi_inv(
            pi_inv_r3,
            P,
            Q,
            r3);

    auto sum = r1 + pi_inv_r3 + commitment;

    NTL::vec_GF2E result;
    if(utils::solve_equation(
            result,
            G,
            sum) != 0) {
        std::cout << "No solutions" << std::endl;
        return 1;
    }
    return 0;
}

int rank::knowledge_of_valid_opening::verify_2(
        const NTL::vec_GF2E &c1,
        const NTL::vec_GF2 &s1,
        const NTL::vec_GF2E &c2,
        const NTL::vec_GF2 &s2,
        const NTL::vec_GF2E &r2,
        const NTL::vec_GF2E &r3,
        const NTL::mat_GF2E &G) {

    auto _r2 = utils::encode_2(r2, MI);

    if (rank::rank_commitment::verify_proof(
            c1,
            s1,
            _r2,
            G) != 0) {
        std::cout << "Verification 1 for ch = 2 failed" << std::endl;
        return 1;
    }

    auto _r3 = utils::encode_2(r3, MI);

    if (rank::rank_commitment::verify_proof(
            c2,
            s2,
            _r3,
            G) != 0) {
        std::cout << "Verification 2 for ch = 2 failed" << std::endl;
        return 1;
    }

    auto r2_plus_r3 = r2 + r3;

    if (utils::rank_of_vector(r2_plus_r3) != RHO) {
        return 1;
    }

    return 0;
}
