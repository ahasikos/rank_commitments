#include <NTL/vec_GF2E.h>
#include <rank/knowledge_of_valid_opening/knowledge_of_valid_opening.h>
#include <rank/rank_commitment/rank_commitment.h>
#include <utils/utils.h>
#include "linear_relations.h"

void rank::linear_relations::initalized_commitments_and_responses(
        commitments_t *commitments,
        responses_t *responses) {

    commitments->s0.SetLength(I);
    commitments->s1.SetLength(I);
    commitments->s2.SetLength(I);

    commitments->c0.SetLength(I);
    commitments->c1.SetLength(I);
    commitments->c2.SetLength(I);

    responses->r1.SetLength(I);
    responses->r2.SetLength(I);
    responses->r3.SetLength(I);
}

void rank::linear_relations::generate_revealed_values(
        revealed_values_t *revealed_values) {

    revealed_values->P.SetLength(I);
    revealed_values->Q.SetLength(I);

    ::utils::generate_random_binary_matrix(
            revealed_values->matrices.x_0,
            MI,
            MI);
    ::utils::generate_random_binary_matrix(
            revealed_values->matrices.x_1,
            MI,
            MI);

    for(int i = 0; i < I; i++) {
        utils::generate_random_square_invertible_matrix(
                revealed_values->P[i],
                EN);
        utils::generate_random_square_invertible_matrix(
                revealed_values->Q[i],
                EM);
    }
}

void rank::linear_relations::generate_private_key(
        private_key_t *private_key,
        const linear_relation_matrices_t *matrices) {

    private_key->m.kill();

    private_key->e.kill();
    private_key->e.SetLength(I);

    for(int i = 0; i < I; i++) {
        private_key->e[i].kill();
        private_key->e[i].SetLength(EN);
        ::utils::generate_vector_of_specific_rank(
                private_key->e[i],
                EN,
                RHO);
    }

    for(int i = 0; i < 2; i++) {
        private_key->m.append(NTL::vec_GF2());
        private_key->m[i] = NTL::random_vec_GF2(MI);
    }
    private_key->m.append((private_key->m[0] * matrices->x_0) + (private_key->m[1] * matrices->x_1));
}

void rank::linear_relations::generate_public_key(
        public_key_t *public_key,
        const private_key_t *private_key) {

    public_key->commitments.SetLength(I);

    utils::generate_random_matrix_gf2e(
            public_key->G,
            K,
            EN);

    for(int i = 0; i < I; i++) {
        NTL::vec_GF2 s;
        utils::generate_random_binary_vector(
                s,
                PI);

        rank::rank_commitment::generate_commitment(
                public_key->commitments[i],
                s,
                private_key->m[i],
                public_key->G,
                private_key->e[i]);
    }
}

void rank::linear_relations::generate_random_values(
        random_values_t *random_values,
        const linear_relation_matrices_t *matrices) {

    for (int i = 0; i < I; i++) {
        random_values->u.append(NTL::random_vec_GF2(PI));
        random_values->f.append(NTL::random_vec_GF2E(EN));
    }

    for (int i = 0; i < I - 1; i++) {
        random_values->v.append(NTL::random_vec_GF2(MI));
    }

    auto v_2 = (random_values->v[0] * matrices->x_0) + (random_values->v[1] * matrices->x_1);
    random_values->v.append(v_2);

    random_values->u_v = random_values->u;

    for(int i = 0; i < I; i++) {
        NTL::append(random_values->u_v[i], random_values->v[i]);
    }
}

void rank::linear_relations::generate_commitments_and_responses(
        commitments_t *commitments,
        responses_t *responses,
        const random_values_t *random_values,
        const revealed_values_t *revealed_values,
        const private_key_t *private_key,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        rank::knowledge_of_valid_opening::generate_commitment_0_and_response_0(
                commitments->c0[i],
                commitments->s0[i],
                responses->r1[i],
                utils::gf2e_from_vec_gf2(random_values->u_v[i]),
                random_values->f[i],
                revealed_values->P[i],
                revealed_values->Q[i],
                public_key->G);

        rank::knowledge_of_valid_opening::generate_commitment_1_and_response_1(
                commitments->c1[i],
                commitments->s1[i],
                responses->r2[i],
                random_values->f[i],
                revealed_values->P[i],
                revealed_values->Q[i],
                public_key->G);

        rank::knowledge_of_valid_opening::generate_commitment_2_and_response_2(
                commitments->c2[i],
                commitments->s2[i],
                responses->r3[i],
                private_key->e[i],
                random_values->f[i],
                revealed_values->P[i],
                revealed_values->Q[i],
                public_key->G);
    }
}

int rank::linear_relations::verify_0(
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
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _r1 = utils::encode(P[i], Q[i], r1[i], MI);
        if (rank::rank_commitment::verify_proof(
                c0[i],
                s0[i],
                _r1,
                public_key->G) != 0) {
            std::cout << "Verification 2 for ch = 0 failed" << std::endl;
            return 1;
        }
    }

    for (int i = 0; i < I; i++) {
        auto _r2 = utils::encode_2(r2[i], MI);
        if (rank::rank_commitment::verify_proof(
                c1[i],
                s1[i],
                _r2,
                public_key->G) != 0) {
            std::cout << "Verification 2 for ch = 0 failed" << std::endl;
            return 1;
        }
    }

    NTL::Vec<NTL::vec_GF2E> results;
    for (int i = 0; i < I; i++) {
        NTL::vec_GF2E pi_inv_r2;
        rank::knowledge_of_valid_opening::calculate_pi_inv(
                pi_inv_r2,
                P[i],
                Q[i],
                r2[i]);

        NTL::vec_GF2E result;
        if (utils::solve_equation(
                result,
                public_key->G,
                r1[i] + pi_inv_r2) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }
        results.append(result);
    }

    NTL::Vec<NTL::vec_GF2E> b;
    b.SetLength(I);
    for (int i = 0; i < I; i++) {
        NTL::VectorCopy(b[i], results[i], K);
    }

    auto b0_gf2 = utils::gf2_from_gf2e(b[0]);
    auto b1_gf2 = utils::gf2_from_gf2e(b[1]);
    auto b2_gf2 = utils::gf2_from_gf2e(b[2]);

    NTL::vec_GF2 b0_gf2_s, b1_gf2_s, b2_gf2_s;
    for (int j = PI; j < PI + MI; j++) {
        b0_gf2_s.append(b0_gf2[j]);
        b1_gf2_s.append(b1_gf2[j]);
        b2_gf2_s.append(b2_gf2[j]);
    }


    if (NTL::IsZero(b2_gf2_s + ((b0_gf2_s * x_0) + (b1_gf2_s * x_1)))) {
        return 0;
    } else {
        std::cout << "Verify 0 failed" << std::endl;
        std::cout << b2_gf2_s << std::endl;
        std::cout << (b0_gf2_s * x_0) + (b1_gf2_s * x_1) << std::endl;
        return 1;
    }
}

int rank::linear_relations::verify_1(
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
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _r1 = utils::encode(P[i], Q[i], r1[i], MI);
        if (rank::rank_commitment::verify_proof(
                c0[i],
                s0[i],
                _r1,
                public_key->G) != 0) {
            std::cout << "Verification 2 for ch = 0 failed" << std::endl;
            return 1;
        }
    }

    for (int i = 0; i < I; i++) {
        auto _r3 = utils::encode_2(r3[i], MI);
        if (rank::rank_commitment::verify_proof(
                c2[i],
                s2[i],
                _r3,
                public_key->G) != 0) {
            std::cout << "Verification 2 for ch = 0 failed" << std::endl;
            return 1;
        }
    }

    NTL::Vec<NTL::vec_GF2E> results;
    for (int i = 0; i < I; i++) {
        NTL::vec_GF2E pi_inv_r3;
        rank::knowledge_of_valid_opening::calculate_pi_inv(
                pi_inv_r3,
                P[i],
                Q[i],
                r3[i]);

        NTL::vec_GF2E result;
        if (utils::solve_equation(
                result,
                public_key->G,
                r1[i] + pi_inv_r3 + public_key->commitments[i]) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }
        results.append(result);
    }

    NTL::Vec<NTL::vec_GF2E> d;
    d.SetLength(I);
    for (int i = 0; i < I; i++) {
        NTL::VectorCopy(d[i], results[i], K);
    }

    auto d0_gf2 = utils::gf2_from_gf2e(d[0]);
    auto d1_gf2 = utils::gf2_from_gf2e(d[1]);
    auto d2_gf2 = utils::gf2_from_gf2e(d[2]);

    NTL::vec_GF2 d0_gf2_s, d1_gf2_s, d2_gf2_s;
    for (int j = 0; j < MI; j++) {
        d0_gf2_s.append(d0_gf2[j + PI]);
        d1_gf2_s.append(d1_gf2[j + PI]);
        d2_gf2_s.append(d2_gf2[j + PI]);
    }

    if (NTL::IsZero(d2_gf2_s + ((d0_gf2_s * x_0) + (d1_gf2_s * x_1)))) {
        return 0;
    } else {
        std::cout << "Verify 1 failed" << std::endl;
        std::cout << d2_gf2_s << std::endl;
        std::cout << (d0_gf2_s * x_0) + (d1_gf2_s * x_1) << std::endl;
        return 1;
    }
}

int rank::linear_relations::verify_2(
        const NTL::Vec<NTL::vec_GF2> &s1,
        const NTL::Vec<NTL::vec_GF2> &s2,
        const NTL::Vec<NTL::vec_GF2E> &c1,
        const NTL::Vec<NTL::vec_GF2E> &c2,
        const NTL::Vec<NTL::vec_GF2E> &r2,
        const NTL::Vec<NTL::vec_GF2E> &r3,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _r2 = utils::encode_2(r2[i], MI);
        if (rank::rank_commitment::verify_proof(
                c1[i],
                s1[i],
                _r2,
                public_key->G)) {
            std::cout << "Verification 1 for ch = 2 failed" << std::endl;
            return 1;
        }
    }

    for (int i = 0; i < I; i++) {
        auto _r3 = utils::encode_2(r3[i], MI);
        if (rank::rank_commitment::verify_proof(
                c2[i],
                s2[i],
                _r3,
                public_key->G)) {
            std::cout << "Verification 2 for ch = 2 failed" << std::endl;
            return 1;
        }
    }

    for(int i = 0; i < I; i++) {
        auto r2_plus_r3 = r2[i] + r3[i];

        NTL::mat_GF2 M;
        M.SetDims(EN, EM);

        for (int j = 0; j < EN; j++) {
            for (int z = 0; z < EM; z++) {
                if (NTL::IsZero(r2_plus_r3[j]._GF2E__rep[z])) {
                    M[j][z] = NTL::GF2(0);
                } else {
                    M[j][z] = NTL::GF2(1);
                }
            }
        }

        auto _M = M;

        auto res = NTL::gauss(_M);
        if (res != RHO) {
            std::cout << "Matrix weight not equal to RHO" << std::endl;
            return 1;
        }
    }

    return 0;
}
