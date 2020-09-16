#include <rank/rank_commitment/rank_commitment.h>
#include <utils/utils.h>
#include <rank/knowledge_of_valid_opening/knowledge_of_valid_opening.h>
#include "multiplicative_relations.h"

void rank::multiplicative_relations::initialize_commitments_and_responses(
        commitments_t *commitments,
        responses_t *responses) {

    responses->r_i_1.SetLength(I);
    responses->r_i_2.SetLength(I);
    responses->r_i_3.SetLength(I);

    responses->r_i_j_1.SetLength(I);
    responses->r_i_j_2.SetLength(I);
    responses->r_i_j_3.SetLength(I);

    commitments->c_i_0.SetLength(I);
    commitments->c_i_1.SetLength(I);
    commitments->c_i_2.SetLength(I);

    commitments->s_i_0.SetLength(I);
    commitments->s_i_1.SetLength(I);
    commitments->s_i_2.SetLength(I);

    commitments->c_i_j_0.SetLength(I);
    commitments->c_i_j_1.SetLength(I);
    commitments->c_i_j_2.SetLength(I);

    commitments->s_i_j_0.SetLength(I);
    commitments->s_i_j_1.SetLength(I);
    commitments->s_i_j_2.SetLength(I);

    for (int i = 0; i < I; i++) {
        responses->r_i_j_1[i].SetLength(J);
        responses->r_i_j_2[i].SetLength(J);
        responses->r_i_j_3[i].SetLength(J);

        commitments->c_i_j_0[i].SetLength(J);
        commitments->c_i_j_1[i].SetLength(J);
        commitments->c_i_j_2[i].SetLength(J);

        commitments->s_i_j_0[i].SetLength(J);
        commitments->s_i_j_1[i].SetLength(J);
        commitments->s_i_j_2[i].SetLength(J);
    }
}

void rank::multiplicative_relations::generate_private_key(
        private_key_t *private_key) {

    //Generate m
    {
        private_key->m.kill();
        private_key->m.SetLength(I);

        utils::generate_random_binary_vector(
                private_key->m[0],
                MI);

        utils::generate_random_binary_vector(
                private_key->m[1],
                MI);

        private_key->m[2].SetLength(MI);
        for (int i = 0; i < MI; i++) {
            private_key->m[2][i] = private_key->m[0][i] * private_key->m[1][i];
        }
    }

    //Generate e
    {
        private_key->e.kill();
        private_key->e.SetLength(I);

        for (int i = 0; i < I; i++) {
            utils::generate_vector_of_specific_rank(
                    private_key->e[i],
                    EN,
                    RHO);

            auto M = utils::mat_gf2_from_vec_gf2e(private_key->e[i]);
            auto rank = NTL::gauss(M);
            if(rank != RHO) {
                std::cout << M << std::endl;
                std::cout << "Rank " << rank << std::endl;
            }
        }
    }
}

void rank::multiplicative_relations::generate_public_key(
        public_key_t *public_key,
        const private_key_t *private_key) {

    public_key->commitments_i.kill();
    public_key->commitments_i.SetLength(I);

    utils::generate_random_matrix_gf2e(
            public_key->G,
            K,
            EN);

    NTL::vec_GF2 s;
    for (int i = 0; i < I; i++) {
        utils::generate_random_binary_vector(
                s,
                PI);

        rank::rank_commitment::generate_commitment(
                public_key->commitments_i[i],
                s,
                private_key->m[i],
                public_key->G,
                private_key->e[i]);
    }
}

void rank::multiplicative_relations::generate_random_values(
        random_values_t *random_values,
        const multiplicative_relation_matrices_t *matrices) {

    //Generate u_i_j
    {
        random_values->u_i_j.kill();
        random_values->u_i_j.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->u_i_j[i].SetLength(J);
            for (int j = 0; j < J; j++) {
                random_values->u_i_j[i][j] = NTL::random_vec_GF2(PI);
            }
        }
    }

    //Generate f_i_j
    {
        random_values->f_i_j.kill();
        random_values->f_i_j.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->f_i_j[i].SetLength(J);
            for (int j = 0; j < J; j++) {
                random_values->f_i_j[i][j] = NTL::random_vec_GF2E(EN);
            }
        }
    }

    //Generate v_i_j
    {
        random_values->v_i_j.kill();
        random_values->v_i_j.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->v_i_j[i].SetLength(J);
            for (int j = 0; j < J; j++) {
                random_values->v_i_j[i][j] = NTL::random_vec_GF2(MI);
            }
        }
    }

    {
        random_values->u_i.kill();
        random_values->u_i.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->u_i[i] = NTL::random_vec_GF2(PI);
        }
    }

    {
        random_values->f_i.kill();
        random_values->f_i.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->f_i[i] = NTL::random_vec_GF2E(EN);
        }
    }

    //Generate v_i
    {
        random_values->v_i.kill();
        random_values->v_i.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->v_i[i].SetLength(MI);
            for (int j = 0; j < J; j++) {
                random_values->v_i[i] += (matrices->R[j] * random_values->v_i_j[i][j]);
            }
        }
    }
}

void rank::multiplicative_relations::generate_revealed_values(
        revealed_values_t *revealed_values,
        const private_key_t *private_key,
        const public_key_t *public_key) {

    revealed_values->commitments_i_j.kill();
    revealed_values->commitments_i_j.SetLength(I);

    revealed_values->e_i_j.kill();
    revealed_values->e_i_j.SetLength(I);

    revealed_values->P_i.SetLength(I);
    revealed_values->P_i_j.SetLength(I);

    revealed_values->Q_i.SetLength(I);
    revealed_values->Q_i_j.SetLength(I);

    NTL::Vec<NTL::vec_GF2> m_prime_i;
    {
        m_prime_i.SetLength(I);
        utils::sample_messages(m_prime_i[0], m_prime_i[1], m_prime_i[2], MI);
        utils::generate_relation_matrix(
                revealed_values->matrices._R,
                revealed_values->matrices.R,
                m_prime_i,
                private_key->m,
                MI);
    }


    {
        generate_m_prime_i_j_from_m_prime_i(
                revealed_values->m_prime_i_j,
                m_prime_i);
    }

    NTL::vec_GF2 s;
    for (int i = 0; i < I; i++) {
        utils::generate_random_square_invertible_matrix(
                revealed_values->P_i[i],
                EN);

        utils::generate_random_square_invertible_matrix(
                revealed_values->Q_i[i],
                EM);

        revealed_values->e_i_j[i].SetLength(J);
        revealed_values->commitments_i_j[i].SetLength(J);
        revealed_values->P_i_j[i].SetLength(J);
        revealed_values->Q_i_j[i].SetLength(J);

        for(int j = 0; j < J; j++) {

            utils::generate_random_binary_vector(
                    s,
                    PI);

            utils::generate_random_square_invertible_matrix(
                    revealed_values->P_i_j[i][j],
                    EN);

            utils::generate_random_square_invertible_matrix(
                    revealed_values->Q_i_j[i][j],
                    EM);

            utils::generate_vector_of_specific_rank(
                    revealed_values->e_i_j[i][j],
                    EN,
                    RHO);

            rank::rank_commitment::generate_commitment(
                    revealed_values->commitments_i_j[i][j],
                    s,
                    revealed_values->m_prime_i_j[i][j],
                    public_key->G,
                    revealed_values->e_i_j[i][j]);
        }
    }
}

void rank::multiplicative_relations::generate_m_prime_i_j_from_m_prime_i(NTL::Vec<NTL::Vec<NTL::vec_GF2>> &m_prime_i_j,
                                                                         const NTL::Vec<NTL::vec_GF2> &m_prime) {
    m_prime_i_j.kill();
    {
        m_prime_i_j.SetLength(I);
        int start_index;

        for (int i = 0; i < I; i++) {
            m_prime_i_j[i].SetLength(J);
            start_index = 0;
            for (int j = 0; j < J; j++) {
                NTL::vec_GF2 tmp;
                tmp.SetLength(MI);
                for (int z = 0; z < MI; z++) {
                    tmp[z] = m_prime[i][start_index + z];
                }
                start_index += MI;
                m_prime_i_j[i][j].append(tmp);
            }
        }
    }
}

void rank::multiplicative_relations::generate_commitments(
        commitments_t *commitments,
        responses_t *responses,
        const random_values_t *random_values,
        const revealed_values_t *revealed_values,
        const private_key_t *private_key,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto u_v = random_values->u_i[i];
        NTL::append(u_v, random_values->v_i[i]);

        rank::knowledge_of_valid_opening::generate_commitment_0_and_response_0(
                commitments->c_i_0[i],
                commitments->s_i_0[i],
                responses->r_i_1[i],
                utils::gf2e_from_vec_gf2(u_v),
                random_values->f_i[i],
                revealed_values->P_i[i],
                revealed_values->Q_i[i],
                public_key->G);

        rank::knowledge_of_valid_opening::generate_commitment_1_and_response_1(
                commitments->c_i_1[i],
                commitments->s_i_1[i],
                responses->r_i_2[i],
                random_values->f_i[i],
                revealed_values->P_i[i],
                revealed_values->Q_i[i],
                public_key->G);

        rank::knowledge_of_valid_opening::generate_commitment_2_and_response_2(
                commitments->c_i_2[i],
                commitments->s_i_2[i],
                responses->r_i_3[i],
                private_key->e[i],
                random_values->f_i[i],
                revealed_values->P_i[i],
                revealed_values->Q_i[i],
                public_key->G);
    }

    for (int i = 0; i < I; i++) {
        for (int j = 0; j < J; j++) {
            auto u_v = random_values->u_i_j[i][j];
            NTL::append(u_v, random_values->v_i_j[i][j]);

            rank::knowledge_of_valid_opening::generate_commitment_0_and_response_0(
                    commitments->c_i_j_0[i][j],
                    commitments->s_i_j_0[i][j],
                    responses->r_i_j_1[i][j],
                    utils::gf2e_from_vec_gf2(u_v),
                    random_values->f_i_j[i][j],
                    revealed_values->P_i_j[i][j],
                    revealed_values->Q_i_j[i][j],
                    public_key->G);

            rank::knowledge_of_valid_opening::generate_commitment_1_and_response_1(
                    commitments->c_i_j_1[i][j],
                    commitments->s_i_j_1[i][j],
                    responses->r_i_j_2[i][j],
                    random_values->f_i_j[i][j],
                    revealed_values->P_i_j[i][j],
                    revealed_values->Q_i_j[i][j],
                    public_key->G);

            rank::knowledge_of_valid_opening::generate_commitment_2_and_response_2(
                    commitments->c_i_j_2[i][j],
                    commitments->s_i_j_2[i][j],
                    responses->r_i_j_3[i][j],
                    revealed_values->e_i_j[i][j],
                    random_values->f_i_j[i][j],
                    revealed_values->P_i_j[i][j],
                    revealed_values->Q_i_j[i][j],
                    public_key->G);
        }
    }
}

int rank::multiplicative_relations::verify_0(
        const NTL::Vec<NTL::vec_GF2E> &r_i_1,
        const NTL::Vec<NTL::vec_GF2E> &r_i_2,
        const NTL::Vec<NTL::vec_GF2> &s_i_0,
        const NTL::Vec<NTL::vec_GF2> &s_i_1,
        const NTL::Vec<NTL::vec_GF2E> &c_i_0,
        const NTL::Vec<NTL::vec_GF2E> &c_i_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &r_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &r_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &s_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &s_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &c_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &c_i_j_1,
        const NTL::Vec<NTL::mat_GF2> &P_i,
        const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &P_i_j,
        const NTL::Vec<NTL::mat_GF2> &Q_i,
        const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &Q_i_j,
        const NTL::Vec<NTL::mat_GF2> &R,
        const public_key_t *public_key) {

    NTL::Vec<NTL::vec_GF2> b_i_s;
    NTL::Vec<NTL::Vec<NTL::vec_GF2>> b_i_j_s;
    b_i_s.SetLength(I);
    b_i_j_s.SetLength(I);

    for (int i = 0; i < I; i++) {
        auto _r_i_1 = utils::encode(P_i[i], Q_i[i], r_i_1[i], MI);
        if (rank::rank_commitment::verify_proof(
                c_i_0[i],
                s_i_0[i],
                _r_i_1,
                public_key->G) != 0) {
            std::cout << "Verification 1 for ch = 0 failed" << std::endl;
            return 1;
        }

        auto _r_i_2 = utils::encode_2(r_i_2[i], MI);
        if (rank::rank_commitment::verify_proof(
                c_i_1[i],
                s_i_1[i],
                _r_i_2,
                public_key->G) != 0) {
            std::cout << "Verification 3 for ch = 0 failed" << std::endl;
            return 1;
        }

        NTL::vec_GF2E result;

        NTL::vec_GF2E pi_inv_t1;
        rank::knowledge_of_valid_opening::calculate_pi_inv(
                pi_inv_t1,
                P_i[i],
                Q_i[i],
                r_i_2[i]);

        if (utils::solve_equation(
                result,
                public_key->G,
                r_i_1[i] + pi_inv_t1) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }

        NTL::vec_GF2E b;
        NTL::VectorCopy(b, result, K);

        auto b_i = utils::gf2_from_gf2e(b);

        for (int z = 0; z < MI; z++) {
            b_i_s[i].append(b_i[z + PI]);
        }

        b_i_j_s[i].SetLength(J);
        for (int j = 0; j < J; j++) {
            auto _r_i_j_1 = utils::encode(P_i_j[i][j], Q_i_j[i][j], r_i_j_1[i][j],
                                          MI);
            if (rank::rank_commitment::verify_proof(
                    c_i_j_0[i][j],
                    s_i_j_0[i][j],
                    _r_i_j_1,
                    public_key->G) != 0) {
                std::cout << "Verification 2 for ch = 0 failed" << std::endl;
                return 1;
            }

            auto _r_i_j_2 = utils::encode_2(r_i_j_2[i][j], MI);
            if (rank::rank_commitment::verify_proof(
                    c_i_j_1[i][j],
                    s_i_j_1[i][j],
                    _r_i_j_2,
                    public_key->G) != 0) {
                std::cout << "Verification 4 for ch = 0 failed" << std::endl;
                return 1;
            }

            rank::knowledge_of_valid_opening::calculate_pi_inv(
                    pi_inv_t1,
                    P_i_j[i][j],
                    Q_i_j[i][j],
                    r_i_j_2[i][j]);

            if (utils::solve_equation(
                    result,
                    public_key->G,
                    r_i_j_1[i][j] + pi_inv_t1) != 0) {
                std::cout << "No Solutions" << std::endl;
                return 1;
            }

            NTL::VectorCopy(b, result, K);

            b_i = utils::gf2_from_gf2e(b);

            for (int q = 0; q < MI; q++) {
                b_i_j_s[i][j].append(b_i[q + PI]);
            }
        }
    }

    NTL::Vec<NTL::vec_GF2> r_b;
    r_b.SetLength(I);
    for (int i = 0; i < I; i++) {
        r_b[i].SetLength(MI);
        for (int j = 0; j < J; j++) {
            r_b[i] += (R[j] * b_i_j_s[i][j]);
        }
        if (b_i_s[i] != r_b[i]) {
            std::cout << "Error: verify_0" << std::endl;
            return 1;
        }
    }

    return 0;
}

int rank::multiplicative_relations::verify_1(
        const NTL::Vec<NTL::vec_GF2E> &r_i_1,
        const NTL::Vec<NTL::vec_GF2E> &r_i_3,
        const NTL::Vec<NTL::vec_GF2> &s_i_0,
        const NTL::Vec<NTL::vec_GF2> &s_i_2,
        const NTL::Vec<NTL::vec_GF2E> &c_i_0,
        const NTL::Vec<NTL::vec_GF2E> &c_i_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &r_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &r_i_j_3,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &s_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &s_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &c_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &c_i_j_2,
        const NTL::Vec<NTL::mat_GF2> &P_i,
        const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &P_i_j,
        const NTL::Vec<NTL::mat_GF2> &Q_i,
        const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &Q_i_j,
        const NTL::Vec<NTL::mat_GF2> &R,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &commitments_i_j,
        const public_key_t *public_key) {

    NTL::Vec<NTL::vec_GF2> b_i_s;
    NTL::Vec<NTL::Vec<NTL::vec_GF2>> b_i_j_s;
    b_i_s.SetLength(I);
    b_i_j_s.SetLength(I);

    for (int i = 0; i < I; i++) {
        auto _r_i_1 = utils::encode(P_i[i], Q_i[i], r_i_1[i], MI);
        if (rank::rank_commitment::verify_proof(
                c_i_0[i],
                s_i_0[i],
                _r_i_1,
                public_key->G) != 0) {
            std::cout << "Verification 1 for ch = 0 failed" << std::endl;
            return 1;
        }

        auto _r_i_3 = utils::encode_2(r_i_3[i], MI);
        if (rank::rank_commitment::verify_proof(
                c_i_2[i],
                s_i_2[i],
                _r_i_3,
                public_key->G) != 0) {
            std::cout << "Verification 3 for ch = 0 failed" << std::endl;
            return 1;
        }

        NTL::vec_GF2E result;

        NTL::vec_GF2E pi_inv_r2;
        rank::knowledge_of_valid_opening::calculate_pi_inv(
                pi_inv_r2,
                P_i[i],
                Q_i[i],
                r_i_3[i]);

        if (utils::solve_equation(
                result,
                public_key->G,
                r_i_1[i] + pi_inv_r2 + public_key->commitments_i[i]) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }

        NTL::vec_GF2E b;
        NTL::VectorCopy(b, result, K);

        auto b_i = utils::gf2_from_gf2e(b);

        for (int z = 0; z < MI; z++) {
            b_i_s[i].append(b_i[z + PI]);
        }

        b_i_j_s[i].SetLength(J);
        for (int j = 0; j < J; j++) {
            auto _r_i_j_1 = utils::encode(P_i_j[i][j], Q_i_j[i][j], r_i_j_1[i][j],
                                          MI);
            if (rank::rank_commitment::verify_proof(
                    c_i_j_0[i][j],
                    s_i_j_0[i][j],
                    _r_i_j_1,
                    public_key->G) != 0) {
                std::cout << "Verification 2 for ch = 0 failed" << std::endl;
                return 1;
            }

            auto _r_i_j_3 = utils::encode_2(r_i_j_3[i][j], MI);
            if (rank::rank_commitment::verify_proof(
                    c_i_j_2[i][j],
                    s_i_j_2[i][j],
                    _r_i_j_3,
                    public_key->G) != 0) {
                std::cout << "Verification 4 for ch = 0 failed" << std::endl;
                return 1;
            }

            rank::knowledge_of_valid_opening::calculate_pi_inv(
                    pi_inv_r2,
                    P_i_j[i][j],
                    Q_i_j[i][j],
                    r_i_j_3[i][j]);

            if (utils::solve_equation(
                    result,
                    public_key->G,
                    r_i_j_1[i][j] + pi_inv_r2 + commitments_i_j[i][j]) != 0) {
                std::cout << "No Solutions" << std::endl;
                return 1;
            }

            NTL::VectorCopy(b, result, K);

            b_i = utils::gf2_from_gf2e(b);

            for (int q = 0; q < MI; q++) {
                b_i_j_s[i][j].append(b_i[q + PI]);
            }
        }
    }

    NTL::Vec<NTL::vec_GF2> r_b;
    r_b.SetLength(I);
    for (int i = 0; i < I; i++) {
        r_b[i].SetLength(MI);
        for (int j = 0; j < J; j++) {
            r_b[i] += (R[j] * b_i_j_s[i][j]);
        }
        if (b_i_s[i] != r_b[i]) {
            std::cout << "Error: verify_0" << std::endl;
            return 1;
        }
    }

    return 0;

}


int rank::multiplicative_relations::verify_2(
        const NTL::Vec<NTL::vec_GF2E> &r_i_2,
        const NTL::Vec<NTL::vec_GF2E> &r_i_3,
        const NTL::Vec<NTL::vec_GF2> &s_i_1,
        const NTL::Vec<NTL::vec_GF2> &s_i_2,
        const NTL::Vec<NTL::vec_GF2E> &c_i_1,
        const NTL::Vec<NTL::vec_GF2E> &c_i_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &r_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &r_i_j_3,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &s_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &s_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &c_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &c_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2E>> &e_i_j,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &m_prime_i_j,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {

        auto _r_i_2 = utils::encode_2(r_i_2[i], MI);
        if (rank::rank_commitment::verify_proof(
                c_i_1[i],
                s_i_1[i],
                _r_i_2,
                public_key->G)) {
            std::cout << "Verification 1 for ch = 2 failed" << std::endl;
            return 1;
        }

        auto _r_i_3 = utils::encode_2(r_i_3[i], MI);
        if (rank::rank_commitment::verify_proof(
                c_i_2[i],
                s_i_2[i],
                _r_i_3,
                public_key->G)) {
            std::cout << "Verification 2 for ch = 2 failed" << std::endl;
            return 1;
        }

        auto r_i_2_xor_r_i_3 = r_i_2[i] + r_i_3[i];
        auto M = utils::mat_gf2_from_vec_gf2e(r_i_2_xor_r_i_3);

        if (NTL::gauss(M) != RHO) {
            std::cout << "Matrix weight not equal to RHO" << std::endl;
            return 1;
        }

        for (int j = 0; j < J; j++) {
            auto _r_i_j_2 = utils::encode_2(r_i_j_2[i][j], MI);
            if (rank_commitment::verify_proof(
                    c_i_j_1[i][j],
                    s_i_j_1[i][j],
                    _r_i_j_2,
                    public_key->G)) {
                std::cout << "Verification 3 for ch = 2 failed" << std::endl;
                return 1;
            }

            auto _r_i_j_3 = utils::encode_2(r_i_j_3[i][j], MI);
            if (rank_commitment::verify_proof(
                    c_i_j_2[i][j],
                    s_i_j_2[i][j],
                    _r_i_j_3,
                    public_key->G)) {
                std::cout << "Verification 4 for ch = 2 failed" << std::endl;
                return 1;
            }

            auto t_i_j_1_xor_t_i_j_2 = r_i_j_2[i][j] + r_i_j_3[i][j];
            M = utils::mat_gf2_from_vec_gf2e(t_i_j_1_xor_t_i_j_2);

            if (NTL::gauss(M) != RHO) {
                std::cout << "Matrix weight not equal to RHO" << std::endl;
                return 1;
            }

            M = utils::mat_gf2_from_vec_gf2e(e_i_j[i][j]);
            if (NTL::gauss(M) != RHO) {
                std::cout << "Matrix weight not equal to RHO" << std::endl;
                return 1;
            }
        }
    }

    for (int j = 0; j < J; j++) {
        for (int z = 0; z < m_prime_i_j[0][j].length(); z++) {
            if (m_prime_i_j[0][j][z] * m_prime_i_j[1][j][z] != m_prime_i_j[2][j][z]) {
                std::cout << "Error: Wrong relations" << std::endl;
                return 1;
            }
        }

    }


    return 0;
}