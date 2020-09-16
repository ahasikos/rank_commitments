#include "multiplicative_relations.h"
#include <hamming/jain_commitment/jain_commitment.h>
#include <NTL/mat_GF2.h>
#include <NTL/vec_GF2.h>
#include <hamming/knowledge_of_valid_opening/knowledge_of_valid_opening.h>
#include <utils/utils.h>

void hamming_metric::multiplicative_relations::initialize_commitments_and_responses(
        commitments_t *commitments,
        responses_t *responses) {

    responses->t_i_0.SetLength(I);
    responses->t_i_1.SetLength(I);
    responses->t_i_2.SetLength(I);
    responses->t_i_j_0.SetLength(I);
    responses->t_i_j_1.SetLength(I);
    responses->t_i_j_2.SetLength(I);

    commitments->c_i_0.SetLength(I);
    commitments->c_i_1.SetLength(I);
    commitments->c_i_2.SetLength(I);
    commitments->c_i_j_0.SetLength(I);
    commitments->c_i_j_1.SetLength(I);
    commitments->c_i_j_2.SetLength(I);

    commitments->r_i_0.SetLength(I);
    commitments->r_i_1.SetLength(I);
    commitments->r_i_2.SetLength(I);
    commitments->r_i_j_0.SetLength(I);
    commitments->r_i_j_1.SetLength(I);
    commitments->r_i_j_2.SetLength(I);

    for (int i = 0; i < I; i++) {
        responses->t_i_j_0[i].SetLength(J);
        responses->t_i_j_1[i].SetLength(J);
        responses->t_i_j_2[i].SetLength(J);

        commitments->c_i_j_0[i].SetLength(J);
        commitments->c_i_j_1[i].SetLength(J);
        commitments->c_i_j_2[i].SetLength(J);

        commitments->r_i_j_0[i].SetLength(J);
        commitments->r_i_j_1[i].SetLength(J);
        commitments->r_i_j_2[i].SetLength(J);
    }
}

void hamming_metric::multiplicative_relations::generate_private_key(
        private_key_t *private_key) {

    //Generate m
    {
        private_key->m.kill();
        private_key->m.SetLength(I);

        utils::generate_random_binary_vector(
                private_key->m[0],
                JAIN_V);

        utils::generate_random_binary_vector(
                private_key->m[1],
                JAIN_V);

        private_key->m[2].SetLength(JAIN_V);
        for (int i = 0; i < JAIN_V; i++) {
            private_key->m[2][i] = private_key->m[0][i] * private_key->m[1][i];
        }
    }

    //Generate e
    {
        private_key->e.kill();
        private_key->e.SetLength(I);

        for (int i = 0; i < I; i++) {
            utils::generate_vector_of_weight_w(
                    private_key->e[i],
                    JAIN_K,
                    W);
        }
    }
}

void hamming_metric::multiplicative_relations::generate_public_key(
        public_key_t *public_key,
        const private_key_t *private_key) {

    public_key->commitments_i.kill();
    public_key->commitments_i.SetLength(I);

    utils::generate_random_binary_matrix(
            public_key->A,
            JAIN_K,
            JAIN_L + JAIN_V);


    for (int i = 0; i < I; i++) {
        NTL::vec_GF2 r;
        utils::generate_random_binary_vector(
                r,
                JAIN_L);

        hamming_metric::commitment::generate_commitment(
                public_key->commitments_i[i],
                public_key->A,
                r,
                private_key->m[i],
                private_key->e[i]);
    }
}

void hamming_metric::multiplicative_relations::generate_random_values(
        random_values_t *random_values,
        const multiplicative_relation_matrices_t *matrices) {

    //Generate u_i_j
    {
        random_values->u_i_j.kill();
        random_values->u_i_j.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->u_i_j[i].SetLength(J);
            for (int j = 0; j < J; j++) {
                random_values->u_i_j[i][j] = NTL::random_vec_GF2(JAIN_L);
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
                random_values->f_i_j[i][j] = NTL::random_vec_GF2(JAIN_K);
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
                random_values->v_i_j[i][j] = NTL::random_vec_GF2(JAIN_V);
            }
        }
    }

    {
        random_values->u_i.kill();
        random_values->u_i.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->u_i[i] = NTL::random_vec_GF2(JAIN_L);
        }
    }

    {
        random_values->f_i.kill();
        random_values->f_i.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->f_i[i] = NTL::random_vec_GF2(JAIN_K);
        }
    }

    //Generate v_i
    {
        random_values->v_i.kill();
        random_values->v_i.SetLength(I);
        for (int i = 0; i < I; i++) {
            random_values->v_i[i].SetLength(JAIN_V);
            for (int j = 0; j < J; j++) {
                random_values->v_i[i] += (matrices->R[j] * random_values->v_i_j[i][j]);
            }
        }
    }
}

void hamming_metric::multiplicative_relations::generate_revealed_values(
        revealed_values_t *revealed_values,
        const private_key_t *private_key,
        const public_key_t *public_key) {

    revealed_values->commitments_i_j.kill();
    revealed_values->commitments_i_j.SetLength(I);

    revealed_values->e_i_j.kill();
    revealed_values->e_i_j.SetLength(I);

    revealed_values->P_i.SetLength(I);
    revealed_values->P_i_j.SetLength(I);

    NTL::Vec<NTL::vec_GF2> m_prime_i;
    {
        m_prime_i.SetLength(I);
        utils::sample_messages(m_prime_i[0], m_prime_i[1], m_prime_i[2], JAIN_V);
        utils::generate_relation_matrix(
                revealed_values->matrices._R,
                revealed_values->matrices.R,
                m_prime_i,
                private_key->m,
                JAIN_V);
    }


    {
        generate_m_prime_i_j_from_m_prime_i(
                revealed_values->m_prime_i_j,
                m_prime_i);
    }

    NTL::vec_GF2 r;
    for (int i = 0; i < I; i++) {
        revealed_values->commitments_i_j[i].SetLength(J);
        revealed_values->e_i_j[i].SetLength(J);
        revealed_values->P_i_j[i].SetLength(J);

        utils::create_permutation_matrix(
                revealed_values->P_i[i],
                JAIN_K);

        for (int j = 0; j < J; j++) {
            utils::create_permutation_matrix(
                    revealed_values->P_i_j[i][j],
                    JAIN_K);

            utils::generate_random_binary_vector(
                    r,
                    JAIN_L);

            utils::generate_vector_of_weight_w(
                    revealed_values->e_i_j[i][j],
                    JAIN_K,
                    W);

            hamming_metric::commitment::generate_commitment(
                    revealed_values->commitments_i_j[i][j],
                    public_key->A,
                    r,
                    revealed_values->m_prime_i_j[i][j],
                    revealed_values->e_i_j[i][j]);
        }
    }
}

void hamming_metric::multiplicative_relations::generate_m_prime_i_j_from_m_prime_i(
        NTL::Vec<NTL::Vec<NTL::vec_GF2>> &m_prime_i_j,
        const NTL::Vec<NTL::vec_GF2> &m_prime_i) {

    m_prime_i_j.kill();
    m_prime_i_j.SetLength(I);
    int start_index;

    for (int i = 0; i < I; i++) {
        m_prime_i_j[i].SetLength(J);
        start_index = 0;
        for (int j = 0; j < J; j++) {
            NTL::vec_GF2 tmp;
            tmp.SetLength(JAIN_V);
            for (int z = 0; z < JAIN_V; z++) {
                tmp[z] = m_prime_i[i][start_index + z];
            }
            start_index += JAIN_V;
            m_prime_i_j[i][j].append(tmp);
        }
    }

}

void hamming_metric::multiplicative_relations::generate_commitments_and_responses(
        responses_t *responses,
        commitments_t *commitments,
        const random_values_t *random_values,
        const revealed_values_t *revealed_values,
        const public_key_t *public_key,
        const private_key_t *private_key) {

    for (int i = 0; i < I; i++) {

        auto u_v = random_values->u_i[i];
        u_v.append(random_values->v_i[i]);
        knowledge_of_valid_opening::generate_commitment_and_response_0(
                commitments->c_i_0[i],
                commitments->r_i_0[i],
                responses->t_i_0[i],
                u_v,
                public_key->A,
                random_values->f_i[i]);

        knowledge_of_valid_opening::generate_commitment_and_response_1(
                commitments->c_i_1[i],
                commitments->r_i_1[i],
                responses->t_i_1[i],
                public_key->A,
                revealed_values->P_i[i],
                random_values->f_i[i]);

        knowledge_of_valid_opening::generate_commitment_and_response_2(
                commitments->c_i_2[i],
                commitments->r_i_2[i],
                responses->t_i_2[i],
                public_key->A,
                revealed_values->P_i[i],
                random_values->f_i[i],
                private_key->e[i]);

        for (int j = 0; j < J; j++) {

            u_v = random_values->u_i_j[i][j];
            u_v.append(random_values->v_i_j[i][j]);
            knowledge_of_valid_opening::generate_commitment_and_response_0(
                    commitments->c_i_j_0[i][j],
                    commitments->r_i_j_0[i][j],
                    responses->t_i_j_0[i][j],
                    u_v,
                    public_key->A,
                    random_values->f_i_j[i][j]);

            knowledge_of_valid_opening::generate_commitment_and_response_1(
                    commitments->c_i_j_1[i][j],
                    commitments->r_i_j_1[i][j],
                    responses->t_i_j_1[i][j],
                    public_key->A,
                    revealed_values->P_i_j[i][j],
                    random_values->f_i_j[i][j]);

            knowledge_of_valid_opening::generate_commitment_and_response_2(
                    commitments->c_i_j_2[i][j],
                    commitments->r_i_j_2[i][j],
                    responses->t_i_j_2[i][j],
                    public_key->A,
                    revealed_values->P_i_j[i][j],
                    random_values->f_i_j[i][j],
                    revealed_values->e_i_j[i][j]);
        }
    }
}

int hamming_metric::multiplicative_relations::verify_0(
        const NTL::Vec<NTL::vec_GF2> &c_i_0,
        const NTL::Vec<NTL::vec_GF2> &r_i_0,
        const NTL::Vec<NTL::vec_GF2> &t_i_0,
        const NTL::Vec<NTL::vec_GF2> &c_i_1,
        const NTL::Vec<NTL::vec_GF2> &r_i_1,
        const NTL::Vec<NTL::vec_GF2> &t_i_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_1,
        const NTL::Vec<NTL::mat_GF2> &P_i,
        const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &P_i_j,
        const NTL::Vec<NTL::mat_GF2> &R,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _t0 = utils::encode_binary_vector(t_i_0[i], JAIN_V);
        auto _t1 = utils::encode_binary_vector(t_i_1[i], JAIN_V);

        if (hamming_metric::commitment::verify(
                c_i_0[i],
                public_key->A,
                r_i_0[i],
                _t0) != 0) {
            std::cout << "Multiplicative Relations. Verification failed on ch = 0 and c0" << std::endl;
            return 1;
        }

        if (hamming_metric::commitment::verify(
                c_i_1[i],
                public_key->A,
                r_i_1[i],
                _t1) != 0) {
            std::cout << "Multiplicative Relations. Verification failed on ch = 0 and c1" << std::endl;
            return 1;
        }
        for (int j = 0; j < J; j++) {
            _t0 = utils::encode_binary_vector(t_i_j_0[i][j], JAIN_V);
            _t1 = utils::encode_binary_vector(t_i_j_1[i][j], JAIN_V);

            if (hamming_metric::commitment::verify(
                    c_i_j_0[i][j],
                    public_key->A,
                    r_i_j_0[i][j],
                    _t0) != 0) {
                std::cout << "Multiplicative Relations. Verification failed on ch = 0 and c0" << std::endl;
                return 1;
            }

            if (hamming_metric::commitment::verify(
                    c_i_j_1[i][j],
                    public_key->A,
                    r_i_j_1[i][j],
                    _t1) != 0) {
                std::cout << "Multiplicative Relations. Verification failed on ch = 0 and c1" << std::endl;
                return 1;
            }
        }
    }

    NTL::Vec<NTL::vec_GF2> results_i;
    NTL::Vec<NTL::Vec<NTL::vec_GF2>> results_i_j;
    results_i_j.SetLength(I);
    for (int i = 0; i < I; i++) {
        NTL::vec_GF2 result;

        if (utils::solve_equation(
                result,
                public_key->A,
                t_i_0[i] + (NTL::inv(P_i[i]) * t_i_1[i])) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }
        results_i.append(result);

        for (int j = 0; j < J; j++) {
            if (utils::solve_equation(
                    result,
                    public_key->A,
                    t_i_j_0[i][j] + (NTL::inv(P_i_j[i][j]) * t_i_j_1[i][j])) != 0) {
                std::cout << "No Solutions" << std::endl;
                return 1;
            }
            results_i_j[i].append(result);
        }
    }

    NTL::Vec<NTL::vec_GF2> b_i;
    b_i.SetLength(I);
    for (int i = 0; i < I; i++) {
        b_i[i].SetLength(JAIN_V);
        for (int j = 0; j < JAIN_V; j++) {
            b_i[i][j] = results_i[i][j + JAIN_L];
        }
    }

    NTL::Vec<NTL::Vec<NTL::vec_GF2>> b_i_j;
    b_i_j.SetLength(I);
    for (int i = 0; i < I; i++) {
        b_i_j[i].SetLength(J);
        for (int j = 0; j < J; j++) {
            b_i_j[i][j].SetLength(JAIN_V);
            for (int z = 0; z < JAIN_V; z++) {
                b_i_j[i][j][z] = results_i_j[i][j][z + JAIN_L];
            }
        }
    }

    NTL::Vec<NTL::vec_GF2> r_b;
    r_b.SetLength(I);
    for (int i = 0; i < I; i++) {
        for (int j = 0; j < J; j++) {
            r_b[i].SetLength(JAIN_V);
            r_b[i] += (R[j] * b_i_j[i][j]);
        }
        if (b_i[i] != r_b[i]) {
            std::cout << "Error: verify_0" << std::endl;
            return 1;
        }
    }

    return 0;
}

int hamming_metric::multiplicative_relations::verify_1(
        const NTL::Vec<NTL::vec_GF2> &c_i_0,
        const NTL::Vec<NTL::vec_GF2> &r_i_0,
        const NTL::Vec<NTL::vec_GF2> &t_i_0,
        const NTL::Vec<NTL::vec_GF2> &c_i_2,
        const NTL::Vec<NTL::vec_GF2> &r_i_2,
        const NTL::Vec<NTL::vec_GF2> &t_i_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_0,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_2,
        const NTL::Vec<NTL::mat_GF2> &P_i,
        const NTL::Vec<NTL::Vec<NTL::mat_GF2>> &P_i_j,
        const NTL::Vec<NTL::mat_GF2> &R,
        const NTL::mat_GF2 &_R,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &commitments_i_j,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _t0 = utils::encode_binary_vector(t_i_0[i], JAIN_V);
        auto _t2 = utils::encode_binary_vector(t_i_2[i], JAIN_V);

        if (hamming_metric::commitment::verify(
                c_i_0[i],
                public_key->A,
                r_i_0[i],
                _t0) != 0) {
            std::cout << "Multiplicative Relations. Verification failed on ch = 1 and c0" << std::endl;
            return 1;
        }

        if (hamming_metric::commitment::verify(
                c_i_2[i],
                public_key->A,
                r_i_2[i],
                _t2) != 0) {
            std::cout << "Multiplicative Relations. Verification failed on ch = 1 and c2" << std::endl;
            return 1;
        }
        for (int j = 0; j < J; j++) {
            _t0 = utils::encode_binary_vector(t_i_j_0[i][j], JAIN_V);
            _t2 = utils::encode_binary_vector(t_i_j_2[i][j], JAIN_V);

            if (hamming_metric::commitment::verify(
                    c_i_j_0[i][j],
                    public_key->A,
                    r_i_j_0[i][j],
                    _t0) != 0) {
                std::cout << "Multiplicative Relations. Verification failed on ch = 1 and c0" << std::endl;
                return 1;
            }

            if (hamming_metric::commitment::verify(
                    c_i_j_2[i][j],
                    public_key->A,
                    r_i_j_2[i][j],
                    _t2) != 0) {
                std::cout << "Multiplicative Relations. Verification failed on ch = 1 and c2" << std::endl;
                return 1;
            }
        }
    }

    // Check rank of matrix
    auto m = _R;
    if (NTL::gauss(m) != m.NumRows()) {
        std::cout << "Not full rank matrix" << std::endl;
        return 1;
    }

    // Ensure that each row has weight one
    for (int i = 0; i < m.NumRows(); i++) {
        if (NTL::weight(m[i]) != 1) {
            std::cout << "Invalid weight" << std::endl;
            return 1;
        }
    }


    NTL::Vec<NTL::vec_GF2> results_i;
    NTL::Vec<NTL::Vec<NTL::vec_GF2>> results_i_j;
    results_i_j.SetLength(I);
    for (int i = 0; i < I; i++) {
        NTL::vec_GF2 result;

        if (utils::solve_equation(
                result,
                public_key->A,
                public_key->commitments_i[i] + t_i_0[i] + (NTL::inv(P_i[i]) * t_i_2[i])) != 0) {
            std::cout << "No Solutions 1" << std::endl;
            return 1;
        }
        results_i.append(result);

        for (int j = 0; j < J; j++) {
            if (utils::solve_equation(
                    result,
                    public_key->A,
                    commitments_i_j[i][j] + t_i_j_0[i][j] +
                    (NTL::inv(P_i_j[i][j]) * t_i_j_2[i][j])) != 0) {
                std::cout << "No Solutions 2" << std::endl;
                return 1;
            }
            results_i_j[i].append(result);
        }
    }

    NTL::Vec<NTL::vec_GF2> b_i;
    b_i.SetLength(I);
    for (int i = 0; i < I; i++) {
        b_i[i].SetLength(JAIN_V);
        for (int j = 0; j < JAIN_V; j++) {
            b_i[i][j] = results_i[i][j + JAIN_L];
        }
    }

    NTL::Vec<NTL::Vec<NTL::vec_GF2>> b_i_j;
    b_i_j.SetLength(I);
    for (int i = 0; i < I; i++) {
        b_i_j[i].SetLength(J);
        for (int j = 0; j < J; j++) {
            b_i_j[i][j].SetLength(JAIN_V);
            for (int z = 0; z < JAIN_V; z++) {
                b_i_j[i][j][z] = results_i_j[i][j][z + JAIN_L];
            }
        }
    }

    NTL::Vec<NTL::vec_GF2> r_b;
    r_b.SetLength(I);
    for (int i = 0; i < I; i++) {
        for (int j = 0; j < J; j++) {
            r_b[i].SetLength(JAIN_V);
            r_b[i] += (R[j] * b_i_j[i][j]);
        }
        if (b_i[i] != r_b[i]) {
            std::cout << "Error: verify_0" << std::endl;
            return 1;
        }
    }

    return 0;
}

int hamming_metric::multiplicative_relations::verify_2(
        const NTL::Vec<NTL::vec_GF2> &c_i_1,
        const NTL::Vec<NTL::vec_GF2> &r_i_1,
        const NTL::Vec<NTL::vec_GF2> &t_i_1,
        const NTL::Vec<NTL::vec_GF2> &c_i_2,
        const NTL::Vec<NTL::vec_GF2> &r_i_2,
        const NTL::Vec<NTL::vec_GF2> &t_i_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_1,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &c_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &r_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &t_i_j_2,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &e_i_j,
        const NTL::Vec<NTL::Vec<NTL::vec_GF2>> &m_prime_i_j,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _t1 = utils::encode_binary_vector(t_i_1[i], JAIN_V);
        auto _t2 = utils::encode_binary_vector(t_i_2[i], JAIN_V);

        if (hamming_metric::commitment::verify(
                c_i_1[i],
                public_key->A,
                r_i_1[i],
                _t1) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 2 and c1" << std::endl;
            return 1;
        }

        if (hamming_metric::commitment::verify(
                c_i_2[i],
                public_key->A,
                r_i_2[i],
                _t2) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 2 and c2" << std::endl;
            return 1;
        }
        for (int j = 0; j < J; j++) {
            _t1 = utils::encode_binary_vector(t_i_j_1[i][j], JAIN_V);
            _t2 = utils::encode_binary_vector(t_i_j_2[i][j], JAIN_V);

            if (hamming_metric::commitment::verify(
                    c_i_j_1[i][j],
                    public_key->A,
                    r_i_j_1[i][j],
                    _t1) != 0) {
                std::cout << "Linear Relations. Verification failed on ch = 2 and c1" << std::endl;
                return 1;
            }

            if (hamming_metric::commitment::verify(
                    c_i_j_2[i][j],
                    public_key->A,
                    r_i_j_2[i][j],
                    _t2) != 0) {
                std::cout << "Linear Relations. Verification failed on ch = 2 and c2" << std::endl;
                return 1;
            }

            if (NTL::weight(e_i_j[i][j]) != W) {
                std::cout << "Error: Wrong weight" << std::endl;
                return 1;
            }

        }
    }

    for (int j = 0; j < J; j++) {
        for (int z = 0; z < m_prime_i_j[0][j].length(); z++) {
            if (m_prime_i_j[0][j][z] * m_prime_i_j[1][j][z] !=
                m_prime_i_j[2][j][z]) {
                std::cout << "Error: Wrong relations" << std::endl;
                return 1;
            }
        }

    }

    return 0;
}
