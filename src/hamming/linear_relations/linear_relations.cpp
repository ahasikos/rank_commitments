#include "linear_relations.h"
#include <vector>
#include <hamming/knowledge_of_valid_opening/knowledge_of_valid_opening.h>
#include <NTL/GF2X.h>
#include <utils/utils.h>

void hamming_metric::linear_relations::initialize_commitments_and_responses(
        commitments_t *commitments,
        responses_t *responses) {

    for (int i = 0; i < I; i++) {
        responses->t0.append(NTL::vec_GF2());
        responses->t1.append(NTL::vec_GF2());
        responses->t2.append(NTL::vec_GF2());
        commitments->r0.append(NTL::vec_GF2());
        commitments->r1.append(NTL::vec_GF2());
        commitments->r2.append(NTL::vec_GF2());
        commitments->c0.append(NTL::vec_GF2());
        commitments->c1.append(NTL::vec_GF2());
        commitments->c2.append(NTL::vec_GF2());
    }
}

void hamming_metric::linear_relations::generate_private_key(
        private_key_t *private_key,
        const linear_relation_matrices_t *matrices) {

    {
        private_key->m.kill();
        private_key->m.SetLength(I);

        private_key->m[0] = NTL::random_vec_GF2(JAIN_V);
        private_key->m[1] = NTL::random_vec_GF2(JAIN_V);
        private_key->m[2] = (matrices->x_0 * private_key->m[0]) + (matrices->x_1 * private_key->m[1]);
    }

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

void hamming_metric::linear_relations::generate_random_values(
        random_values_t *random_values,
        const linear_relation_matrices_t *matrices) {

    {
        random_values->u.kill();
        random_values->u.SetLength(I);
        random_values->v.kill();
        random_values->v.SetLength(I);
        random_values->u_v.kill();
        random_values->u_v.SetLength(I);
        random_values->f.kill();
        random_values->f.SetLength(I);
    }
    for (int i = 0; i < I; i++) {
        utils::generate_random_binary_vector(
                random_values->u[i],
                JAIN_L);
        utils::generate_random_binary_vector(
                random_values->f[i],
                JAIN_K);
    }

    for (int i = 0; i < I - 1; i++) {
        utils::generate_random_binary_vector(
                random_values->v[i],
                JAIN_V);
    }

    random_values->v[2] = (matrices->x_0 * random_values->v[0]) + (matrices->x_1 * random_values->v[1]);

    random_values->u_v = random_values->u;
    for (int i = 0; i < I; i++) {
        NTL::append(random_values->u_v[i], random_values->v[i]);
    }
}

void hamming_metric::linear_relations::generate_public_key(
        public_key_t *public_key,
        const private_key_t *private_key) {

    public_key->commitments.kill();
    public_key->commitments.SetLength(I);

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
                public_key->commitments[i],
                public_key->A,
                r,
                private_key->m[i],
                private_key->e[i]);
    }
}

void hamming_metric::linear_relations::generate_revealed_values(
        revealed_values_t *revealed_values) {

    ::utils::generate_random_binary_matrix(
            revealed_values->matrices.x_0,
            JAIN_V,
            JAIN_V);
    ::utils::generate_random_binary_matrix(
            revealed_values->matrices.x_1,
            JAIN_V,
            JAIN_V);

    for(int i = 0; i < I; i++) {

        revealed_values->P.append(NTL::mat_GF2());

        utils::create_permutation_matrix(
                revealed_values->P[i],
                JAIN_K);
    }

}

void hamming_metric::linear_relations::generate_commitments_and_responses(
        responses_t *responses,
        commitments_t *commitments,
        const random_values_t *random_values,
        const revealed_values_t *revealed_values,
        const public_key_t *public_key,
        const private_key_t *private_key) {

    for (int i = 0; i < I; i++) {
        hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_0(
                commitments->c0[i],
                commitments->r0[i],
                responses->t0[i],
                random_values->u_v[i],
                public_key->A,
                random_values->f[i]);

        hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_1(
                commitments->c1[i],
                commitments->r1[i],
                responses->t1[i],
                public_key->A,
                revealed_values->P[i],
                random_values->f[i]);

        hamming_metric::knowledge_of_valid_opening::generate_commitment_and_response_2(
                commitments->c2[i],
                commitments->r2[i],
                responses->t2[i],
                public_key->A,
                revealed_values->P[i],
                random_values->f[i],
                private_key->e[i]);
    }
}

int hamming_metric::linear_relations::verify_0(
        const NTL::Vec<NTL::vec_GF2> &c0,
        const NTL::Vec<NTL::vec_GF2> &r0,
        const NTL::Vec<NTL::vec_GF2> &t0,
        const NTL::Vec<NTL::vec_GF2> &c1,
        const NTL::Vec<NTL::vec_GF2> &r1,
        const NTL::Vec<NTL::vec_GF2> &t1,
        const NTL::Vec<NTL::mat_GF2> &P,
        const NTL::mat_GF2 &x_0,
        const NTL::mat_GF2 &x_1,
        const public_key_t *public_key) {

    for(int i = 0; i < I; i++) {
        auto _t0 = utils::encode_binary_vector(t0[i], JAIN_V);
        auto _t1 = utils::encode_binary_vector(t1[i], JAIN_V);

        if (hamming_metric::commitment::verify(
                c0[i],
                public_key->A,
                r0[i],
                _t0) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 0 and c0" << std::endl;
            return 1;
        }

        if (hamming_metric::commitment::verify(
                c1[i],
                public_key->A,
                r1[i],
                _t1) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 0 and c1" << std::endl;
            return 1;
        }
    }

    NTL::Vec<NTL::vec_GF2> results;
    for (int i = 0; i < I; i++) {
        NTL::vec_GF2 result;

        if (utils::solve_equation(
                result,
                public_key->A,
                t0[i] + (NTL::inv(P[i]) * t1[i])) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }
        results.append(result);
    }

    NTL::Vec<NTL::vec_GF2> b;
    for (int i = 0; i < I; i++) {
        {
            b.append(NTL::vec_GF2());
            b[i].SetLength(JAIN_V);
        }

        for (int j = 0; j < JAIN_V; j++) {
            b[i][j] = results[i].at(j + JAIN_L);
        }
    }

    if (NTL::IsZero(b[2] + ((x_0 * b[0]) + (x_1 * b[1])))) {
        return 0;
    } else {
        std::cout << b[2] << std::endl;
        std::cout << ((b[0] * x_0) + (b[1] * x_1)) << std::endl;
        return 1;
    }

}

int hamming_metric::linear_relations::verify_1(
        const NTL::Vec<NTL::vec_GF2> &c0,
        const NTL::Vec<NTL::vec_GF2> &r0,
        const NTL::Vec<NTL::vec_GF2> &t0,
        const NTL::Vec<NTL::vec_GF2> &c2,
        const NTL::Vec<NTL::vec_GF2> &r2,
        const NTL::Vec<NTL::vec_GF2> &t2,
        const NTL::Vec<NTL::mat_GF2> &P,
        const NTL::mat_GF2 &x_0,
        const NTL::mat_GF2 &x_1,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _t0 = utils::encode_binary_vector(t0[i], JAIN_V);
        auto _t2 = utils::encode_binary_vector(t2[i], JAIN_V);

        if (hamming_metric::commitment::verify(
                c0[i],
                public_key->A,
                r0[i],
                _t0) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 1 and c0" << std::endl;
            return 1;
        }

        if (hamming_metric::commitment::verify(
                c2[i],
                public_key->A,
                r2[i],
                _t2) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 1 and c2" << std::endl;
            return 1;
        }
    }

    NTL::Vec<NTL::vec_GF2> results;
    for (int i = 0; i < 3; i++) {
        NTL::vec_GF2 result;

        if (utils::solve_equation(
                result,
                public_key->A,
                t0[i] + (NTL::inv(P[i]) * t2[i]) + public_key->commitments[i]) != 0) {
            std::cout << "No Solutions" << std::endl;
            return 1;
        }
        results.append(result);
    }

    NTL::Vec<NTL::vec_GF2> d;
    for (int i = 0; i < 3; i++) {
        {
            d.append(NTL::vec_GF2());
            d[i].SetLength(JAIN_V);
        }

        for (int j = 0; j < JAIN_V; j++) {
            d[i][j] = results[i].at(j + JAIN_L);
        }
    }

    if (NTL::IsZero(d[2] + ((x_0 * d[0]) + (x_1 * d[1])))) {
        return 0;
    } else {
        std::cout << d[2] << std::endl;
        std::cout << ((d[2] + ((x_0 * d[0]) + (x_1 * d[1])))) << std::endl;
        return 1;
    }
}

int hamming_metric::linear_relations::verify_2(
        const NTL::Vec<NTL::vec_GF2> &c1,
        const NTL::Vec<NTL::vec_GF2> &r1,
        const NTL::Vec<NTL::vec_GF2> &t1,
        const NTL::Vec<NTL::vec_GF2> &c2,
        const NTL::Vec<NTL::vec_GF2> &r2,
        const NTL::Vec<NTL::vec_GF2> &t2,
        const public_key_t *public_key) {

    for (int i = 0; i < I; i++) {
        auto _t1 = utils::encode_binary_vector(t1[i], JAIN_V);
        auto _t2 = utils::encode_binary_vector(t2[i], JAIN_V);

        if (hamming_metric::commitment::verify(
                c1[i],
                public_key->A,
                r1[i],
                _t1) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 2 and c1" << std::endl;
            return 1;
        }

        if (hamming_metric::commitment::verify(
                c2[i],
                public_key->A,
                r2[i],
                _t2) != 0) {
            std::cout << "Linear Relations. Verification failed on ch = 2 and c2" << std::endl;
            return 1;
        }

        if(NTL::weight(t1[i] + t2[i]) != W) {
            std::cout << "Invalid weight" << std::endl;
            return 1;
        }

    }

    return 0;
}