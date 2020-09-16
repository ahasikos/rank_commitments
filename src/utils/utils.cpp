#include "utils.h"
#include <NTL/GF2X.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <vector>
#include <rank/rank_params.h>
#include <random>

static int is_element_in_vector(const NTL::GF2E &element, const NTL::vec_GF2E &vector) {
    for (int i = 0; i < vector.length(); i++) {
        if (element == vector[i]) {
            return 1;
        }
    }
    return 0;
}

static void gf2_from_gf2e_element(NTL::vec_GF2 &res, const NTL::GF2E &v) {


    if (NTL::IsZero(v)) {
        for (int i = 0; i < v.degree(); i++) {
            res.append(NTL::GF2(0));
            return;
        }
    }

    for (int i = 0; i < v.degree(); i++) {
        res.append(v._GF2E__rep[i]);
    }
}

NTL::GF2X utils::gf2x_from_gf2(const NTL::Vec<NTL::GF2> &in) {

    NTL::GF2X v;
    v.SetLength(in.length());

    for (int i = 0; i < in.length(); i++) {
        NTL::SetCoeff(v, i, in[i]);
    }

    return v;
}

NTL::Vec<NTL::GF2> utils::gf2_from_gf2x(const NTL::GF2X &in, int len) {
    NTL::Vec<NTL::GF2> v;
    NTL::VectorCopy(v, in, len);

    return v;
}

NTL::GF2X utils::gf2x_from_matgf2(const NTL::mat_GF2 &in) {
    NTL::GF2X v;
    v.SetLength(in.NumRows() * in.NumCols());

    for (int i = 0; i < in.NumRows(); i++) {
        for (int j = 0; j < in.NumCols(); j++) {
            v[(i * in.NumCols()) + j] = in[i][j];
        }
    }
    return v;
}

NTL::GF2X utils::gf2x_from_gf2e(const NTL::vec_GF2E &in) {
    NTL::GF2X v;
    v.SetLength(in.length() * in[0].degree());

    for (int i = 0; i < in.length(); i++) {
        for (int j = 0; j < in[i].degree(); j++) {
            NTL::SetCoeff(v, (i * in[i].degree()) + j, in[i]._GF2E__rep[j]);
        }
    }

    return v;
}

NTL::vec_GF2 utils::gf2_from_gf2e(const NTL::vec_GF2E &in) {
    NTL::vec_GF2 v;
    v.SetLength(in.length() * in[0].degree());

    for (int i = 0; i < in.length(); i++) {
        for (int j = 0; j < in[i].degree(); j++) {
            v[(i * in[i].degree()) + j] = in[i]._GF2E__rep[j];
        }
    }

    return v;
}

NTL::vec_GF2E utils::gf2e_from_gf2x(const NTL::GF2X &in, int length) {
    NTL::vec_GF2E v;
    auto v_size = std::ceil((float) length / (float) v[0].degree());
    v.SetLength(v_size);

    for (int i = 0; i < v.length(); i++) {
        for (int j = 0; j < v[i].degree(); j++) {
            NTL::SetCoeff(v[i]._GF2E__rep, j, in[(i * v[i].degree()) + j]);
        }
    }
    return v;
}

NTL::vec_GF2 utils::encode(const NTL::mat_GF2 &P, const NTL::mat_GF2 &Q, const NTL::vec_GF2E &V,
                           int size) {

    uint digest_length = SHA512_DIGEST_LENGTH;

    const EVP_MD* algorithm = EVP_sha3_512();
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, nullptr);

    NTL::vec_GF2 out;
    std::vector<uint8_t> hash(digest_length);

    auto P_gf2x = gf2x_from_matgf2(P);
    std::vector<uint8_t> P_bytes(NTL::NumBytes(P_gf2x));
    NTL::BytesFromGF2X(P_bytes.data(), P_gf2x, P_bytes.size());
    EVP_DigestUpdate(context, P_bytes.data(), P_bytes.size());

    auto Q_gf2x = gf2x_from_matgf2(Q);
    std::vector<uint8_t> Q_bytes(NTL::NumBytes(Q_gf2x));
    NTL::BytesFromGF2X(Q_bytes.data(), Q_gf2x, Q_bytes.size());
    EVP_DigestUpdate(context, Q_bytes.data(), Q_bytes.size());

    auto V_gf2x = gf2x_from_gf2e(V);
    std::vector<uint8_t> V_bytes(NTL::NumBytes(V_gf2x));
    NTL::BytesFromGF2X(V_bytes.data(), V_gf2x, V_bytes.size());
    EVP_DigestUpdate(context, V_bytes.data(), V_bytes.size());

    EVP_DigestFinal_ex(context, hash.data(), &digest_length);

    auto hash_gf2x = NTL::GF2XFromBytes(hash.data(), hash.size());

    out = gf2_from_gf2x(hash_gf2x, size);

    EVP_MD_CTX_destroy(context);

    return out;
}

NTL::vec_GF2 utils::encode_2(const NTL::vec_GF2E &V, int size) {

    uint digest_length = SHA512_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_512();
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, nullptr);

    NTL::vec_GF2 out;
    std::vector<uint8_t> hash(digest_length);

    auto V_gf2x = gf2x_from_gf2e(V);
    std::vector<uint8_t> V_bytes(NTL::NumBytes(V_gf2x));
    NTL::BytesFromGF2X(V_bytes.data(), V_gf2x, V_bytes.size());
    EVP_DigestUpdate(context, V_bytes.data(), V_bytes.size());

    EVP_DigestFinal_ex(context, hash.data(), &digest_length);

    auto hash_gf2x = NTL::GF2XFromBytes(hash.data(), hash.size());

    out = gf2_from_gf2x(hash_gf2x, size);

    EVP_MD_CTX_destroy(context);

    return out;
}

NTL::vec_GF2E utils::gf2e_from_two_gf2(const NTL::vec_GF2 &first, const NTL::vec_GF2 &second) {
    NTL::vec_GF2E out;
    auto out_size = std::ceil((float) (first.length() + second.length()) / (float) out[0].degree());
    out.SetLength(out_size);

    NTL::vec_GF2 first_second = first;
    first_second.append(second);

    for (int i = 0; i < out.length(); i++) {
        for (int j = 0; j < out[i].degree(); j++) {
            NTL::SetCoeff(out[i]._GF2E__rep, j, first_second[(i * out[i].degree()) + j]);
        }
    }

    return out;
}

NTL::vec_GF2E utils::gf2e_from_vec_gf2(const NTL::vec_GF2 &in) {
    NTL::vec_GF2E out;
    auto out_size = std::ceil((float) in.length() / (float) out[0].degree());
    out.SetLength(out_size);

    for (int i = 0; i < out.length(); i++) {
        for (int j = 0; j < out[i].degree(); j++) {
            NTL::SetCoeff(out[i]._GF2E__rep, j, in[(i * out[i].degree()) + j]);
        }
    }

    return out;
}

NTL::Vec<NTL::GF2> utils::encode_binary_vector(const NTL::Vec<NTL::GF2> &in, int size) {

    uint digest_length = SHA512_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_512();
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, nullptr);

    auto in_to_gf2x = utils::gf2x_from_gf2(in);
    std::vector<uint8_t> in_to_bytes(NTL::NumBytes(in_to_gf2x));
    NTL::BytesFromGF2X(in_to_bytes.data(), in_to_gf2x, in_to_bytes.size());

    std::vector<uint8_t> hash(NTL::NumBytes(in_to_gf2x));

    EVP_DigestUpdate(context, in_to_bytes.data(), in_to_bytes.size());
    EVP_DigestFinal_ex(context, hash.data(), &digest_length);

    NTL::GF2X hash_to_gf2x;
    NTL::GF2XFromBytes(hash_to_gf2x, hash.data(), hash.size());

    auto hash_gf2 = utils::gf2_from_gf2x(hash_to_gf2x, size);

    EVP_MD_CTX_destroy(context);

    return hash_gf2;
}

void utils::sample_messages(
        NTL::vec_GF2 &m_1,
        NTL::vec_GF2 &m_2,
        NTL::vec_GF2 &m_3,
        int size) {

    NTL::vec_GF2 _m_1, _m_2, _m_3;
    {
        _m_1.SetLength(4);
        _m_2.SetLength(4);
        _m_3.SetLength(4);

        _m_1[2] = 1;
        _m_1[3] = 1;

        _m_2[1] = 1;
        _m_2[3] = 1;

        _m_3[3] = 1;
    }

    m_1.append(_m_1);
    m_2.append(_m_2);
    m_3.append(_m_3);

    for (int i = 0; i < size - 1; i++) {

        std::vector<uint> permutation;
        {
            permutation.resize(4);
        }

        create_random_permutation(
                permutation,
                4);

        NTL::mat_GF2 permutation_matrix;
        {
            permutation_matrix.SetDims(4, 4);
        }

        for (uint j = 0; j < permutation.size(); j++) {
            permutation_matrix[j][permutation[j]] = NTL::GF2(1);
        }

        m_1.append(permutation_matrix * _m_1);
        m_2.append(permutation_matrix * _m_2);
        m_3.append(permutation_matrix * _m_3);


    }
}

void utils::create_random_permutation(
        std::vector<uint> &permutation,
        int size) {

    permutation.resize(size);

    for (uint i = 0; i < permutation.size(); i++) {
        permutation[i] = i;
    }

    auto shuffled_vector = shuffle(
            permutation,
            permutation.size());

    permutation = shuffled_vector;

}

void utils::create_permutation_matrix(
        NTL::mat_GF2 &P,
        const std::vector<uint> &permutation) {

    for (uint i = 0; i < permutation.size(); i++) {
        P[i][permutation[i]] = NTL::GF2(1);
    }
}

void utils::create_permutation_matrix(
        NTL::mat_GF2 &P,
        int size) {

    P.kill();
    P.SetDims(size, size);

    std::vector<uint> permutation(size);

    create_random_permutation(
            permutation,
            size);

    for (uint i = 0; i < permutation.size(); i++) {
        P[i][permutation[i]] = NTL::GF2(1);
    }
}

NTL::mat_GF2 utils::mat_gf2_from_vec_gf2e(const NTL::vec_GF2E &v) {
    NTL::mat_GF2 M;
    M.SetDims(v.length(), v[0].degree());

    for (int j = 0; j < v.length(); j++) {
        for (int z = 0; z < v[0].degree(); z++) {
            if (NTL::IsZero(v[j]._GF2E__rep[z])) {
                M[j][z] = NTL::GF2(0);
            } else {
                M[j][z] = NTL::GF2(1);
            }
        }
    }
    return M;
}

void utils::generate_relation_matrix(
        NTL::mat_GF2 &_R,
        NTL::Vec<NTL::mat_GF2> &R,
        const NTL::Vec<NTL::vec_GF2> &m_tilde,
        const NTL::Vec<NTL::vec_GF2> &m,
        int size) {

    _R.SetDims(size, 4 * size);

    NTL::vec_GF2 tmp;
    tmp.SetLength(_R.NumCols());

    for (int i = 0; i < _R.NumRows(); i++) {
        for (int j = 0; j < _R.NumCols(); j++) {
            _R[i][j] = NTL::GF2(1);
        }
    }

    for (int i = 0; i < m[0].length(); i++) {
        for (int j = 0; j < m.length() - 1; j++) {
            for (int q = 0; q < m_tilde[j].length(); q++) {
                if (NTL::IsZero(m[j][i]) && (NTL::IsZero(m_tilde[j][q]))) {
                    tmp[q] = NTL::GF2(1);
                }
                if (NTL::IsZero(m[j][i]) && (!NTL::IsZero(m_tilde[j][q]))) {
                    tmp[q] = NTL::GF2(0);
                }
                if (!NTL::IsZero(m[j][i]) && (NTL::IsZero(m_tilde[j][q]))) {
                    tmp[q] = NTL::GF2(0);
                }
                if (!NTL::IsZero(m[j][i]) && (!NTL::IsZero(m_tilde[j][q]))) {
                    tmp[q] = NTL::GF2(1);
                }
            }
            for (int c = 0; c < tmp.length(); c++) {
                _R[i][c] *= tmp[c];
            }
        }
    }

    NTL::mat_GF2 R_tmp;
    R_tmp.SetDims(_R.NumRows(), _R.NumCols());

    std::vector<uint> v;
    v.resize(size);

    std::vector<std::vector<uint>> indexes;
    indexes.resize(size);

    for (int i = 0; i < _R.NumRows(); i++) {
        for (int j = 0; j < _R.NumCols(); j++) {
            if (NTL::IsOne(_R[i][j])) {
                indexes[i].push_back(j);
            }
        }
    }

    auto rnd_element = indexes[0][NTL::RandomBnd(indexes[0].size() - 1)];
    v[0] = rnd_element;
    R_tmp[0][rnd_element] = NTL::GF2(1);

    for (int i = 1; i < _R.NumRows(); i++) {
        do {
            rnd_element = indexes[i][NTL::RandomBnd(indexes[i].size() - 1)];
        } while (std::find(v.begin(), v.end(), rnd_element) != v.end());
        v[i] = rnd_element;
        R_tmp[i][rnd_element] = NTL::GF2(1);
    }

    _R = R_tmp;

    // Generate R
    R.SetLength(J);

    for (int i = 0; i < J; i++) {
        R[i].SetDims(size, size);
        for (int j = 0; j < size; j++) {
            for (int z = 0; z < size; z++) {
                R[i][j][z] = _R[j][z + (i * size)];
            }
        }
    }
}

int utils::gauss_row_reduced_echelon_form(NTL::mat_GF2 &M) {
    long row;
    long max_i = (int) floor((M.NumRows() + (M.NumCols() - 1)) / M.NumCols());
    for (long i = 0; i < max_i; i++) {
        for (long j = 0; j < M.NumCols(); j++) {

            row = i * M.NumCols() + j;

            if (row >= M.NumRows()) {
                return 1;
            }
            for (long k = row + 1; k < M.NumRows(); k++) {
                if (!NTL::IsZero(M[row][j] + M[k][j])) {
                    M[row] += M[k];
                }
            }

            for (long k = 0; k < M.NumRows(); k++) {
                if (k != row) {
                    if (!NTL::IsZero(M[k][j])) {
                        M[k] += M[row];
                    }
                }
            }
        }
    }
    return 0;
}

int utils::gauss_row_reduced_echelon_form_gf2e(
        NTL::mat_GF2E &M) {
    int i = 0;
    int j = 0;
    int found = 0;

    for (;;) {
        if (!NTL::IsZero(M[i][j])) {
            auto element = M[i][j];
            for (int c = 0; c < M.NumCols(); ++c) {
                M[i][c] = M[i][c] / element;
            }
        }

        if (!NTL::IsZero(M[i][j])) {
            for (int k = 0; k < M.NumRows(); k++) {
                if (k != i) {
                    auto t = M[k][j] / M[i][j];
                    for (int h = 0; h < M.NumCols(); h++) {
                        M[k][h] = M[k][h] - M[i][h] * t;
                    }
                }
            }
            i++;
            j++;
        } else {
            found = 0;
            for (int k = i; k < M.NumRows(); k++) {
                if (!NTL::IsZero(M[k][j])) {
                    for (int h = 0; h < M.NumCols(); h++) {
                        M[i][h] = M[i][h] + M[k][h];
                    }
                    found = 1;
                    break;
                }
            }
            if (found == 0) {
                j++;
            }
        }
        if (i > (M.NumRows() - 1) || j > (M.NumCols() - 1)) {
            break;
        }
    }

    return 0;
}

int utils::convert_matrix_to_rref_and_check_solutions(NTL::mat_GF2 &M) {

    utils::gauss_row_reduced_echelon_form(M);

    for (int i = 0; i < M.NumRows(); i++) {
        if (NTL::weight(NTL::IsZero(M[i]))) {
            break;
        }
        if (NTL::IsOne(M[i][M.NumCols() - 1]) && (NTL::weight(M[i]) == 1)) {
            return 1;
        }
    }
    return 0;
}

int utils::convert_matrix_to_rref_and_check_solutions(NTL::mat_GF2E &M) {

    utils::gauss_row_reduced_echelon_form_gf2e(M);

    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            if (i == j) {
                if (M[i][j]._GF2E__rep != NTL::GF2(1)) {
                    return 1;
                }
            } else {
                if (M[i][j]._GF2E__rep != NTL::GF2(0)) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

void utils::generate_random_matrix_gf2e(
        NTL::mat_GF2E &g,
        int num_of_rows,
        int num_of_cols) {

    g.kill();
    g = NTL::random_mat_GF2E(num_of_rows, num_of_cols);
}

void utils::generate_random_square_invertible_matrix(
        NTL::mat_GF2 &M,
        int size) {

    do {
        M = NTL::random_mat_GF2(size, size);
    } while (NTL::determinant(M) == 0);
}

void utils::generate_random_binary_matrix(
        NTL::mat_GF2 &A,
        int num_of_rows,
        int num_of_cols) {

    A.kill();
    A = NTL::random_mat_GF2(num_of_rows, num_of_cols);
}

void utils::generate_random_binary_vector_gf2e(
        NTL::vec_GF2E &v,
        int length) {

    v.SetLength(length);
    v = NTL::random_vec_GF2E(length);
}

void utils::generate_vector_of_specific_rank(
        NTL::vec_GF2E &e,
        int length,
        int rank) {

    e.SetLength(length);
    auto degree = e[0].degree();

    NTL::mat_GF2 _e;
    _e.SetDims(degree, length);

    NTL::vec_GF2E F;
    F.append(NTL::GF2E());

    int dim = 0;

    while (dim < rank) {
        auto n = NTL::random_GF2E();
        if (!is_element_in_vector(n, F)) {
            NTL::GF2E tmp;
            auto size_of_F = F.length();
            for (int i = 0; i < size_of_F; i++) {
                tmp = n + F[i];
                F.append(tmp);
            }
            dim++;
        }
    }

    NTL::mat_GF2 tmp_e;
    uint _rank = 0;
    do {
        for (int i = 0; i < length; i++) {
            auto rnd_element = F[NTL::RandomBnd(F.length() - 1)];
            NTL::vec_GF2 v;
            gf2_from_gf2e_element(v, rnd_element);

            for (int c = 0; c < v.length(); c++) {
                _e[c][i] = v[c];
            }
        }

        for (int i = 0; i < length; i++) {
            for (int j = 0; j < degree; j++) {
                NTL::SetCoeff(e[i].LoopHole(), j, _e[j][i]);
            }
        }

        tmp_e = utils::mat_gf2_from_vec_gf2e(e);
        _rank = NTL::gauss(tmp_e);
    } while (_rank != rank);

}

void utils::generate_random_binary_vector(
        NTL::vec_GF2 &v,
        int length) {

    v.SetLength(length);
    v = NTL::random_vec_GF2(length);
}

void utils::generate_vector_of_weight_w(
        NTL::vec_GF2 &e,
        int length,
        int weight) {

    e.SetLength(length);

    std::vector<uint> pos;
    for (long i = 0; i < e.length(); i++) {
        pos.push_back(i);
    }

    auto shuffled_vector = shuffle(
            pos,
            pos.size());

    for (long i = 0; i < weight; i++) {
        e[shuffled_vector[i]] = NTL::GF2(1);
    }
}

int utils::solve_equation(
        NTL::vec_GF2 &res,
        const NTL::mat_GF2 &M,
        const NTL::vec_GF2 &v) {

    auto A_T = NTL::transpose(M);

    A_T._mat__rep.append(v);
    A_T = NTL::transpose(A_T);

    if (utils::convert_matrix_to_rref_and_check_solutions(A_T) != 0) {
        return 1;
    }

    A_T = NTL::transpose(A_T);
    res = A_T[A_T.NumRows() - 1];

    return 0;
}

int utils::solve_equation(
        NTL::vec_GF2E &res,
        const NTL::mat_GF2E &M,
        const NTL::vec_GF2E &v) {

    auto A_T = M;

    A_T._mat__rep.append(v);
    A_T = NTL::transpose(A_T);

    if (utils::convert_matrix_to_rref_and_check_solutions(A_T) != 0) {
        return 1;
    }

    A_T = NTL::transpose(A_T);
    res = A_T[A_T.NumRows() - 1];

    return 0;
}

int utils::rank_of_vector(
        NTL::vec_GF2E &v) {

    NTL::mat_GF2 M;
    M.SetDims(v.length(), v[0].degree());

    for (int z = 0; z < EN; z++) {
        for (int j = 0; j < EM; j++) {
            if (NTL::IsZero(v[z]._GF2E__rep[j])) {
                M[z][j] = NTL::GF2(0);
            } else {
                M[z][j] = NTL::GF2(1);
            }
        }
    }

    auto _M = NTL::transpose(M);
    return NTL::gauss(_M);
}

std::vector<uint> utils::shuffle(
        const std::vector<uint> &input,
        int array_size) {

    std::vector<uint> index_array(input.size());
    std::vector<uint> output(input.size());

    int index;
    for (int i = 0; i < array_size; i++) {
        do {
            index = rand() % array_size;
        } while (index_array[index] != 0);
        index_array[index] = 1;
        output[i] = input[index];
    }

    return output;
}