#include <NTL/vec_GF2.h>
#include <utils/utils.h>
#include <NTL/GF2XFactoring.h>
#include "test_utils.h"

int test::utils::test_gf2x_from_gf2() {

    NTL::vec_GF2 input;
    input.SetLength(5);

    {
        input[0] = NTL::GF2(0);
        input[1] = NTL::GF2(1);
        input[2] = NTL::GF2(1);
        input[3] = NTL::GF2(1);
        input[4] = NTL::GF2(0);
    }

    auto out = ::utils::gf2x_from_gf2(input);

    assert(out[0] == input[0]);
    assert(out[1] == input[1]);
    assert(out[2] == input[2]);
    assert(out[3] == input[3]);
    assert(out[4] == input[4]);

    return 0;
}
int test::utils::test_gf2_from_gf2x() {

    NTL::GF2X input;
    input.SetLength(5);

    {
        input[0] = NTL::GF2(0);
        input[1] = NTL::GF2(1);
        input[2] = NTL::GF2(1);
        input[3] = NTL::GF2(1);
        input[4] = NTL::GF2(0);
    }

    auto out = ::utils::gf2_from_gf2x(input, 5);

    assert(out[0] == input[0]);
    assert(out[1] == input[1]);
    assert(out[2] == input[2]);
    assert(out[3] == input[3]);
    assert(out[4] == input[4]);

    return 0;
}

int test::utils::test_gf2x_from_matgf2() {

    NTL::mat_GF2 input;
    input.SetDims(2, 4);

    {
        input[0][0] = NTL::GF2(0);
        input[0][1] = NTL::GF2(1);
        input[0][2] = NTL::GF2(1);
        input[0][3] = NTL::GF2(0);

        input[1][0] = NTL::GF2(1);
        input[1][1] = NTL::GF2(1);
        input[1][2] = NTL::GF2(0);
        input[1][3] = NTL::GF2(1);
    }

    auto out = ::utils::gf2x_from_matgf2(input);

    assert(out[0] == input[0][0]);
    assert(out[1] == input[0][1]);
    assert(out[2] == input[0][2]);
    assert(out[3] == input[0][3]);

    assert(out[4] == input[1][0]);
    assert(out[5] == input[1][1]);
    assert(out[6] == input[1][2]);
    assert(out[7] == input[1][3]);


    return 0;
}

int test::utils::test_gf2x_from_gf2e() {

    int polynomial_degree = 18;
    int length_of_vector = 100;

    auto irred_poly = NTL::BuildIrred_GF2X(polynomial_degree);
    NTL::GF2E::init(irred_poly);

    auto input = NTL::random_vec_GF2E(1);
    auto output = ::utils::gf2x_from_gf2e(input);

    for(int i = 0; i < input[0].degree(); i++) {
        assert(input[0].LoopHole()[i] == output[i]);
    }

    input = NTL::random_vec_GF2E(length_of_vector);
    output = ::utils::gf2x_from_gf2e(input);

    for(int i = 0; i < input.length(); i++) {
        for(int j = 0; j < input[i].degree(); j++) {
            assert(input[i].LoopHole()[j] == output[j + (i * input[i].degree())]);
        }
    }

    return 0;
}

int test::utils::test_gf2_from_gf2e() {

    int polynomial_degree = 19;
    int length_of_vector = 100;

    auto irred_poly = NTL::BuildIrred_GF2X(polynomial_degree);
    NTL::GF2E::init(irred_poly);

    auto input = NTL::random_vec_GF2E(1);
    auto output = ::utils::gf2_from_gf2e(input);

    for(int i = 0; i < input[0].degree(); i++) {
        assert(input[0].LoopHole()[i] == output[i]);
    }

    input = NTL::random_vec_GF2E(length_of_vector);
    output = ::utils::gf2_from_gf2e(input);

    for(int i = 0; i < input.length(); i++) {
        for(int j = 0; j < input[i].degree(); j++) {
            assert(input[i].LoopHole()[j] == output[j + (i * input[i].degree())]);
        }
    }

    return 0;
}

int test::utils::test_gf2e_from_gf2x() {

    int polynomial_degree = 21;
    int vector_length = 250;

    auto irred_poly = NTL::BuildIrred_GF2X(polynomial_degree);
    NTL::GF2E::init(irred_poly);

    auto input = NTL::random_GF2X(vector_length);
    auto output = ::utils::gf2e_from_gf2x(input, vector_length);

    for(int i = 0; i < output.length(); i++) {
        for(int j = 0; j < output[i].degree(); j++) {
            assert(input[j + (i * output[i].degree())] == output[i].LoopHole()[j]);
        }
    }

    return 0;
}

int test::utils::test_gf2e_from_two_gf2() {

    int polynomial_degree = 17;
    int vector_length = 4;

    auto irred_poly = NTL::BuildIrred_GF2X(polynomial_degree);
    NTL::GF2E::init(irred_poly);

    auto input_1 = NTL::random_vec_GF2(vector_length);
    auto input_2 = NTL::random_vec_GF2(vector_length);

    auto output = ::utils::gf2e_from_two_gf2(input_1, input_2);

    NTL::append(input_1, input_2);

    for(int i = 0; i < output.length(); i++) {
        for(int j = 0; j < output[i].degree(); j++) {
            assert(input_1[j + (i * output[i].degree())] == output[i].LoopHole()[j]);
        }
    }

    return 0;
}

int test::utils::test_gf2e_from_vec_gf2() {

    int polynomial_degree = 17;
    int vector_length = 100;

    auto irred_poly = NTL::BuildIrred_GF2X(polynomial_degree);
    NTL::GF2E::init(irred_poly);

    auto input = NTL::random_vec_GF2(vector_length);
    auto output = ::utils::gf2e_from_vec_gf2(input);

    for(int i = 0; i < output.length(); i++) {
        for(int j = 0; j < output[i].degree(); j++) {
            assert(input[j + (i * output[i].degree())] == output[i].LoopHole()[j]);
        }
    }

    return 0;
}

int test::utils::test_mat_gf2_from_vec_gf2e() {

    int polynomial_degree = 17;
    int vector_length = 100;

    auto irred_poly = NTL::BuildIrred_GF2X(polynomial_degree);
    NTL::GF2E::init(irred_poly);

    auto input = NTL::random_vec_GF2E(vector_length);
    auto output = ::utils::mat_gf2_from_vec_gf2e(input);

    for(int i = 0; i < input.length(); i++) {
        for(int j = 0; j < input[i].degree(); j++) {
            assert(output[i][j] == input[i]._GF2E__rep[j]);
        }
    }

    return 0;
}