#ifndef TEST_UTILS_H_
#define TEST_UTILS_H_

namespace test {
    namespace utils {
        int test_gf2x_from_gf2();
        int test_gf2_from_gf2x();
        int test_gf2x_from_matgf2();
        int test_gf2x_from_gf2e();
        int test_gf2_from_gf2e();
        int test_gf2e_from_gf2x();
        int test_gf2e_from_two_gf2();
        int test_gf2e_from_vec_gf2();
        int test_mat_gf2_from_vec_gf2e();
    }
}

#endif //TEST_UTILS_H_
