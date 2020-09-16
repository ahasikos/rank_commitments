#include "test_functions.h"
#include "test_params.h"

void test::test_functions::print_perf(
        const std::string &type_of_metric,
        const std::string &test,
        const std::chrono::duration<double, std::milli> &diff) {
    std::cout
            << "====== " << type_of_metric << " Weight ======\n"
            << test << " \n"
            << std::chrono::duration<double, std::milli>(diff / NUMBER_OF_ITERATIONS).count() << " ms\n"
            << "=========================="
            << std::endl;
}

void test::test_functions::print_ops(
        const std::string &type_of_metric,
        const std::string &test,
        double seconds,
        double ops) {

    std::cout
            << "====== " << type_of_metric << " Weight ======\n"
            << test << " \n"
//            << seconds << " s\n"
            << ops * 1000 << " ms\n"
            << "=========================="
            << std::endl;
}