#ifndef TEST_FUNCTIONS_H_
#define TEST_FUNCTIONS_H_

#include <iostream>

namespace test {
    namespace test_functions {
        void print_perf(
                const std::string &type_of_metric,
                const std::string &test,
                const std::chrono::duration<double, std::milli> &diff);

        void print_ops(
                const std::string &type_of_metric,
                const std::string &test,
                double seconds,
                double ops);
    }
}


#endif //TEST_FUNCTIONS_H_
