#ifndef NETFORGE_TEST_UTIL_HPP
#define NETFORGE_TEST_UTIL_HPP

#include <cstdio>

namespace netforge_test {

inline int failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,   \
                         #cond);                                           \
            ++netforge_test::failures;                                     \
        }                                                                  \
    } while (0)

#define DONE()                                                             \
    do {                                                                   \
        std::printf("== %s: %s (%d failure%s) ==\n", __FILE__,             \
                    netforge_test::failures ? "FAILED" : "PASSED",         \
                    netforge_test::failures,                               \
                    netforge_test::failures == 1 ? "" : "s");              \
        return netforge_test::failures ? 1 : 0;                            \
    } while (0)

}  // namespace netforge_test

#endif  // NETFORGE_TEST_UTIL_HPP