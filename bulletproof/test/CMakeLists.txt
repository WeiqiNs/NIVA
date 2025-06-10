# -----------------------------------------------------
# Include google test here and enable testing.
include(GoogleTest)
# Set alias for google test.
set(GTEST_LIB gtest gtest_main)
# -----------------------------------------------------
add_executable(test_helper test_helper.cpp)
target_link_libraries(test_helper BP ${GTEST_LIB})
gtest_discover_tests(test_helper)
# -----------------------------------------------------
add_executable(test_range_proof test_range_proof.cpp)
target_link_libraries(test_range_proof BP ${GTEST_LIB})
gtest_discover_tests(test_range_proof)
# -----------------------------------------------------
add_executable(test_norm_bound test_norm_bound.cpp)
target_link_libraries(test_norm_bound BP ${GTEST_LIB})
gtest_discover_tests(test_norm_bound)
# -----------------------------------------------------
add_executable(test_norm_eq test_norm_eq.cpp)
target_link_libraries(test_norm_eq BP ${GTEST_LIB})
gtest_discover_tests(test_norm_eq)
# -----------------------------------------------------