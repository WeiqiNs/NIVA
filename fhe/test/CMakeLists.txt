# -----------------------------------------------------
# Include google test here and enable testing.
include(GoogleTest)
# Set alias for google test.
set(GTEST_LIB gtest gtest_main)
# -----------------------------------------------------
add_executable(test_helper test_helper.cpp)
target_link_libraries(test_helper SealFHE ${GTEST_LIB})
gtest_discover_tests(test_helper)
# -----------------------------------------------------
add_executable(test_fhe test_fhe.cpp)
target_link_libraries(test_fhe SealFHE ${GTEST_LIB})
gtest_discover_tests(test_fhe)
# -----------------------------------------------------