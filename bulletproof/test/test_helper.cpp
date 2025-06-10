#include <gtest/gtest.h>
#include "helper.hpp"

TEST(HelperTests, L2Test){
    // Create the testing vector.
    const IntVec x{10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    // Check the computation.
    EXPECT_EQ(Helper::int_vec_l2(x), 38500);
}

TEST(HelperTests, BigNumTest){
    // Create the testing vector.
    const IntVec x{10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    // Convert the big num.
    const BNVec bn_x = Helper::int_to_bignum(x);
    // Verify the conversion.
    EXPECT_TRUE(BN_is_word(bn_x[0], 10));
    EXPECT_FALSE(BN_is_word(bn_x[1], 100));
}