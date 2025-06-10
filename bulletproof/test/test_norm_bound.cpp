#include <gtest/gtest.h>
#include "norm_bound.hpp"

TEST(R1CSTests, NormBoundTrue){
    // Create the testing vector.
    const IntVec x{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // Create the R1CS test object
    const auto test = NormBound("test");
    // Generate the proof.
    BP_R1CS_PROOF* proof = test.prove(9, x);
    // Perform testing.
    EXPECT_TRUE(test.verify(9, x.size(), proof));
}

TEST(R1CSTests, NormBoundFalse){
    // Create the testing vector.
    const IntVec x{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // Create the R1CS test object
    const auto test = NormBound("test");
    // Generate the proof.
    BP_R1CS_PROOF* proof = test.prove(8, x);
    // Perform testing.
    EXPECT_FALSE(test.verify(8, x.size(), proof));
}
