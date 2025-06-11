#include <gtest/gtest.h>
#include "norm_eq.hpp"

TEST(R1CSTests, NormEqTrue){
    // Create the testing vector.
    const IntVec x{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // Create the R1CS test object
    const auto test = NormEq("test");
    // Generate the proof.
    BP_R1CS_PROOF* proof = test.prove(385, x);
    // Perform testing.
    EXPECT_TRUE(test.verify(x.size(), proof));
}

TEST(R1CSTests, NormEqFalse){
    // Create the testing vector.
    const IntVec x{1, 2, 3, 4, 5, 6, 7, 8, 9};
    // Create the R1CS test object
    const auto test = NormEq("test");
    // Generate the proof.
    BP_R1CS_PROOF* proof = test.prove(100, x);
    // Perform testing.
    EXPECT_FALSE(test.verify(x.size(), proof));
}