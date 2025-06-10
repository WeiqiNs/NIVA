#include <gtest/gtest.h>
#include "range_proof.hpp"

TEST(R1CSTests, RangeProofTrue){
    // Create the R1CS test object
    const auto test = RangeProof("test");
    // Generate the proof.
    BP_R1CS_PROOF* proof = test.prove(16, 100);
    // Verify that the proof is correct, i.e. returns 1.
    EXPECT_TRUE(RangeProof::verify(16, test.get_ctx(), test.get_witness(), proof));
}

TEST(R1CSTests, RangeProofFalse){
    // Create the R1CS test object
    const auto test = RangeProof("test");
    // Generate the proof.
    BP_R1CS_PROOF* proof = test.prove(16, 1 << 20);
    // Verify that the proof is correct, i.e. returns 1.
    EXPECT_FALSE(RangeProof::verify(16, test.get_ctx(), test.get_witness(), proof));
}
