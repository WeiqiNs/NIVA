#include <gtest/gtest.h>
#include "helper.hpp"

TEST(HelperTests, Hash){
    // Set the value and the mod.
    constexpr uint64_t x = 1234567890;
    constexpr uint64_t y = 10;

    // Perform the hash operation.
    const uint64_t z = Helper::hash_mod(x, y);

    // Perform testing.
    EXPECT_EQ(z, 7);
}

TEST(HelperTests, IntToHex){
    // Set the value and perform testing.
    constexpr uint64_t x = 17;
    EXPECT_EQ(Helper::uint64_to_hex_string(x), "11");
}

TEST(HelperTests, HexToInt){
    // Set the value and perform testing.
    const string x = "123";
    EXPECT_EQ(Helper::hex_string_to_uint64(x), 291);
}
