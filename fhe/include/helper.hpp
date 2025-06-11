#pragma once

#include <cstdint>
#include <iomanip>
#include <string>
#include <openssl/evp.h>

using namespace std;

class Helper{
public:
    /**
     * Given an integer x, compute hash(x) mod y. The hash used is BLAKE2b from openssl.
     * @param x some integer, at max 64 bits long.
     * @param y some integer, at max 64 bits long.
     * @return hash(x) mod y.
     */
    static uint64_t hash_mod(uint64_t x, uint64_t y);

    /**
     * Convert an uint64 object to hex string.
     * @param value some integer hold by uint64.
     * @return a hex string representation of the input integer.
     */
    static string uint64_to_hex_string(uint64_t value);

    /**
     * Convert an uint64 object to hex string.
     * @param value some integer hold by uint64.
     * @return a hex string representation of the input integer.
     */
    static uint64_t hex_string_to_uint64(const string& value);
};
