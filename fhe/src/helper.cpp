#include "helper.hpp"

uint64_t Helper::hash_mod(const uint64_t x, const uint64_t y){
    // Set the holder for hash result and the final result.
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    // Create an EVP context and use BLAKE2b.
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx){
        fprintf(stderr, "Error: failed to create EVP_MD_CTX\n");
        return 0;
    }

    if (EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr) != 1){
        fprintf(stderr, "Error: EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Hash the bytes of x.
    if (EVP_DigestUpdate(ctx, &x, sizeof(x)) != 1){
        fprintf(stderr, "Error: EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Finalize the digest to get up to 64 bytes.
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1){
        fprintf(stderr, "Error: EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Clean up.
    EVP_MD_CTX_free(ctx);

    // Create holder for the remainder.
    uint64_t remainder = 0;

    // Perform the modulo step by step.
    for (int i = 0; i < 8; i++){
        // Extract the next 8 bytes as a 64-bit chunk (big-endian).
        uint64_t chunk = 0;
        for (int j = 0; j < 8; j++) chunk = (chunk << 8) | hash[i * 8 + j];

        // Combine old remainder with this chunk in 128 bits.
        const __uint128_t temp = static_cast<__uint128_t>(remainder) << 64 | chunk;

        // Reduce mod y.
        remainder = static_cast<uint64_t>(temp % y);
    }

    return remainder;
}

string Helper::uint64_to_hex_string(const uint64_t value){
    // Create a string stream and perform hex conversion.
    stringstream ss;
    ss << hex << value;
    return ss.str();
}

uint64_t Helper::hex_string_to_uint64(const string& value){
    return stoull(value, nullptr, 16);
}
