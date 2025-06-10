#pragma once

#include <openssl/bulletproofs.h>

class RangeProof{
public:
    explicit RangeProof(const char* label);

    RangeProof(BP_R1CS_CTX* ctx, BP_WITNESS* witness);

    [[nodiscard]] BP_R1CS_CTX* get_ctx() const;

    [[nodiscard]] BP_WITNESS* get_witness() const;

    [[nodiscard]] BP_R1CS_PROOF* prove(int64_t bits, int64_t value) const;

    static BP_R1CS_PROOF* prove(
        int64_t bits,
        int64_t value,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness
    );

    [[nodiscard]] int verify(int64_t bits, BP_R1CS_PROOF* proof) const;

    static int verify(
        int64_t bits,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness,
        BP_R1CS_PROOF* proof
    );

    void logic(int64_t bits, const int64_t* value, BP_R1CS_LINEAR_COMBINATION* v) const;

    static void logic(
        int64_t bits,
        const int64_t* value,
        BP_R1CS_CTX* ctx,
        BP_R1CS_LINEAR_COMBINATION* v
    );

private:
    // Create null pointers to hold these parameters.
    BP_R1CS_CTX* ctx_ = nullptr;
    BP_WITNESS* witness_ = nullptr;
};
