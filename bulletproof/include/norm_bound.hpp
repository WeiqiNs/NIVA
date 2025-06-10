#pragma once

#include "norm_eq.hpp"
#include "range_proof.hpp"

class NormBound{
public:
    explicit NormBound(const char* label);

    NormBound(BP_R1CS_CTX* ctx, BP_WITNESS* witness);

    [[nodiscard]] BP_R1CS_CTX* get_ctx() const;

    [[nodiscard]] BP_WITNESS* get_witness() const;

    [[nodiscard]] BP_R1CS_PROOF* prove(int64_t bits, const IntVec& x) const;

    static BP_R1CS_PROOF* prove(
        int64_t bits,
        const IntVec& x,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness
    );

    [[nodiscard]] int verify(int64_t bits,  int64_t size, BP_R1CS_PROOF* proof) const;

    static int verify(
        int64_t bits,
        int64_t size,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness,
        BP_R1CS_PROOF* proof
    );

private:
    // Create null pointers to hold these parameters.
    BP_R1CS_CTX* ctx_ = nullptr;
    BP_WITNESS* witness_ = nullptr;
};
