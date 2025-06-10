#pragma once

#include <openssl/bulletproofs.h>
#include "helper.hpp"

class NormEq{
public:
    explicit NormEq(const char* label);

    NormEq(BP_R1CS_CTX* ctx, BP_WITNESS* witness);

    [[nodiscard]] BP_R1CS_CTX* get_ctx() const;

    [[nodiscard]] BP_WITNESS* get_witness() const;

    [[nodiscard]] BP_R1CS_PROOF* prove(int64_t value, const IntVec& x) const;

    static BP_R1CS_PROOF* prove(
        int64_t value,
        const IntVec& x,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness
    );

    [[nodiscard]] int verify(int64_t size, BP_R1CS_PROOF* proof) const;

    static int verify(
        int64_t size,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness,
        BP_R1CS_PROOF* proof
    );

    void logic(const R1CSVec& x, const BP_R1CS_LINEAR_COMBINATION* v) const;

    static void logic(const R1CSVec& x, BP_R1CS_CTX* ctx, const BP_R1CS_LINEAR_COMBINATION* v);

private:
    // Create null pointers to hold these parameters.
    BP_R1CS_CTX* ctx_ = nullptr;
    BP_WITNESS* witness_ = nullptr;
};
