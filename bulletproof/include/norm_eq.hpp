#pragma once

#include <openssl/bulletproofs.h>
#include "helper.hpp"

/**
 * @class NormEq
 * @brief A class for generating and verifying Bulletproofs-based L2 norm bound using R1CS.
 */
class NormEq {
public:
    /**
     * Construct a new NormEq object and initialize the context and witness with a label.
     * @param label A unique label used to namespace the constraint system.
     */
    explicit NormEq(const char* label);

    /**
     * Construct a new NormEq object with existing R1CS context and witness.
     * @param ctx Pointer to an existing BP_R1CS_CTX.
     * @param witness Pointer to an existing BP_WITNESS.
     */
    NormEq(BP_R1CS_CTX* ctx, BP_WITNESS* witness);

    /**
     * Get the internal R1CS context.
     * @return Pointer to the BP_R1CS_CTX.
     */
    [[nodiscard]] BP_R1CS_CTX* get_ctx() const;

    /**
     * Get the internal witness.
     * @return Pointer to the BP_WITNESS.
     */
    [[nodiscard]] BP_WITNESS* get_witness() const;

    /**
     * Generate a proof that the l2 norm of vector x equals the given value using the internal context and witness.
     * @param value The expected norm value.
     * @param x The input vector.
     * @return Pointer to the generated BP_R1CS_PROOF.
     */
    [[nodiscard]] BP_R1CS_PROOF* prove(int64_t value, const IntVec& x) const;

    /**
     * Generate a proof that the l2 norm of vector x equals the given value using the provided context and witness.
     * @param value The expected norm value.
     * @param x The input vector.
     * @param ctx Pointer to the BP_R1CS_CTX.
     * @param witness Pointer to the BP_WITNESS.
     * @return Pointer to the generated BP_R1CS_PROOF.
     */
    static BP_R1CS_PROOF* prove(
        int64_t value,
        const IntVec& x,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness
    );

    /**
     * Verify a proof for a l2 norm using the internal context and witness.
     * @param size The size of the vector used in the proof.
     * @param proof Pointer to the proof to verify.
     * @return 1 if the proof is valid, 0 otherwise.
     */
    [[nodiscard]] int verify(int64_t size, BP_R1CS_PROOF* proof) const;

    /**
     * Verify a proof for a l2 norm using the given context and witness.
     * @param size The size of the vector used in the proof.
     * @param ctx Pointer to the BP_R1CS_CTX.
     * @param witness Pointer to the BP_WITNESS.
     * @param proof Pointer to the proof to verify.
     * @return 1 if the proof is valid, 0 otherwise.
     */
    static int verify(
        int64_t size,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness,
        BP_R1CS_PROOF* proof
    );

    /**
     * Define the R1CS constraints for the l2 norm using the internal context.
     * @param x The vector of R1CS variables.
     * @param v The linear combination representing the norm value.
     */
    void logic(const R1CSVec& x, const BP_R1CS_LINEAR_COMBINATION* v) const;

    /**
     * Define the R1CS constraints for the l2 norm using the provided context.
     * @param x The vector of R1CS variables.
     * @param ctx Pointer to the BP_R1CS_CTX.
     * @param v The linear combination representing the norm value.
     */
    static void logic(const R1CSVec& x, BP_R1CS_CTX* ctx, const BP_R1CS_LINEAR_COMBINATION* v);

private:
    // Create null pointers to hold these parameters.
    BP_R1CS_CTX* ctx_ = nullptr;
    BP_WITNESS* witness_ = nullptr;
};
