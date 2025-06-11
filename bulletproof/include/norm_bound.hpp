#pragma once

#include "norm_eq.hpp"
#include "range_proof.hpp"


class NormBound {
public:
    /**
     * Construct a new NormBound object and initialize context and witness using a label.
     * @param label A unique label used to namespace the constraint system.
     */
    explicit NormBound(const char* label);

    /**
     * Construct a new NormBound object with existing R1CS context and witness.
     * @param ctx Pointer to an existing BP_R1CS_CTX.
     * @param witness Pointer to an existing BP_WITNESS.
     */
    NormBound(BP_R1CS_CTX* ctx, BP_WITNESS* witness);

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
     * Generate a proof that the l2 norm of vector x is within the specified bit bound.
     * @param bits The upper bound on the bit length of the norm.
     * @param x The input vector.
     * @return Pointer to the generated BP_R1CS_PROOF.
     */
    [[nodiscard]] BP_R1CS_PROOF* prove(int64_t bits, const IntVec& x) const;

    /**
     * Generate a proof that the l2 norm of vector x is within the bit bound using the provided context and witness.
     * @param bits The upper bound on the bit length of the norm.
     * @param x The input vector.
     * @param ctx Pointer to the BP_R1CS_CTX.
     * @param witness Pointer to the BP_WITNESS.
     * @return Pointer to the generated BP_R1CS_PROOF.
     */
    static BP_R1CS_PROOF* prove(
        int64_t bits,
        const IntVec& x,
        BP_R1CS_CTX* ctx,
        BP_WITNESS* witness
    );

    /**
     * Verify that a proof asserts the l2 norm of a vector is within the specified bit bound using the internal context and witness.
     * @param bits The upper bound on the bit length of the norm.
     * @param size The expected size of the vector.
     * @param proof Pointer to the proof to verify.
     * @return 1 if the proof is valid, 0 otherwise.
     */
    [[nodiscard]] int verify(int64_t bits, int64_t size, BP_R1CS_PROOF* proof) const;

    /**
     * Verify that a proof asserts the l2 norm of a vector is within the specified bit bound using the given context and witness.
     * @param bits The upper bound on the bit length of the norm.
     * @param size The expected size of the vector.
     * @param ctx Pointer to the BP_R1CS_CTX.
     * @param witness Pointer to the BP_WITNESS.
     * @param proof Pointer to the proof to verify.
     * @return 1 if the proof is valid, 0 otherwise.
     */
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
