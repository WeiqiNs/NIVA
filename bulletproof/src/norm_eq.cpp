#include "norm_eq.hpp"

NormEq::NormEq(const char* label){
    // Create the transcript.
    ZKP_TRANSCRIPT* transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), label);
    // Create the public parameter.
    BP_PUB_PARAM* pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, 128, 1);
    // Create the witness.
    witness_ = BP_WITNESS_new(pp);
    // Create the CTX object.
    ctx_ = BP_R1CS_CTX_new(pp, witness_, transcript);;
}

NormEq::NormEq(BP_R1CS_CTX* ctx, BP_WITNESS* witness){
    ctx_ = ctx;
    witness_ = witness;
}

BP_R1CS_CTX* NormEq::get_ctx() const{ return ctx_; }

BP_WITNESS* NormEq::get_witness() const{ return witness_; }

BP_R1CS_PROOF* NormEq::prove(const int64_t value, const IntVec& x) const{
    return prove(value, x, ctx_, witness_);
}

BP_R1CS_PROOF* NormEq::prove(const int64_t value, const IntVec& x, BP_R1CS_CTX* ctx, BP_WITNESS* witness){
    // Perform the conversion and commitment.
    const BNVec bn_x = Helper::int_to_bignum(x);
    const R1CSVec cm_x = Helper::commit_vector(bn_x, witness);

    // Get a commitment for value v and commitment.
    BIGNUM* bn_value = BN_new();
    BN_set_word(bn_value, value);

    // Also commit the value v.
    const BP_R1CS_LINEAR_COMBINATION* v = BP_WITNESS_r1cs_linear_combination_commit(witness, "v", bn_value);

    // Do the l2 norm logic.
    logic(cm_x, ctx, v);

    // Generate proof.
    return BP_R1CS_PROOF_prove(ctx);
}

int NormEq::verify(const int64_t size, BP_R1CS_PROOF* proof) const{
    return verify(size, ctx_, witness_, proof);
}

int NormEq::verify(const int64_t size, BP_R1CS_CTX* ctx, BP_WITNESS* witness, BP_R1CS_PROOF* proof){
    // Extract commitments of the vector.
    const R1CSVec x = Helper::extract_commit_vector(size, witness);
    // Extract commitment of the norm value.
    const BP_R1CS_LINEAR_COMBINATION* v = BP_WITNESS_r1cs_linear_combination_get(witness, "v");
    // Run through the logic.
    logic(x, ctx, v);
    // Perform verification.
    return BP_R1CS_PROOF_verify(ctx, proof);
}

void NormEq::logic(const R1CSVec& x, const BP_R1CS_LINEAR_COMBINATION* v) const{
    logic(x, ctx_, v);
}

void NormEq::logic(const R1CSVec& x, BP_R1CS_CTX* ctx, const BP_R1CS_LINEAR_COMBINATION* v){
    // The first item is square of x0.
    BP_R1CS_LINEAR_COMBINATION* result = BP_R1CS_LINEAR_COMBINATION_dup(x[0]);
    BP_R1CS_LINEAR_COMBINATION_mul(result, result, ctx);

    // Keep adding the result to result.
    for (int i = 1; i < x.size(); i++){
        // Get the current big number.
        BP_R1CS_LINEAR_COMBINATION* temp = BP_R1CS_LINEAR_COMBINATION_dup(x[i]);
        // Square it and add it to result.
        BP_R1CS_LINEAR_COMBINATION_mul(temp, temp, ctx);
        BP_R1CS_LINEAR_COMBINATION_add(result, temp);
        // Free the temp pointer.
        BP_R1CS_LINEAR_COMBINATION_free(temp);
    }

    // Minus the aggregated value.
    BP_R1CS_LINEAR_COMBINATION_sub(result, v);
    BP_R1CS_LINEAR_COMBINATION_constrain(result, ctx);
}
