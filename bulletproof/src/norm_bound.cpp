#include "norm_bound.hpp"

NormBound::NormBound(const char* label){
    // Create the transcript.
    ZKP_TRANSCRIPT* transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), label);
    // Create the public parameter.
    BP_PUB_PARAM* pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, 128, 1);
    // Create the witness.
    witness_ = BP_WITNESS_new(pp);
    // Create the CTX object.
    ctx_ = BP_R1CS_CTX_new(pp, witness_, transcript);;
}

NormBound::NormBound(BP_R1CS_CTX* ctx, BP_WITNESS* witness){
    ctx_ = ctx;
    witness_ = witness;
}

BP_R1CS_CTX* NormBound::get_ctx() const{ return ctx_; }

BP_WITNESS* NormBound::get_witness() const{ return witness_; }

BP_R1CS_PROOF* NormBound::prove(const int64_t bits, const IntVec& x) const{
    return prove(bits, x, ctx_, witness_);
}

BP_R1CS_PROOF* NormBound::prove(const int64_t bits, const IntVec& x, BP_R1CS_CTX* ctx, BP_WITNESS* witness){
    // Perform the conversion and commitment.
    const BNVec bn_x = Helper::int_to_bignum(x);
    const R1CSVec cm_x = Helper::commit_vector(bn_x, witness);

    // Get a commitment for value v and commitment.
    const int64_t value = Helper::int_vec_l2(x);
    BIGNUM* bn_value = BN_new();
    BN_set_word(bn_value, value);

    // Also commit the value v.
    BP_R1CS_LINEAR_COMBINATION* v = BP_WITNESS_r1cs_linear_combination_commit(witness, "v", bn_value);

    // Do the l2 norm logic.
    NormEq::logic(cm_x, ctx, v);
    RangeProof::logic(bits, &value, ctx, v);

    // Generate proof.
    return BP_R1CS_PROOF_prove(ctx);
}

int NormBound::verify(const int64_t bits, const int64_t size, BP_R1CS_PROOF* proof) const{
    return verify(bits, size, ctx_, witness_, proof);
}

int NormBound::verify(
    const int64_t bits, const int64_t size, BP_R1CS_CTX* ctx, BP_WITNESS* witness, BP_R1CS_PROOF* proof){
    // Extract commitments of the vector.
    const R1CSVec x = Helper::extract_commit_vector(size, witness);
    // Extract commitment of the norm value.
    BP_R1CS_LINEAR_COMBINATION* v = BP_WITNESS_r1cs_linear_combination_get(witness, "v");
    // Run through the logic.
    NormEq::logic(x, ctx, v);
    RangeProof::logic(bits, nullptr, ctx, v);
    // Perform verification.
    return BP_R1CS_PROOF_verify(ctx, proof);
}
