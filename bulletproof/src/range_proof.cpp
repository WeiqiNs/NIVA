#include "range_proof.hpp"

RangeProof::RangeProof(const char* label){
    // Create the transcript.
    ZKP_TRANSCRIPT* transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), label);
    // Create the public parameter.
    BP_PUB_PARAM* pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, 128, 1);
    // Create the witness.
    witness_ = BP_WITNESS_new(pp);
    // Create the CTX object.
    ctx_ = BP_R1CS_CTX_new(pp, witness_, transcript);;
}

RangeProof::RangeProof(BP_R1CS_CTX* ctx, BP_WITNESS* witness){
    // Assign the ctx and witness to the class.
    ctx_ = ctx;
    witness_ = witness;
}

BP_R1CS_CTX* RangeProof::get_ctx() const{ return ctx_; }

BP_WITNESS* RangeProof::get_witness() const{ return witness_; }

BP_R1CS_PROOF* RangeProof::prove(int64_t bits, const int64_t value) const{
    return prove(bits, value, ctx_, witness_);
}

BP_R1CS_PROOF* RangeProof::prove(int64_t bits, const int64_t value, BP_R1CS_CTX* ctx, BP_WITNESS* witness){
    // Create a BN value for v.
    BIGNUM* v = BN_new();
    BN_set_word(v, value);

    // Commit the value v and perform the logic.
    BP_R1CS_LINEAR_COMBINATION* lc = BP_WITNESS_r1cs_linear_combination_commit(witness, "v", v);
    logic(bits, &value, ctx, lc);

    // Generate the proof.
    return BP_R1CS_PROOF_prove(ctx);
}

int RangeProof::verify(int64_t bits, BP_R1CS_PROOF* proof) const{
    return verify(bits, ctx_, witness_, proof);
}

int RangeProof::verify(const int64_t bits, BP_R1CS_CTX* ctx, BP_WITNESS* witness, BP_R1CS_PROOF* proof){
    // Extract the witness.
    BP_R1CS_LINEAR_COMBINATION* lc = BP_WITNESS_r1cs_linear_combination_get(witness, "v");
    // Perform the logic.
    logic(bits, nullptr, ctx, lc);
    // Return the proof result.
    return BP_R1CS_PROOF_verify(ctx, proof);
}

void RangeProof::logic(const int64_t bits, const int64_t* value, BP_R1CS_LINEAR_COMBINATION* v) const{
    logic(bits, value, ctx_, v);
}

void RangeProof::logic(const int64_t bits, const int64_t* value, BP_R1CS_CTX* ctx, BP_R1CS_LINEAR_COMBINATION* v){
    // Declare the useful variables.
    BP_R1CS_LINEAR_COMBINATION *a = nullptr, *b = nullptr, *o = nullptr;

    // Get new BN values for these.
    BIGNUM* l = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* power_two = BN_new();

    // Set the value one, power_two will start from one and keep adding itself.
    BN_one(one);
    BN_one(power_two);

    // Iterate through the bits to check for larger or not.
    for (int i = 0; i < bits; i++){
        if (value != nullptr){
            // Get whether the i-th bit is zero or not.
            const int64_t n = *value >> i & 0x1;
            const int64_t m = 1 - n;
            // Perform BN conversion.
            BN_set_word(l, m);
            BN_set_word(r, n);
            // Perform raw multiplication from the BN numbers.
            BP_R1CS_LINEAR_COMBINATION_raw_mul(&o, &a, &b, l, r, ctx);
        }
        else{
            // Perform raw multiplication from the BN numbers.
            BP_R1CS_LINEAR_COMBINATION_raw_mul(&o, &a, &b, nullptr, nullptr, ctx);
        }

        // More constraint and logic.
        BP_R1CS_LINEAR_COMBINATION_constrain(o, ctx);
        BP_R1CS_LINEAR_COMBINATION_add(a, b);
        BP_R1CS_LINEAR_COMBINATION_sub_bn(a, one);
        BP_R1CS_LINEAR_COMBINATION_mul_bn(b, power_two);
        BP_R1CS_LINEAR_COMBINATION_sub(v, b);
        BN_add(power_two, power_two, power_two);

        // Free the temp pointers used in this iteration.
        BP_R1CS_LINEAR_COMBINATION_free(a);
        BP_R1CS_LINEAR_COMBINATION_free(b);
        BP_R1CS_LINEAR_COMBINATION_free(o);
        a = b = o = nullptr;
    }

    BP_R1CS_LINEAR_COMBINATION_constrain(v, ctx);
}