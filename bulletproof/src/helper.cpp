#include "helper.hpp"

int64_t Helper::int_vec_l2(const IntVec& x){
    // Compute the L2 norm (without square root).
    auto result = x[0] * x[0];
    for (int i = 1; i < x.size(); i++) result += x[i] * x[i];

    return result;
}

BNVec Helper::int_to_bignum(const IntVec& x){
    BNVec result(x.size());

    for (int i = 0; i < x.size(); i++){
        // Set the values.
        result[i] = BN_new();
        BN_set_word(result[i], x[i]);
    }
    return result;
}

R1CSVec Helper::commit_vector(const BNVec& x, BP_WITNESS* witness){
    R1CSVec result(x.size());

    for (int i = 0; i < x.size(); i++){
        // Create the name of the witness.
        const char* name = ("x" + std::to_string(i)).c_str();
        // Commit to the witness.
        result[i] = BP_WITNESS_r1cs_linear_combination_commit(witness, name, x[i]);
    }

    return result;
}

R1CSVec Helper::extract_commit_vector(const int64_t size, BP_WITNESS* witness){
    R1CSVec result(size);

    for (unsigned long i = 0; i < size; i++){
        // Create the name of the witness.
        const char* name = ("x" + std::to_string(i)).c_str();
        // Extract from the witness.
        result[i] = BP_WITNESS_r1cs_linear_combination_get(witness, name);
    }

    return result;
}
