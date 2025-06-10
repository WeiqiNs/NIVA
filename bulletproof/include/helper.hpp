#pragma once

#include <vector>
#include <string>
#include <openssl/bulletproofs.h>

using BNVec = std::vector<BIGNUM*>;
using IntVec = std::vector<int64_t>;
using R1CSVec = std::vector<BP_R1CS_LINEAR_COMBINATION*>;

class Helper{
public:
    /**
     * Given an array x of int64 integers, compute sum(x_i^2).
     * @param x an array of int64 integers.
     * @return an integer representing sum(x_i^2).
     */
    static int64_t int_vec_l2(const IntVec& x);

    /**
     * Given an array x of int64 integers, convert them to pointers of BIGNUM.
     * @param x an array of int64 integers.
     * @return a vector holding pointers of BIGNUM.
     */
    static BNVec int_to_bignum(const IntVec& x);

    /**
     * Given an array x of int64 integers, commit them to values from x_0 to x_(|x| - 1) to the witness.
     * @param x an array of int64 integers.
     * @param witness a pointer of the R1CS witness.
     * @return a vector of commited R1CS constraint.
     */
    static R1CSVec commit_vector(const BNVec& x, BP_WITNESS* witness);

    /**
     * Given a size, extract commitment from x_0 to x_(size - 1) from the witness.
     * @param size an int64 integer.
     * @param witness a pointer of the R1CS witness.
     * @return a vector of extracted R1CS constraint.
     */
    static R1CSVec extract_commit_vector(int64_t size, BP_WITNESS* witness);
};
