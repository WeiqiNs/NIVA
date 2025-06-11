#include "fhe.hpp"

FHE::FHE(){
    // Set the degree of the "polynomial modulus".
    params_.set_poly_modulus_degree(32768);

    // Set the ciphertext "coefficient modulus".
    params_.set_coeff_modulus(CoeffModulus::BFVDefault(32768));

    constexpr uint64_t order = 534512;

    // The plaintext modulus needs to be set for the BFV scheme.
    params_.set_plain_modulus(order);

    // Create the context object from parameters.
    context_ = make_unique<SEALContext>(params_);

    // Create the KeyGenerator.
    const KeyGenerator keygen(*context_);
    // Create the secret key.
    sk_ = make_unique<SecretKey>(keygen.secret_key());
    // Create the public key.
    PublicKey pk;
    keygen.create_public_key(pk);
    pk_ = make_unique<PublicKey>(pk);

    // Initialize the encryptor, decryptor, and evaluator.
    encryptor_ = std::make_unique<Encryptor>(*context_, *pk_);
    decryptor_ = std::make_unique<Decryptor>(*context_, *sk_);
    evaluator_ = std::make_unique<Evaluator>(*context_);
}

PublicKey& FHE::get_pk() const{ return *pk_; }

Encryptor& FHE::get_encryptor() const{ return *encryptor_; }

Evaluator& FHE::get_evaluator() const{ return *evaluator_; }

Ciphertext FHE::add(const Ciphertext& x, const Ciphertext& y, const Evaluator& evaluator){
    Ciphertext result;
    evaluator.add(x, y, result);
    return result;
}

Ciphertext FHE::add(const Ciphertext& x, const Ciphertext& y) const{
    return add(x, y, *evaluator_);
}

Ciphertext FHE::add_plain(const Ciphertext& x, const uint64_t& y, const Evaluator& evaluator){
    Ciphertext result;
    evaluator.add_plain(x, Helper::uint64_to_hex_string(y), result);
    return result;
}

Ciphertext FHE::add_plain(const Ciphertext& x, const uint64_t& y) const{
    return add_plain(x, y, *evaluator_);
}

Ciphertext FHE::mul(const Ciphertext& x, const Ciphertext& y, const Evaluator& evaluator){
    Ciphertext result;
    evaluator.multiply(x, y, result);
    return result;
}

Ciphertext FHE::mul(const Ciphertext& x, const Ciphertext& y) const{
    return mul(x, y, *evaluator_);
}

Ciphertext FHE::mul_plain(const Ciphertext& x, const uint64_t& y, const Evaluator& evaluator){
    Ciphertext result;
    evaluator.multiply_plain(x, Helper::uint64_to_hex_string(y), result);
    return result;
}

Ciphertext FHE::mul_plain(const Ciphertext& x, const uint64_t& y) const{
    return mul_plain(x, y, *evaluator_);
}


Ciphertext FHE::encrypt(const uint64_t& plaintext, const Encryptor& encryptor){
    // Perform conversion and create the seal plaintext object.
    const Plaintext plain(Helper::uint64_to_hex_string(plaintext));

    // Declare the ciphertext result and perform encryption.
    Ciphertext result;
    encryptor.encrypt(plain, result);
    return result;
}

Ciphertext FHE::encrypt(const uint64_t& plaintext) const{
    return encrypt(plaintext, *encryptor_);
}

uint64_t FHE::decrypt(const Ciphertext& ciphertext) const{
    // Get the plaintext object and perform decryption.
    Plaintext result;
    decryptor_->decrypt(ciphertext, result);
    // Return a decrypted uint object.
    return Helper::hex_string_to_uint64(result.to_string());
}
