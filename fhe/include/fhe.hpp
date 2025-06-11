#pragma once

#include <memory>
#include <seal/seal.h>
#include "helper.hpp"

using namespace seal;

class FHE{
public:
    /// Construct a new FHE instance with default encryption parameters and initialized components.
    FHE();

    /**
     * Get a reference to the public key.
     * @return Reference to the PublicKey object.
     */
    [[nodiscard]] PublicKey& get_pk() const;

    /**
     * Get a reference to the encryptor object.
     * @return Reference to the Encryptor object.
     */
    [[nodiscard]] Encryptor& get_encryptor() const;

    /**
     * Get a reference to the evaluator object.
     * @return Reference to the Evaluator object.
     */
    [[nodiscard]] Evaluator& get_evaluator() const;

    /**
     * Add two ciphertexts using the provided evaluator.
     * @param x The first ciphertext.
     * @param y The second ciphertext.
     * @param evaluator Evaluator to perform the addition.
     * @return Resulting Ciphertext after addition.
     */
    static Ciphertext add(const Ciphertext& x, const Ciphertext& y, const Evaluator& evaluator);

    /**
     * Add two ciphertexts using the internal evaluator.
     * @param x The first ciphertext.
     * @param y The second ciphertext.
     * @return Resulting Ciphertext after addition.
     */
    [[nodiscard]] Ciphertext add(const Ciphertext& x, const Ciphertext& y) const;

    /**
     * Add a plaintext value to a ciphertext using the provided evaluator.
     * @param x The ciphertext.
     * @param y The plaintext integer.
     * @param evaluator Evaluator to perform the addition.
     * @return Resulting Ciphertext after addition.
     */
    static Ciphertext add_plain(const Ciphertext& x, const uint64_t& y, const Evaluator& evaluator);

    /**
     * Add a plaintext value to a ciphertext using the internal evaluator.
     * @param x The ciphertext.
     * @param y The plaintext integer.
     * @return Resulting Ciphertext after addition.
     */
    [[nodiscard]] Ciphertext add_plain(const Ciphertext& x, const uint64_t& y) const;

    /**
     * Multiply two ciphertexts using the provided evaluator.
     * @param x The first ciphertext.
     * @param y The second ciphertext.
     * @param evaluator Evaluator to perform the multiplication.
     * @return Resulting Ciphertext after multiplication.
     */
    static Ciphertext mul(const Ciphertext& x, const Ciphertext& y, const Evaluator& evaluator);

    /**
     * Multiply two ciphertexts using the internal evaluator.
     * @param x The first ciphertext.
     * @param y The second ciphertext.
     * @return Resulting Ciphertext after multiplication.
     */
    [[nodiscard]] Ciphertext mul(const Ciphertext& x, const Ciphertext& y) const;

    /**
     * Multiply a ciphertext with a plaintext integer using the provided evaluator.
     * @param x The ciphertext.
     * @param y The plaintext integer.
     * @param evaluator Evaluator to perform the multiplication.
     * @return Resulting Ciphertext after multiplication.
     */
    static Ciphertext mul_plain(const Ciphertext& x, const uint64_t& y, const Evaluator& evaluator);

    /**
     * Multiply a ciphertext with a plaintext integer using the internal evaluator.
     * @param x The ciphertext.
     * @param y The plaintext integer.
     * @return Resulting Ciphertext after multiplication.
     */
    [[nodiscard]] Ciphertext mul_plain(const Ciphertext& x, const uint64_t& y) const;

    /**
     * Encrypt a plaintext integer using the provided encryptor.
     * @param plaintext The plaintext integer to encrypt.
     * @param encryptor Encryptor to use for encryption.
     * @return Resulting Ciphertext.
     */
    static Ciphertext encrypt(const uint64_t& plaintext, const Encryptor& encryptor);

    /**
     * Encrypt a plaintext integer using the internal encryptor.
     * @param plaintext The plaintext integer to encrypt.
     * @return Resulting Ciphertext.
     */
    [[nodiscard]] Ciphertext encrypt(const uint64_t& plaintext) const;

    /**
     * Decrypt a ciphertext to obtain the plaintext integer.
     * @param ciphertext The ciphertext to decrypt.
     * @return Decrypted plaintext integer.
     */
    [[nodiscard]] uint64_t decrypt(const Ciphertext& ciphertext) const;

private:
    // Declare the parameter variable, we use BFV scheme.
    EncryptionParameters params_ = EncryptionParameters(scheme_type::bfv);
    // Declare the pointers to hold initialized objects.
    shared_ptr<SecretKey> sk_;
    shared_ptr<PublicKey> pk_;
    shared_ptr<SEALContext> context_;
    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Decryptor> decryptor_;
    shared_ptr<Evaluator> evaluator_;
};
