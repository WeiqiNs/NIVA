#include <gtest/gtest.h>
#include "fhe.hpp"

TEST(FHETests, Encryption){
    // Set the value and the mod.
    constexpr uint64_t x = 100;

    // Perform the encryption.
    const FHE test;
    const Ciphertext ct = test.encrypt(x);

    // Perform testing.
    EXPECT_EQ(test.decrypt(ct), 100);
}

TEST(FHETests, Encryptor){
    // Set the value and the mod.
    constexpr uint64_t x = 100;

    // Perform the encryption using the encryptor.
    const FHE test;
    const Ciphertext ct = FHE::encrypt(x, test.get_encryptor());

    // Perform testing.
    EXPECT_EQ(test.decrypt(ct), 100);
}

TEST(FHETests, Add){
    // Set the value and the mod.
    constexpr uint64_t x = 100;
    constexpr uint64_t y = 200;

    // Encrypt two integers.
    const FHE test;
    const Ciphertext ctx = test.encrypt(x);
    const Ciphertext cty = test.encrypt(y);

    // Perform the addition.
    const Ciphertext r = test.add(ctx, cty);

    // Perform testing.
    EXPECT_EQ(test.decrypt(r), 300);
}

TEST(FHETests, AddPlain){
    // Set the value and the mod.
    constexpr uint64_t x = 100;

    // Encrypt two integers.
    const FHE test;
    const Ciphertext ctx = test.encrypt(x);

    // Perform the addition.
    const Ciphertext r = test.add_plain(ctx, 99);

    // Perform testing.
    EXPECT_EQ(test.decrypt(r), 199);
}

TEST(FHETests, Mul){
    // Set the value and the mod.
    constexpr uint64_t x = 100;
    constexpr uint64_t y = 200;

    // Encrypt two integers.
    const FHE test;
    const Ciphertext ctx = test.encrypt(x);
    const Ciphertext cty = test.encrypt(y);

    // Perform the addition.
    const Ciphertext r = test.mul(ctx, cty);

    // Perform testing.
    EXPECT_EQ(test.decrypt(r), 20000);
}

TEST(FHETests, MulPlain){
    // Set the value and the mod.
    constexpr uint64_t x = 100;

    // Encrypt two integers.
    const FHE test;
    const Ciphertext ctx = test.encrypt(x);

    // Perform the addition.
    const Ciphertext r = test.mul_plain(ctx, 99);

    // Perform testing.
    EXPECT_EQ(test.decrypt(r), 9900);
}

TEST(FHETests, Evaluator){
    // Set the value and the mod.
    constexpr uint64_t x = 100;
    constexpr uint64_t y = 200;

    // Encrypt two integers.
    const FHE test;
    const Ciphertext ctx = test.encrypt(x);
    const Ciphertext cty = test.encrypt(y);

    // Perform the addition using the evaluator.
    const Ciphertext r = FHE::add(ctx, cty, test.get_evaluator());

    // Perform testing.
    EXPECT_EQ(test.decrypt(r), 300);
}

TEST(FHETests, Time){
    const FHE test;
    constexpr int round = 200;
    constexpr uint64_t x = 100;
    const Ciphertext ctx = test.encrypt(x);

    // Create a random device
    std::random_device rd;

    // Initialize a Mersenne Twister pseudo-random number generator
    std::mt19937 gen(rd());

    // Define a range for the random integer
    std::uniform_int_distribution int_distribution(1, 100000);
    std::uniform_int_distribution<uint64_t> uint_distribution(1, 100000); // Generates integers from 1 to 100

    // Create holder for timings.
    std::chrono::duration<double, std::milli> time{};

    // Perform ROUND number of Mul Int.
    for (int i = 0; i < round; ++i){
        // Sample a random integer.
        int temp = int_distribution(gen);
        auto start = std::chrono::high_resolution_clock::now();
        std::ignore = test.mul_plain(ctx, temp);
        time += std::chrono::high_resolution_clock::now() - start;
    }

    std::cout << "Mul int time: " << time.count() / round << std::endl;

    time = std::chrono::duration<double, std::milli>::zero();

    // Perform ROUND number of Add.
    for (int i = 0; i < round; ++i){
        // Sample a random integer.
        uint64_t r = uint_distribution(gen);
        Ciphertext temp = test.encrypt(r);
        auto start = std::chrono::high_resolution_clock::now();
        std::ignore = test.add(ctx, temp);
        time += std::chrono::high_resolution_clock::now() - start;
    }

    std::cout << "Add time: " << time.count() / round << std::endl;

    time = std::chrono::duration<double, std::milli>::zero();

    // Perform ROUND number of Add.
    for (int i = 0; i < round; ++i){
        // Sample a random integer.
        uint64_t r = uint_distribution(gen);
        Ciphertext temp = test.encrypt(r);
        auto start = std::chrono::high_resolution_clock::now();
        std::ignore = test.mul(ctx, temp);
        time += std::chrono::high_resolution_clock::now() - start;
    }

    std::cout << "Mul time: " << time.count() / round << std::endl;
}