cmake_minimum_required(VERSION 3.28)

# Project name and language.
project(
        BulletProof
        VERSION 0.1
        LANGUAGES CXX
        DESCRIPTION "This library implements bulletproof for some circuits."
)

# Set language standards.
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable the testing.
enable_testing()

# Add desired subdirectories.
add_subdirectory(src)
add_subdirectory(test)
