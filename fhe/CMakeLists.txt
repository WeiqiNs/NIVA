# Set cmake version.
cmake_minimum_required(VERSION 3.20)

# Project name and language.
project(
        SealFHE
        VERSION 0.1
        DESCRIPTION "This project implements a FHE protocol using Microsoft SEAL."
        LANGUAGES CXX
)

# Set standards.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable the testing.
enable_testing()

# Find required libraries.
find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SEAL 4.1.2 EXACT REQUIRED)

# Add desired subdirectories.
add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(experiment)
