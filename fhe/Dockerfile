FROM ubuntu:latest

# Update libraries.
RUN apt update && apt upgrade -y
# Install needed libraries.
RUN apt install -y git gdb wget cmake libssl-dev build-essential
# Clean up.
RUN apt clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Download SEAL and install it.
RUN wget https://github.com/microsoft/SEAL/archive/refs/tags/v4.1.2.tar.gz
RUN tar -zxvf v4.1.2.tar.gz
RUN cd SEAL-4.1.2 && cmake -S . -B build && cmake --build build && cmake --install build
