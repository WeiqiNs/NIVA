FROM ubuntu:latest

# Update libraries.
RUN apt update && apt upgrade -y
# Install needed libraries.
RUN apt install -y perl libtext-template-perl git build-essential gdb cmake libgtest-dev

# Clone the Tongsuo Library.
RUN git clone https://github.com/Tongsuo-Project/Tongsuo.git
WORKDIR /Tongsuo
RUN git checkout 8.4-stable
# Configure the library and enable some features.
RUN ./config --prefix=/opt/tongsuo \
    enable-nizk \
    enable-paillier \
    enable-ec_elgamal \
    enable-zkp-gadget \
    enable-bulletproofs \
    enable-twisted_ec_elgamal
# Make and install the library.
RUN make && make install
