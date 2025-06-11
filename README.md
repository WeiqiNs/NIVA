# Non-Interactive Verifiable Aggregation
This repository contains code supporting the [Non-Interactive Verifiable Aggregation](https://eprint.iacr.org/2025/420) paper.
## Codebase Design
```
project/
├── README.md
├── pear/
│   ├── ipfe/
│   └── flpcp/
└──  bulletproof/
```
- `pear/`: Contains python code for the proposed `PEAR` system, which integrates FLPCP from 
  [Boneh et al. (2019)](https://eprint.iacr.org/2019/188.pdf) and IPFE from [Castagnos et al. (2018)](https://eprint.iacr.org/2018/791.pdf).
- `bulletproof/`: Includes code used to benchmark a naive construction based on Bulletproofs.

## Running the PEAR Codebase
Python 3.8 or above and the [sage](https://www.sagemath.org) library are required.
The installation guide of sage can be found [here](https://doc.sagemath.org/html/en/installation/index.html).

### (Optional) Install development dependencies
If you wish to run the test suite:
```bash
pip install -r dev-requirements.txt
```
This includes pytest. To execute all tests from the root directory:
```bash
pytest --verbose
``` 

## Running the Bulletproof Codebase
Cmake and the [Tongsuo library](https://github.com/Tongsuo-Project/Tongsuo) are required. 
You can refer to the `Dockerfile` under `bulletproof/` for a reference of how to install the library.

To build the project:
```bash
cmake -B build -S . && cmake --build build --parallel
```
To run the tests:
```bash
ctest
```