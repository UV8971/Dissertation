# Hybrid Post-Quantum Signal Protocol (PQXDH) with FrodoKEM (Python)

This repository contains a proof-of-concept implementation of a hybrid post-quantum key exchange and messaging protocol, inspired by the Signal Protocol. The implementation combines the classical X3DH key exchange with the post-quantum key encapsulation mechanism (KEM), **FrodoKEM-640-AES**, to provide forward secrecy and post-compromise security against both classical and quantum adversaries.

The project also includes functional tests to verify the correctness of the cryptographic primitives and a benchmarking suite to analyze the performance and memory overhead of the post-quantum components.

## License

MIT License

Copyright (c) Microsoft Corporation. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

## Features

-   **Hybrid X3DH/PQXDH Key Exchange**: Combines classical Curve25519 with post-quantum FrodoKEM-640-AES.
-   **Hybrid Double Ratchet**: Implements a session-based key evolution mechanism for ongoing conversations, ensuring forward secrecy and post-compromise security.
-   **Key Derivation**: Uses a robust HKDF (HMAC-based Key Derivation Function) with SHA-256.
-   **Authenticated Encryption**: Employs AES-256-GCM for message encryption.
-   **Functional Tests**: Includes a suite of tests to verify the correctness of HKDF, prekey bundle generation, session setup, and the end-to-end message flow.
-   **Benchmarking**: Measures the time and memory consumption of key generation, session setup, and message encryption/decryption.

## FrodoKEM's official source code

For a complete and reproducible implementation of the cryptographic protocols discussed, you can clone the source code from the official GitHub repository. The repository contains the full code, including the functional tests and benchmarking suite, allowing you to run the analysis yourself individually.

You can clone the repository using the following command:
```bash
git clone https://github.com/microsoft/PQCrypto-LWEKE.git
```
## Prerequisites


The project requires the following Python libraries / requirements. Copy them as it is and save it in a file named "requirements.txt". 

Based on the provided Python code, here are the required packages for a "requirements.txt" file, and a snippet for installing them with pip.

### requirements.txt
PyNaCl

cryptography



## Installation Snippet
You can install all the required packages at once by running the following command in your terminal, assuming you have saved the above content as a file named requirements.txt:

```Bash
pip install -r requirements.txt
```

## How to Run
To run the script, simply execute the Python file from your terminal:

```Bash
python multi.py
```
The script will first run a series of functional tests to ensure the protocol works correctly. If all tests pass, it will then proceed to perform a benchmark run and save the results to a CSV file.

## Code Structure
The script is organized into the following sections:

**UTILITY FUNCTIONS**: Helper functions for key printing and HKDF.

**PREKEY BUNDLE**: generate_prekey_bundle() creates a full set of prekeys for a user.

**HYBRID X3DH/PQXDH SESSION SETUP**: session_setup() performs the initial key agreement between two parties.

**HYBRID DOUBLE RATCHET**: The HybridDoubleRatchet class manages the state and provides encrypt() and decrypt() methods.

**FUNCTIONAL TESTS**: A series of test functions that verify core protocol functionality.

**MAIN DEMO WITH BENCHMARKING**: The main execution block that runs the tests and then performs a benchmark for a specified number of iterations.

## Output
When you run the script, it will print detailed information about the keys being generated and the cryptographic steps being performed in the terminal. After the tests, the benchmarking phase will save the performance and memory metrics to a CSV file named pq_x3dh_benchmark_results.csv in the same directory.