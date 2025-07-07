# 🔐 ML-KEM 512 — Minimal C++ Demo

This is a reference implementation of **ML-KEM-512** (formerly Kyber512), a post-quantum **Key Encapsulation Mechanism (KEM)** standardized by NIST in [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf).

It shows how **key generation**, **encapsulation**, and **decapsulation** work using ML-KEM, and helps understand the structure and magnitude of the ciphertexts, public and private keys, and shared secrets.

---

## 📖 What is ML-KEM?

**ML-KEM** stands for **Module Lattice-based Key Encapsulation Mechanism**. It is a quantum-resistant public key cryptographic primitive based on the **Learning With Errors (LWE)** problem over module lattices.

Key properties:
- IND-CCA2 secure (against adaptive chosen ciphertext attacks)
- Efficient key and ciphertext sizes
- Highly performant on embedded and web platforms

Kyber512 (ML-KEM-512) parameters:
| Component     | Size (bytes) |
|---------------|--------------|
| Public Key    | 800          |
| Secret Key    | 1632         |
| Ciphertext    | 768          |
| Shared Secret | 32           |

---

## ⚙️ Build and Run (WSL or Linux)

To build and run the demo:

```bash
# Clone or place this in your project root
mkdir build
cd build

\### Run CMake configuration
cmake ..

\### Compile the project
cmake --build .

\### Run the executable (generates KEM keypair, encapsulates & decapsulates)
./Test.exe

\### Run the individual function run KEM keypair generation
./mlkem-keygen
./mlkem-encaps public-key(hex)
./mlkem-decaps decaps_key(hex) cipher-text(hex)
 
```
