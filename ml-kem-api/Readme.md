# ML-KEM 512 on Web

This project demonstrates how **ML-KEM-512** (Kyber512, standardized in [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)) works on the web using a simple API interface.

---

## 🔐 Purpose

This implementation is designed **for educational and reference purposes**. It illustrates how ML-KEM operates, focusing on:

- Key generation
- Encapsulation and decapsulation
- Structure and size of ciphertexts and secret keys

---

## 🧠 Key Concepts

- **ML-KEM (Module-Lattice KEM)** is a quantum-safe key encapsulation mechanism.
- Based on **Kyber512**, this scheme offers a balance of performance and post-quantum security.
- All values are shown in their **raw hex/base64 form** to understand key sizes and data magnitude.

---

## 🚀 API Endpoints

The following endpoints simulate the full ML-KEM workflow:

### `GET /keygen`

- **Generates** a public and private key pair.
- Returns:
  - `publicKey` (Hex)
  - `secretKey` (Hex)

---

### `POST /encaps`

- Takes a `publicKey`
- Returns:
  - `ciphertext`: encapsulated value
  - `sharedSecret`: secret derived by the sender

---

### `POST /decaps`

- Takes:
  - `ciphertext`
  - `secretKey`
- Returns:
  - `sharedSecret`: secret derived by the receiver (should match sender’s)

---

## 📏 Size Overview (Kyber512 Parameters)

| Component     | Size (bytes) |
|---------------|--------------|
| Public Key    | 800          |
| Secret Key    | 1632         |
| Ciphertext    | 768          |
| Shared Secret | 32           |

---

## 📎 Notes

- ML-KEM-512 uses lattice-based cryptography and is IND-CCA2 secure.
- Encapsulation is non-deterministic: ciphertext changes each time, but shared secrets will match if decapsulated correctly.
- Ideal for client-server key exchange over insecure channels.

---

## 🛠️ Technologies Used

- **C++ Backend (Kyber)** — for core cryptographic operations
- **Node.js** (choose as applicable) — for exposing web endpoints
- **HTML** frontend — For now its reference or test of api further making it for actual use

---

## 📚 References

- [FIPS 203 - ML-KEM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)
- [Kyber GitHub Repository](https://github.com/pq-crystals/kyber)
- NIST Post-Quantum Cryptography Project

---

## 🧪 Test Cases

Use tools like **Postman** or **curl** to test the API:

```bash
curl -X POST http://localhost:3050/keygen
curl -X POST -d '{"publicKey": "..." }' http://localhost:3050/encaps
curl -X POST -d '{"ciphertext": "...", "secretKey": "..." }' http://localhost:3050/decaps
