#pragma once

#include<iostream>
#include<cstdint>
#include<vector>
#include<cmath>

using namespace std;

typedef uint8_t ui8;
typedef unsigned long long int u64;
typedef unsigned int ui;
typedef int16_t i16;
typedef int32_t i32;

/** 
| Parameter Name         | ML-KEM-512   | ML-KEM-768   | ML-KEM-1024         |
| ---------------------- | ------------ | ------------ | ------------------- |
| **Security Level**     | NIST Level 1 | NIST Level 3 | NIST Level 5        |
| **n (poly degree)**    | 256          | 256          | 256                 |
| **q (modulus)**        | 3329         | 3329         | 3329                |
| **η (eta)**            | 2            | 2            | 2 (or 1 for noise2) |
| **k (matrix dim)**     | 2            | 3            | 4                   |
| **Symmetric security** | 128-bit      | 192-bit      | 256-bit             |



| Variant   | Public Key Size | Secret Key Size | Ciphertext Size |
| --------- | --------------- | --------------- | --------------- |
| Kyber512  | 800 bytes       | 1,632 bytes     | 768 bytes       |
| Kyber768  | 1,184 bytes     | 2,400 bytes     | 1,088 bytes     |
| Kyber1024 | 1,568 bytes     | 3,168 bytes     | 1,568 bytes     |

 H(𝑠) ∶= SHA3-256(𝑠) and J(𝑠) ∶= SHAKE256(𝑠,8⋅32)
 G ∶ 𝔹∗ → 𝔹32 × 𝔹32 sha-512

 Table 3: Parameters for the three instantiations of Kyber. The security of the three schemes
are approximately equivalent to that of AES-128, AES-192, and AES-256, respectively.
            k   η1  η2  du  dv  decryption error    pk size     ciphertext size
Kyber-512   2   3   2   10  4   2−139               800 B       768 B
Kyber-768   3   2   2   10  4   2−164               1184 B      1088 B
Kyber-1024  4   2   2   11  5   2−174               1568 B      1568 B

**/



#define Kyber_N 256
#define Kyber_Q 3329
#define eta1 3
#define eta2 2
#define Kyber_k 2 // for 512 implementation
#define du 10
#define dv 4

typedef struct{
    vector<i16> coeffs;
} poly; 
