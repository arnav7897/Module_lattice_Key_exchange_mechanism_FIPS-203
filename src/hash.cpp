#include <iostream>
#include <cstring>
#include "ml-kem/hash.hpp"

using namespace std;

int main() {
    const char* msg = "hello world";
    unsigned char hash[32];

    FIPS202_SHA3_256(reinterpret_cast<const unsigned char*>(msg), strlen(msg), hash);

    std::cout << "SHA3-256(\"" << msg << "\") = ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    return 0;
}
