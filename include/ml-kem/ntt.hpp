#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "param.hpp"

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16

int16_t montgomery_reduce(int32_t a);

int16_t barrett_reduce(int16_t a);

extern const int16_t zetas[128];

void ntt(vector<int16_t> &poly);

vector<i16> poly_multiply_pointwise_mont(vector<i16> &a, vector<i16> & b);

int16_t fqmul(int16_t a, int16_t b);

void invntt(vector<int16_t> &poly);

void basemul(i16* r, i16* a, i16* b, i16 zeta);

void poly_reduce(vector<i16> & a);

vector<i16> poly_add(vector<i16> &a , vector<i16> &b);

void poly_tomont(vector<i16> &r);

#endif