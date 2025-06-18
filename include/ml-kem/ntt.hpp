#pragma once

#include "param.hpp"

vector<i16> ntt(vector<i16> &f);
void invntt(vector<int16_t>& f);
vector<i16> poly_mul(vector<i16>& a,vector<i16>& b);