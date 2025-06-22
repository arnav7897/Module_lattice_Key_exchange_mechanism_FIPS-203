#pragma once

#include "param.hpp"
#include "hash.hpp"
#include "base.hpp"
#include "ntt.hpp"

using namespace std;

vector<i16> NTT_sample(vector<ui8> &random, ui8 i ,ui8 j);

vector<i16> Binomial_sample(vector<ui8> &random , int eta);