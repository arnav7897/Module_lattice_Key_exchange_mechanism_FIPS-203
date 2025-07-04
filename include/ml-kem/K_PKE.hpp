#pragma once
#include "param.hpp"
#include "base.hpp"
#include "ntt.hpp"
#include "sampling.hpp"
#include "hash.hpp"
#include <utility> 

pair<vector<ui8>,vector<ui8>> K_PKE_KeyGen(vector<ui8> &seed);

vector<ui8> K_PKE_Encrypt(vector<ui8> &public_key ,vector<ui8> &msg,vector<ui8> &random); 

vector<ui8> K_PKE_Decrypt(vector<ui8> &secret_key, vector<ui8> &c);