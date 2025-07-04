#pragma once

#include "K_PKE.hpp"

pair<vector<ui8>,vector<ui8>> ML_KEM_KEYGEN();

pair<vector<ui8>,vector<ui8>> ML_KEM_ENCAPSULATION(vector<ui8> &public_key); 

vector<ui8> ML_KEM_DECAPSULATION(vector<ui8> &decaps, vector<ui8> &c);