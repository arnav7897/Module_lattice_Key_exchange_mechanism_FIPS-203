#pragma once
#include "param.hpp"

#include<iostream>
#include<vector> 
#include <cstdint>

using namespace std;

vector<ui8> BitToByte(vector<bool> a);

vector<bool> ByteToBit(vector<ui8> a);

vector<ui8> ByteEncode(vector<int16_t> a, int d);

vector<int16_t> ByteDecode(vector<bool> a);