#pragma once

#include "param.hpp"

using namespace std;

vector<ui8> BitToByte(vector<bool> &a);

vector<bool> ByteToBit(vector<ui8> &a);

vector<ui8> ByteEncode(vector<i16> &a, int d);

vector<i16> ByteDecode(vector<ui8> &a, int d);

vector<i16> Compress( vector<i16> &a, int d);

vector<i16> Decompress( vector<i16> &a, int d);