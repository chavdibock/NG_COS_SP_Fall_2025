#pragma once
#include "BaseAlgo.h"
class OcSvm : public BaseAlgo
{
public:
	OcSvm(int, double, int);
	
private:
	int c;
};
