// (C) 2019 University of NKU. Free for used
// Author: stoneboat@mail.nankai.edu.cn

/*
 * client.cpp
 *
 */
#include<iostream>
#include"Client/client_core.h"

using namespace std;

/*
* For attestation part
*/
char debug = 0;
char verbose = 0;

int main(int argc, char** argv)
{
	/*
	*	Client side protocol start
	*/
    client_core(argc,(const char**) argv);
}


