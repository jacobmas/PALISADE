/*
 * @file utilities.cpp This file contains the utility function functionality.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */ 

#include "utilities.h"

namespace lbcrypto {

//Zero-Padd adds extra zeros to the Input polynomial
//if Input polynomial has a length n less than CycloOrder,
//then it adds CycloOrder-n zeros in the Input Polynomial
BigVector ZeroPadForward(const BigVector &InputPoly,usint target_order){

	if(InputPoly.GetLength()<target_order){

		BigVector ans(target_order);

		for(usint i=0;i<InputPoly.GetLength();i++)
			ans.SetValAtIndex(i,InputPoly.GetValAtIndex(i));

		for(usint i=InputPoly.GetLength();i<target_order;i++)
			ans.SetValAtIndex(i, BigInteger(0));

		ans.SetModulus(InputPoly.GetModulus());

	    return ans;

	}

	else{
		return BigVector(InputPoly);
	}
}

//Adds 0 between each BigInteger to support conversion from Inverse FFT to Inverse CRT
BigVector ZeroPadInverse(const BigVector &InputPoly,usint target_order){

	if(InputPoly.GetLength()<target_order){

		BigVector ans(target_order);

		for(usint i=0;i<InputPoly.GetLength();i++)
		{
			ans.SetValAtIndex(2*i,BigInteger("0"));
			ans.SetValAtIndex(2*i+1,InputPoly.GetValAtIndex(i));
		}

		ans.SetModulus(InputPoly.GetModulus());

	    return ans;
	}

	else{
		return BigVector(InputPoly);
	}

}

bool IsPowerOfTwo(usint Input){
	usint tm = 1;
	bool ans = false;
	while(tm<=Input){
		if((tm-Input)==0){
			ans = true;
			break;
		}
		tm <<=1;
	}

	return ans;
}

// auxiliary function to replace a specific character "in" with another character "out"
std::string replaceChar(std::string str, char in, char out) {

  // set our locator equal to the first appearance of any character in replace
  size_t found = str.find_first_of(in);

  while (found != std::string::npos) { // While our position in the sting is in range.
    str[found] = out; // Change the character at position.
    found = str.find_first_of(in, found+1); // Relocate again.
  }

  return str; // return our new string.
}

}//namespace ends here