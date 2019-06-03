/*
 * @file challenge_bfvrns.cpp - PALISADE library.
 * @author  TPOC: palisade@njit.edu, jacobmas@gmail.com
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT), modified by Jacob Alperin-Sheriff, 2019
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
 * @section DESCRIPTION
 * Demo software for BFV multiparty operations.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>
#include <random>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "encoding/encodings.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

/** 
 * Make playing with parameters easier by reading them line by line from a file, if desired
 * 1st line: plaintext modulus
 * 2nd line: additive depth
 * 3rd line: multiplicative depth
 * 4th line: maximum depth
 * 5th line: batch size for efficient multiplication
 * 6th line: m from packing
 * 7th line: size of vectors 
 * 
 * Automatically sets multiplicative depth to 0 if both adds and mults are greater than 0
 */
void setChallengeParamsFromFile(char *fileName, int *plaintextModulus, unsigned int *numAdds, unsigned int *numMults, int *maxDepth,
				int *batchSize,usint *m, int *vec_size) {
    std::ifstream ifs;
    ifs.open(fileName, std::ifstream::in);
    if(!ifs.is_open()) return;
    ifs >> *plaintextModulus;
    ifs >> *numAdds;
    ifs >> *numMults;
    ifs >> *maxDepth;
    ifs >> *batchSize;
    ifs >> *m;
    ifs >> *vec_size;
    if(*numAdds&&*numMults) *numMults=0;
    return;
}

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	std::cout << "\nThis code solves the challenge problem using the BFVrns scheme. " << std::endl;
	std::cout << "Following the demo's code (demo-bfvrns.cpp), This code shows how to auto-generate parameters during "<<std::endl;
	std::cout << "run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we give a C++ prototype that uses the BFVrns scheme to efficiently evaluate " << std::endl;
	std::cout << " an inner product of two encrypted vectors, each with 10,000 integers randomly generated in the range of [-5,5]." << std::endl;

	std::cout << "Assumptions made on vague aspects of the challenge problem. " << std::endl;
	std::cout << "\t(A) The random vectors need not be generated via (a properly seeded with true randomness) CSPRNG, as " <<std::endl;
	std::cout << "\tpresumably they are being used only for some kind of data science machine-learning algorithm here." << std::endl;
	std::cout << "\n\n" << endl;

	//Standard iterator
	int i;
	
	//Hardcoded seed to ensure correctness for now



	//Generate hard-coded parameters, somewhat trial and error for what gives enough for hard-coded
	double diff, start, finish;
	unsigned int numAdds=0;
	unsigned int numMults=4;
	int maxDepth=6;

	int plaintextModulus = 536903681;
	double sigma = 4;
	double rootHermiteFactor = 1.006;

	// m for packing 
	usint m=53;
	int batchSize=10000;

	int vec_size=10000;

	std::random_device rd;

	int seed=rd();


	// Read in parameters from file if desired
	if(argc>=2) setChallengeParamsFromFile(argv[1],&plaintextModulus,&numAdds,&numMults,&maxDepth,&batchSize,&m,&vec_size);

	std::default_random_engine e1(seed);
	std::uniform_int_distribution<int64_t> uniform_dist(-5, 5);
	
	// Creating encoding parameters 
	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));
	PackedEncoding::SetParams(m, encodingParams);
	
	//Set Crypto Parameters, use encoding parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			encodingParams, rootHermiteFactor, sigma, numAdds, numMults, 0, OPTIMIZED,maxDepth);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "m = "<<m << std::endl;
	std::cout << "batchSize=" << batchSize << std::endl;
	std::cout << "vec_size=" << vec_size << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	//Create evaluation key vector to be used in keyswitching
	cryptoContext->EvalMultKeysGen(keyPair.secretKey);
	cryptoContext->EvalSumKeyGen(keyPair.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	
	std::vector<int64_t> vectorOfInts1={};//= {5,4,3,2,1,0,5,4,3,2,-1,-2,};
	std::vector<int64_t> vectorOfInts2={};//={2,3,-2,0,-1,-2,3,0,0,0,0,0};
	
	int64_t inner_prod=0;
	for(i=0;i<vec_size;i++) {
	    vectorOfInts1.push_back(uniform_dist(e1));
	    vectorOfInts2.push_back(uniform_dist(e1));
	}
	for(i=0;i<batchSize-vec_size;i++) {
	    vectorOfInts1.push_back(0);
	    vectorOfInts2.push_back(0);
	}
	
	//std::cout << vectorOfInts1 << std::endl;
	//std::cout << vectorOfInts2 << std::endl;

	for(i=0;i<vec_size;i++) {
	    inner_prod+=vectorOfInts1[i]*vectorOfInts2[i]; }
	
	

	Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
	Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);


	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	Ciphertext<DCRTPoly> ciphertext1;
	Ciphertext<DCRTPoly> ciphertext2;


	start = currentDateTime();

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);


	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintext1Dec;
	Plaintext plaintext2Dec;
	Plaintext plaintext3Dec;
	Plaintext plaintext4Dec;
	Plaintext plaintext5Dec;
	Plaintext plaintext6Dec;

	start = currentDateTime();


	cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintext1Dec);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintext2Dec);



	////////////////////////////////////////////////////////////
	// EvalMult Operation
	////////////////////////////////////////////////////////////

	Ciphertext<DCRTPoly> ciphertextInner;


	start = currentDateTime();
	//Perform consecutive multiplications and do a keyswtiching at the end.
	ciphertextInner     = cryptoContext->EvalInnerProduct(ciphertext1,ciphertext2,batchSize);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextInner, &plaintext3Dec);


	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMult time: " << "\t" << diff << " ms" << endl;

	cout << "\n Inner product computed: \n";
	cout << plaintext3Dec->GetPackedValue()[0] << endl;
	cout << "\n Inner product not homomorphically: \n";
	cout << inner_prod << std::endl;



	std::cout << "Execution Completed." << std::endl;

	return 0;
}
