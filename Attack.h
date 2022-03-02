#ifndef _ATTACK_H_
#define _ATTACK_H_
#include "AES.h"
#include <bitset>
#include <unordered_map>

using namespace std;

enum FlipFlops{
    FF1,
    FF2,
    FF3,
    FF4
};

class Attack : public AES {
    public:
        vector<unsigned char> RoundOneResult;
        vector<unsigned char> RandomizedResult;
        //Key
        unsigned char* key;
        //Hashtable bit-index -> Flip Flops index
        unordered_map<int,FlipFlops> FFtable; 

        Attack(AESKeyLength, unsigned char * input): AES(AESKeyLength::AES_128){
            key=input;
        };
        //Run the only pre-round + round1, store the result in RoundOneResult
        void FirstRoundOut(unsigned char * plaintext);
        
        /*Act like Hardware scan chain that output random-bit ordered
        128-bits round result*/
        void ScanChainOut(unsigned char a[], int n);

        //Step 1: determine 4 32-bits FF position
        void DetermineScanChainStructure();

        //Step 2: Recover Roundkey
        void RecoverRoundKey();

        //Output everything here
        void PrintResult();

        bitset<128> vec_to_Bitset(vector<unsigned char>);  
};

#endif
