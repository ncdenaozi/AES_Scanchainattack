#ifndef _ATTACK_H_
#define _ATTACK_H_
#include "AES.h"
#include <bitset>
#include <utility>
#include <unordered_map>
#include <sstream>

using namespace std;

class Attack : public AES {
    public:
        vector<unsigned char> RoundOneResult;

        bitset<128> RandomizedResult;
        //Key
        unsigned char* key;
        //Hashtable bit-index -> first bit 1 and last bit 1 after xor
        unordered_map<int,pair<int,int>> FFtable; 

        Attack(AESKeyLength, unsigned char * input): AES(AESKeyLength::AES_128){
            RandomizedResult=0;
            key=input;
        };
        //Run the only pre-round + round1, store the result in RoundOneResult
        void FirstRoundOut(unsigned char * plaintext);
        
        /*Act like Hardware scan chain that output random-bit ordered
        128-bits round result*/
        void ScanChainOut(unsigned char * plaintext);

        //Step 1: determine 4 32-bits FF position
        void DetermineScanChainStructure();

        //Step 2: Recover Roundkey
        vector<unsigned char> RecoverRoundKey();

        //Output everything here
        void PrintResult();

        bitset<128> vec_to_Bitset(vector<unsigned char>);

        int count_ones_in_bitset(bitset<128>);  
};

#endif
