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
        //an output register of a scan chain 
        vector<unsigned char> RoundOneResult;
        bitset<128> RandomizedResult;
        //current Key
        unsigned char* key;
        //Hashtable bit-index -> first bit 1 and last bit 1 after xor
        //unordered_map<int,pair<int,int>> FFtable; 
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
        //Debug print
        void PrintResult();
        //translate 16 char vector to 128-bit bitset
        bitset<128> vec_to_Bitset(vector<unsigned char>);
        // count number of ones in a 128-bit bitset
        int count_ones_in_bitset(bitset<128>);
        //assemble the key using a 16*2 option
        vector<unsigned char> assemble_key(vector<vector<unsigned char>>);  
};

#endif
