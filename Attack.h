#ifndef _ATTACK_H_
#define _ATTACK_H_
#include "AES.h"

using namespace std;

class Attack : public AES {
    public:
        vector<unsigned char> RoundOneResult;
        vector<unsigned char> RandomizedResult;

        Attack(AESKeyLength): AES(AESKeyLength::AES_128){
        };
        //Run the only pre-round + round1, store the result in RoundOneResult
        void FirstRoundOut(unsigned char * plaintext, unsigned char * key);
        
        /*Act like Hardware scan chain that output random-bit ordered
        128-bits round result*/
        void ScanChainOut();

        //Step 1: determine 4 32-bits FF position
        void DetermineScanChainStructure();

        //Step 2: Recover Roundkey
        void RecoverRoundKey();

        //Output everything here
        void PrintResult();  
};

#endif
