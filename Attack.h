#include "AES.h"

class Attack : public AES {
    public:
        Attack(AESKeyLength): AES(AESKeyLength::AES_128){};
        
        /*Act like Hardware scan chain that output random-bit ordered
        128-bits round result*/
        string ScanChainOut();

        //Step 1: determine 4 32-bits FF position
        void DetermineScanChainStructure();

        //Step 2: Recover Roundkey
        void RecoverRoundKey();

        //Output everything here
        void PrintResult();  
};
