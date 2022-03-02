#include "Attack.h"
#include <stdlib.h>
#include <time.h>

void Attack::FirstRoundOut(unsigned char * plaintext){
    //implementation
    unsigned char *out = new unsigned char[16];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    EncryptBlock(plaintext, out, roundKeys);

    unsigned char **state = new unsigned char *[4];
    state[0] = new unsigned char[4 * Nb];
    int i, j;
    for (i = 0; i < 4; i++)
        state[i] = state[0] + Nb * i;

    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++)
            state[i][j] = plaintext[i + 4 * j];

    //pre round
    AddRoundKey(state, roundKeys);
    //round 1
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKeys + 1 * 4 * Nb);

    /*
    for (j = 0; j < Nb; j++)
      for (i = 0; i < 4; i++)
        std::cout<<std::hex<<(int)state[i][j];
    std::cout<<std::endl;
    */

    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++)
      out[i + 4 * j] = state[i][j];

    delete[] state[0];
    delete[] state;

    vector<unsigned char> v = ArrayToVector(out, 16);
    RoundOneResult=v;
	//cout<<sizeof(v)<<endl;
    delete[] roundKeys;
}

void Attack::ScanChainOut(unsigned char a[], int size){
    //implementation
    int i, j; 
    unsigned char tmp;
    srand(time(NULL)); 
    for (i = 0; i < size; i++) 
    { 
        j = rand() % size; 
        tmp = a[i]; 
    	a[i] = a[j]; 
        a[j] = tmp;
    } 
	
    //RandomizedResult=RoundOneResult;
}

void Attack::DetermineScanChainStructure(){
    //implementation
    /*
    0000 0000 BASE
    0000 0001 1<<1
    .... ....
    1000 0000 1<<7
    */
    unsigned char ALLZERO[16];
    for(int x=0;x<16;x++)
        ALLZERO[x]=0;
    FirstRoundOut(ALLZERO);
    ScanChainOut();
    bitset<128> pivot=vec_to_Bitset(RandomizedResult);
    
    for(int i=0;i<128;i++){
        unsigned char input[16];
        //initialize
        for(int x=0;x<16;x++)
            input[x]=0;
        //generate bit-different input
        int byte_number=i/8;
        int bit_index=i%8;  //MSB 127 --- 0 LSB
        
        input[byte_number]=1<<bit_index;

        FirstRoundOut(input);
        ScanChainOut();
        bitset<128> temp=vec_to_Bitset(RandomizedResult);

        //FFtable[i]=FF1;
    }

}

void Attack::RecoverRoundKey(){
    //implementation
}

void Attack::PrintResult(){
    //implementation
    cout<<"0x";
    for(auto i:RoundOneResult)
        cout<<hex<<(int)i;
    cout<<endl;
}

bitset<128> Attack::vec_to_Bitset(vector<unsigned char> input){
    if(input.size()!=16)
        throw std::length_error("Not enough byte, should be 16 bytes");

    bitset<128> result;
    for(int i=15;i>0;i--)
        result|=(bitset<128>(input[i]))<<(8*(15-i));

    return result;
}

