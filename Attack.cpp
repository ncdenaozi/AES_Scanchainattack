#include "Attack.h"
#include <stdlib.h>
#include <time.h>

void Attack::FirstRoundOut(unsigned char * plaintext, unsigned char * key){
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
}

void Attack::RecoverRoundKey(){
    //implementation
}

void Attack::PrintResult(unsigned char a[], int size){
    //implementation
    cout<<"0x";
    for(auto i:RoundOneResult)
        cout<<hex<<(int)i;
    cout<<endl;
    
    for (int i = 0; i < size; i++)
    {
    	cout<<hex<<int(a[i]);
	}
	cout<<endl;
    
} 

