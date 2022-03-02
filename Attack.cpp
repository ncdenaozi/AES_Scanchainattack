#include "Attack.h"

void Attack::FirstRoundOut(unsigned char * plaintext){
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

void Attack::ScanChainOut(unsigned char * plaintext){
    FirstRoundOut(plaintext);
    bitset<128> plain=vec_to_Bitset(RoundOneResult);
    for(int i=0;i<128;i++)
        RandomizedResult[127-i]=plain[i];
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
    ScanChainOut(ALLZERO);
    bitset<128> pivot=RandomizedResult;
    
    for(int i=0;i<128;i++){
        unsigned char input[16];
        //initialize
        for(int x=0;x<16;x++)
            input[x]=0;
        //generate bit-different input
        int byte_number=i/8;
        int bit_index=i%8;  //MSB 127 --- 0 LSB
        
        input[byte_number]=1<<bit_index;

        ScanChainOut(input);
        bitset<128> current_input=RandomizedResult;
        bitset<128> difference=current_input^pivot;

        cout<<difference<<endl;

        //FFtable[i]=FF1;
    }

}

vector<unsigned char>  Attack::RecoverRoundKey(){
    vector<unsigned char> roundkey(16,0);

    for(int byte_count=0;byte_count<16;byte_count++){
        bool this_byte_find=false;
        for(uint8_t a_one=0;;a_one=a_one+2){
            if(!this_byte_find){
                unsigned char input[16];
                for(int x=0;x<16;x++)
                    input[x]=0;
                input[byte_count]=a_one;
                ScanChainOut(input);
                bitset<128> First_FF=RandomizedResult;

                unsigned char another_input[16];
                for(int x=0;x<16;x++)
                    another_input[x]=0;
                another_input[byte_count]=a_one+1;
                ScanChainOut(another_input);
                bitset<128> Second_FF=RandomizedResult;
            
                bitset<128> xor_result=First_FF ^ Second_FF;
                int number_of_ones=count_ones_in_bitset(xor_result);

                switch (number_of_ones){
                    case 9:{
                        cout<<(a_one^226)<<endl;
                        cout<<((a_one+1)^226)<<endl;
                        this_byte_find=true;
                    }
                    break;
                    case 12:{
                        cout<<(a_one^242)<<endl;
                        cout<<((a_one+1)^242)<<endl;
                        this_byte_find=true;
                    }
                    break;
                    case 23:{
                        cout<<(a_one^122)<<endl;
                        cout<<((a_one+1)^122)<<endl;
                        this_byte_find=true;
                    }
                    break;
                    case 24:{
                        cout<<(a_one^130)<<endl;
                        cout<<((a_one+1)^130)<<endl;
                        this_byte_find=true;
                    }
                    break;            
                    default:break;
                }
            }else
                break;
        }
    }

    return roundkey;
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

int Attack::count_ones_in_bitset(bitset<128> input){
    int result=0;
    for(int i=0;i<128;i++){
        if(input[i]==true)
            result++;
    }
    return result;
}

