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
    //ALLZERO_ScanChainOut=RandomizedResult;
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
    
    vector<vector<unsigned char>> alloptions;
    
    for(int byte_count=0;byte_count<16;byte_count++){
        vector<unsigned char> this_byte_option(2);
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
                        cout<<"Byte Location: "<<dec<<byte_count<<", Input Byte is "<<hex<<(int)a_one<<endl;
                        cout<<"Input plaintext is "<<vec_to_Bitset(ArrayToVector(input,16))<<endl;
                        cout<<"First Byte Option: "<<(a_one^226)<<", Second Byte Option: "<<(a_one^227)<<endl;
                        this_byte_option[0]=(a_one^226);
                        this_byte_option[1]=(a_one^227);
                        this_byte_find=true;
                    }
                    break;
                    case 12:{
                        cout<<"Byte Location: "<<dec<<byte_count<<", Input Byte is "<<hex<<(int)a_one<<endl;
                        cout<<"Input plaintext is "<<vec_to_Bitset(ArrayToVector(input,16))<<endl;
                        cout<<"First Byte Option: "<<(a_one^242)<<", Second Byte Option: "<<(a_one^243)<<endl;
                        this_byte_option[0]=(a_one^242);
                        this_byte_option[1]=(a_one^243);
                        this_byte_find=true;
                    }
                    break;
                    case 23:{
                        cout<<"Byte Location: "<<dec<<byte_count<<", Input Byte is "<<hex<<(int)a_one<<endl;
                        cout<<"Input plaintext is "<<vec_to_Bitset(ArrayToVector(input,16))<<endl;
                        cout<<"First Byte Option: "<<(a_one^122)<<", Second Byte Option: "<<(a_one^123)<<endl;
                        this_byte_option[0]=(a_one^122);
                        this_byte_option[1]=(a_one^123);
                        this_byte_find=true;
                    }
                    break;
                    case 24:{
                        cout<<"Byte Location: "<<dec<<byte_count<<", Input Byte is "<<hex<<(int)a_one<<endl;
                        cout<<"Input plaintext is "<<vec_to_Bitset(ArrayToVector(input,16))<<endl;
                        cout<<"First Byte Option: "<<(a_one^130)<<", Second Byte Option: "<<(a_one^131)<<endl;
                        this_byte_option[0]=(a_one^130);
                        this_byte_option[1]=(a_one^131);
                        this_byte_find=true;
                    }
                    break;            
                    default:break;
                }
            }else{
                break;
            }
                
        }
        alloptions.push_back(this_byte_option);
    }
    /*
    for(int index=0;index<alloptions.size();index++){
        cout<<"Bit location "<<index<<" --";
        for(auto j:alloptions[index])
            cout<<hex<<(int)j<<"--";
        cout<<endl;
    }
    */

    roundkey=assemble_key(alloptions);
    
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
    result|= bitset<128>(input[0]) <<120;
    result|= bitset<128>(input[1]) <<112;
    result|= bitset<128>(input[2]) <<104;
    result|= bitset<128>(input[3]) <<96;
    result|= bitset<128>(input[4]) <<88;
    result|= bitset<128>(input[5]) <<80;
    result|= bitset<128>(input[6]) <<72;
    result|= bitset<128>(input[7]) <<64;
    result|= bitset<128>(input[8]) <<56;
    result|= bitset<128>(input[9]) <<48;
    result|= bitset<128>(input[10]) <<40;
    result|= bitset<128>(input[11]) <<32;
    result|= bitset<128>(input[12]) <<24;
    result|= bitset<128>(input[13]) <<16;
    result|= bitset<128>(input[14]) <<8;
    result|= bitset<128>(input[15]) ;
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

vector<unsigned char> Attack::assemble_key(vector<vector<unsigned char>> all_option){
    /*
    for(int index=0;index<all_option.size();index++){
        cout<<"Bit location "<<index<<" --";
        for(auto j:all_option[index])
            cout<<(int)j<<"--";
        cout<<endl;
    }*/

    //store allzero scanchain in ALLZERO_ScanChainOut
    unsigned char ALLZERO[16];
    for(int x=0;x<16;x++)
        ALLZERO[x]=0;
    ScanChainOut(ALLZERO);
    bitset<128> ALLZERO_ScanChainOut=RandomizedResult;
    bitset<128> ALLZERO_FirstRoundOut=vec_to_Bitset(RoundOneResult);
    
    vector<unsigned char> final_key(16);
    long mask=0;
    while(mask<pow(2,16)){
        unsigned char current_key[16];
        for(int index=0;index<all_option.size();index++)
            current_key[index]=all_option[index][(mask>>(15-index))&1];
        
        Attack* temp_attack=new Attack(AESKeyLength::AES_128,current_key);
        temp_attack->ScanChainOut(ALLZERO);
        
        if(temp_attack->RandomizedResult==ALLZERO_ScanChainOut){
            //cout<<vec_to_Bitset(ArrayToVector(current_key,16))<<endl;
            final_key=ArrayToVector(current_key,16);
            break;
        }
        
        mask++;
        delete temp_attack;
    }

    cout<<"Round Key Zero is: ";
    for(auto b:final_key)
        cout<<"0x"<<hex<<(int)b<<", ";
    cout<<endl;

    return final_key;
}
