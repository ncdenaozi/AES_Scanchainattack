#include "Attack.h"

using namespace std;

int main(){
    unsigned char plain[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
    unsigned char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example

    Attack attk(AESKeyLength::AES_128,key);

    attk.FirstRoundOut(plain);

    bitset<128> temp=attk.vec_to_Bitset(attk.ArrayToVector(plain,16));
    cout<<temp<<endl;

    return 1;
}