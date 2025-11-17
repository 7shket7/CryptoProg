#include <iostream>
#include <fstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Использование: " << argv[0] << " <файл>" << endl;
        return 1;
    }

    string filename = argv[1];
    
    ifstream file(filename);
    if (!file) {
        cout << "Ошибка: файл не найден" << endl;
        return 1;
    }
    file.close();

    try {
        SHA256 hash;
        string digest;
        
        FileSource(filename.c_str(), true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );

        cout << "SHA-256: " << digest << endl;
        
    } catch(const exception& e) {
        cout << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}
