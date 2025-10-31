#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

using namespace std;

string calculate_file_hash_openssl(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось открыть файл: " + filename);
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Update(&sha256, buffer, file.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    // Конвертируем в hex строку
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << setw(2) << static_cast<unsigned>(hash[i]);
    }

    return ss.str();
}

// Версия с Crypto++ (альтернативный подход)
#ifdef USE_CRYPTOPP
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>

string calculate_file_hash_cryptopp(const string& filename) {
    using namespace CryptoPP;
    
    SHA256 hash;
    string digest;
    
    try {
        FileSource file(filename.c_str(), true, 
                       new HashFilter(hash,
                                     new HexEncoder(
                                     new StringSink(digest))));
        return digest;
    } catch(const Exception& e) {
        throw runtime_error("Crypto++ error: " + string(e.what()));
    }
}
#endif

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Использование: " << argv[0] << " <filename>" << endl;
        cout << "Пример: " << argv[0] << " document.txt" << endl;
        return 1;
    }
    
    string filename = argv[1];
    
    try {
        string file_hash = calculate_file_hash_openssl(filename);
        cout << "SHA-256 хэш файла '" << filename << "':" << endl;
        cout << file_hash << endl;
    } catch(const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
