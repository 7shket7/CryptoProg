#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

// Используем OpenSSL вместо Crypto++ - более стабильно
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

class AESCipher {
private:
    static const size_t KEY_SIZE = 32; // 256 бит для AES-256
    static const size_t IV_SIZE = 16;  // 128 бит для AES
    static const size_t SALT_SIZE = 8;
    
    vector<unsigned char> derive_key(const string& password, const unsigned char* salt) {
        vector<unsigned char> key(KEY_SIZE);
        
        if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                             salt, SALT_SIZE,
                             10000,  // iterations
                             EVP_sha256(),
                             KEY_SIZE, key.data()) != 1) {
            throw runtime_error("Ошибка генерации ключа из пароля");
        }
        
        return key;
    }
    
    void generate_random_bytes(unsigned char* buffer, size_t size) {
        if (RAND_bytes(buffer, size) != 1) {
            throw runtime_error("Ошибка генерации случайных чисел");
        }
    }
    
public:
    void encrypt_file(const string& input_file, const string& output_file, const string& password) {
        // Генерируем соль и IV
        unsigned char salt[SALT_SIZE];
        unsigned char iv[IV_SIZE];
        generate_random_bytes(salt, SALT_SIZE);
        generate_random_bytes(iv, IV_SIZE);
        
        // Производим ключ из пароля
        auto key = derive_key(password, salt);
        
        // Открываем файлы
        ifstream in(input_file, ios::binary);
        ofstream out(output_file, ios::binary);
        
        if (!in.is_open()) {
            throw runtime_error("Не удалось открыть входной файл: " + input_file);
        }
        if (!out.is_open()) {
            throw runtime_error("Не удалось открыть выходной файл: " + output_file);
        }
        
        // Записываем соль и IV в начало зашифрованного файла
        out.write(reinterpret_cast<char*>(salt), SALT_SIZE);
        out.write(reinterpret_cast<char*>(iv), IV_SIZE);
        
        // Настраиваем шифрование
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw runtime_error("Ошибка создания контекста шифрования");
        }
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Ошибка инициализации шифрования");
        }
        
        // Буферы для чтения/шифрования
        const size_t BUFFER_SIZE = 4096;
        unsigned char in_buf[BUFFER_SIZE];
        unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        
        int bytes_read, out_len;
        while ((bytes_read = in.read(reinterpret_cast<char*>(in_buf), BUFFER_SIZE).gcount()) > 0) {
            if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("Ошибка шифрования данных");
            }
            out.write(reinterpret_cast<char*>(out_buf), out_len);
        }
        
        // Финальный блок
        if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Ошибка финализации шифрования");
        }
        out.write(reinterpret_cast<char*>(out_buf), out_len);
        
        EVP_CIPHER_CTX_free(ctx);
    }
    
    void decrypt_file(const string& input_file, const string& output_file, const string& password) {
        // Открываем входной файл
        ifstream in(input_file, ios::binary);
        if (!in.is_open()) {
            throw runtime_error("Не удалось открыть входной файл: " + input_file);
        }
        
        // Читаем соль и IV из начала файла
        unsigned char salt[SALT_SIZE];
        unsigned char iv[IV_SIZE];
        
        in.read(reinterpret_cast<char*>(salt), SALT_SIZE);
        in.read(reinterpret_cast<char*>(iv), IV_SIZE);
        
        if (in.gcount() != SALT_SIZE + IV_SIZE) {
            throw runtime_error("Неверный формат зашифрованного файла");
        }
        
        // Производим ключ из пароля
        auto key = derive_key(password, salt);
        
        // Открываем выходной файл
        ofstream out(output_file, ios::binary);
        if (!out.is_open()) {
            throw runtime_error("Не удалось открыть выходной файл: " + output_file);
        }
        
        // Настраиваем дешифрование
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw runtime_error("Ошибка создания контекста дешифрования");
        }
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Ошибка инициализации дешифрования");
        }
        
        // Буферы для чтения/дешифрования
        const size_t BUFFER_SIZE = 4096;
        unsigned char in_buf[BUFFER_SIZE];
        unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        
        int bytes_read, out_len;
        while ((bytes_read = in.read(reinterpret_cast<char*>(in_buf), BUFFER_SIZE).gcount()) > 0) {
            if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("Ошибка дешифрования данных");
            }
            out.write(reinterpret_cast<char*>(out_buf), out_len);
        }
        
        // Финальный блок
        if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Ошибка финализации дешифрования. Возможно неверный пароль.");
        }
        out.write(reinterpret_cast<char*>(out_buf), out_len);
        
        EVP_CIPHER_CTX_free(ctx);
    }
};

void print_menu() {
    cout << "=== Программа шифрования/дешифрования AES-256-CBC ===" << endl;
    cout << "1. Зашифровать файл" << endl;
    cout << "2. Расшифровать файл" << endl;
    cout << "3. Выход" << endl;
    cout << "Выберите режим работы: ";
}

int main() {
    AESCipher cipher;
    int choice;
    
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    
    while (true) {
        print_menu();
        cin >> choice;
        cin.ignore(); // очистка буфера
        
        if (choice == 3) {
            cout << "Выход..." << endl;
            break;
        }
        
        if (choice != 1 && choice != 2) {
            cout << "Неверный выбор! Попробуйте снова." << endl;
            continue;
        }
        
        string input_file, output_file, password;
        
        cout << "Введите путь к исходному файлу: ";
        getline(cin, input_file);
        
        cout << "Введите путь для результирующего файла: ";
        getline(cin, output_file);
        
        cout << "Введите пароль: ";
        getline(cin, password);
        
        if (password.empty()) {
            cout << "Ошибка: пароль не может быть пустым!" << endl;
            continue;
        }
        
        try {
            if (choice == 1) {
                cipher.encrypt_file(input_file, output_file, password);
                cout << "Файл успешно зашифрован!" << endl;
                cout << "Зашифрованный файл: " << output_file << endl;
            } else {
                cipher.decrypt_file(input_file, output_file, password);
                cout << "Файл успешно расшифрован!" << endl;
                cout << "Расшифрованный файл: " << output_file << endl;
            }
        } catch (const exception& e) {
            cerr << "Ошибка: " << e.what() << endl;
        }
        
        cout << endl;
    }
    
    return 0;
}
