#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

// Функция для вывода помощи
void printHelp() {
    cout << "Использование: cipher [options]" << endl;
    cout << endl;
    cout << "Опции:" << endl;
    cout << "  -h, --help          Показать эту справку" << endl;
    cout << "  -e, --encrypt       Режим шифрования" << endl;
    cout << "  -d, --decrypt       Режим дешифрования" << endl;
    cout << "  -i, --input         Входной файл" << endl;
    cout << "  -o, --output        Выходной файл" << endl;
    cout << "  -p, --password      Пароль" << endl;
    cout << endl;
    cout << "Примеры:" << endl;
    cout << "  cipher -e -i data.txt -o encrypted.bin -p \"my password\"" << endl;
    cout << "  cipher -d -i encrypted.bin -o decrypted.txt -p \"my password\"" << endl;
    cout << endl;
    cout << "Алгоритм: AES-256-CBC" << endl;
}

// Функция для генерации ключа и IV из пароля
void deriveKeyAndIV(const string& password, byte* key, byte* iv) {
    // Соль для PBKDF2
    byte salt[] = {0x73, 0x61, 0x6C, 0x74, 0x56, 0x61, 0x6C, 0x75};
    
    // Генерация ключа с помощью PBKDF2
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, AES::DEFAULT_KEYLENGTH, 0, 
                   (byte*)password.data(), password.size(),
                   salt, sizeof(salt), 10000);
    
    // Генерация IV из хеша пароля
    SHA256 hash;
    hash.CalculateDigest(iv, (byte*)password.data(), password.size());
}

// Функция шифрования
bool encryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Проверка существования входного файла
        ifstream test(inputFile, ios::binary);
        if (!test) {
            cerr << "Ошибка: Входной файл не существует: " << inputFile << endl;
            return false;
        }
        test.close();

        // Генерация ключа и IV
        byte key[AES::DEFAULT_KEYLENGTH];
        byte iv[AES::BLOCKSIZE];
        deriveKeyAndIV(password, key, iv);
        
        // Настройка шифрования AES-CBC
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        
        // Шифрование
        FileSource fs(inputFile.c_str(), true,
            new StreamTransformationFilter(encryption,
                new FileSink(outputFile.c_str())
            )
        );
        
        cout << "Успешно зашифрован: " << inputFile << " -> " << outputFile << endl;
        return true;
        
    } catch(const Exception& e) {
        cerr << "Ошибка шифрования: " << e.what() << endl;
        return false;
    }
}

// Функция дешифрования
bool decryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Проверка существования входного файла
        ifstream test(inputFile, ios::binary);
        if (!test) {
            cerr << "Ошибка: Входной файл не существует: " << inputFile << endl;
            return false;
        }
        test.close();

        // Генерация ключа и IV
        byte key[AES::DEFAULT_KEYLENGTH];
        byte iv[AES::BLOCKSIZE];
        deriveKeyAndIV(password, key, iv);
        
        // Настройка дешифрования AES-CBC
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        
        // Дешифрование
        FileSource fs(inputFile.c_str(), true,
            new StreamTransformationFilter(decryption,
                new FileSink(outputFile.c_str())
            )
        );
        
        cout << "Успешно расшифрован: " << inputFile << " -> " << outputFile << endl;
        return true;
        
    } catch(const Exception& e) {
        cerr << "Ошибка дешифрования: " << e.what() << endl;
        return false;
    }
}

// Функция парсинга аргументов командной строки
bool parseArguments(int argc, char* argv[], string& mode, string& inputFile, 
                   string& outputFile, string& password) {
    
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printHelp();
            return false;
        }
        else if ((arg == "-e" || arg == "--encrypt") && mode.empty()) {
            mode = "encrypt";
        }
        else if ((arg == "-d" || arg == "--decrypt") && mode.empty()) {
            mode = "decrypt";
        }
        else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            inputFile = argv[++i];
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            outputFile = argv[++i];
        }
        else if ((arg == "-p" || arg == "--password") && i + 1 < argc) {
            password = argv[++i];
        }
        else {
            // Если аргумент не распознан, предполагаем что это режим по умолчанию
            if (mode.empty()) {
                if (arg == "encrypt" || arg == "e") {
                    mode = "encrypt";
                } else if (arg == "decrypt" || arg == "d") {
                    mode = "decrypt";
                } else {
                    cerr << "Неизвестный аргумент: " << arg << endl;
                    return false;
                }
            }
            // Или пытаемся определить что это за параметр по позиции
            else if (inputFile.empty()) {
                inputFile = arg;
            }
            else if (outputFile.empty()) {
                outputFile = arg;
            }
            else if (password.empty()) {
                password = arg;
            }
        }
    }
    
    // Проверка обязательных параметров
    if (mode.empty()) {
        cerr << "Ошибка: Не указан режим работы (шифрование/дешифрование)" << endl;
        return false;
    }
    
    if (inputFile.empty()) {
        cerr << "Ошибка: Не указан входной файл" << endl;
        return false;
    }
    
    if (outputFile.empty()) {
        cerr << "Ошибка: Не указан выходной файл" << endl;
        return false;
    }
    
    if (password.empty()) {
        cerr << "Ошибка: Не указан пароль" << endl;
        return false;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    // Установка локализации
    setlocale(LC_ALL, "ru_RU.UTF-8");
    
    // Если нет аргументов, показываем справку
    if (argc == 1) {
        printHelp();
        return 0;
    }
    
    string mode, inputFile, outputFile, password;
    
    // Парсинг аргументов
    if (!parseArguments(argc, argv, mode, inputFile, outputFile, password)) {
        return 1;
    }
    
    // Проверка что входной и выходной файлы разные
    if (inputFile == outputFile) {
        cerr << "Ошибка: Входной и выходной файлы не могут быть одинаковыми" << endl;
        return 1;
    }
    
    // Выполнение операции
    bool success = false;
    if (mode == "encrypt") {
        success = encryptFile(inputFile, outputFile, password);
    } else {
        success = decryptFile(inputFile, outputFile, password);
    }
    
    return success ? 0 : 1;
}
