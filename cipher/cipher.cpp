#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>

using namespace std;

const size_t BLOCK_SIZE = 16;

vector<char> generateIV() {
    vector<char> iv(BLOCK_SIZE);
    random_device rd;
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        iv[i] = static_cast<char>(rd() % 256);
    }
    return iv;
}

void cbcEncrypt(const string& inputFile, const string& outputFile, const string& password) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);
    
    if (!in || !out) {
        cout << "Ошибка открытия файлов!" << endl;
        return;
    }
    
    vector<char> iv = generateIV();
    out.write(iv.data(), BLOCK_SIZE);
    
    vector<char> prevBlock = iv;
    vector<char> buffer(BLOCK_SIZE);
    
    while (in.read(buffer.data(), BLOCK_SIZE)) {
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            buffer[i] ^= prevBlock[i];
        }
        
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            buffer[i] ^= password[i % password.size()];
        }
        
        out.write(buffer.data(), BLOCK_SIZE);
        prevBlock = buffer;
    }
    
    // Обработка последнего неполного блока
    size_t bytesRead = in.gcount();
    if (bytesRead > 0) {
        // Дополняем блок
        char padding = BLOCK_SIZE - bytesRead;
        for (size_t i = bytesRead; i < BLOCK_SIZE; i++) {
            buffer[i] = padding;
        }
        
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            buffer[i] ^= prevBlock[i];
        }
        
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            buffer[i] ^= password[i % password.size()];
        }
        
        out.write(buffer.data(), BLOCK_SIZE);
    }
    
    cout << "Файл зашифрован: " << outputFile << endl;
}

void cbcDecrypt(const string& inputFile, const string& outputFile, const string& password) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);
    
    if (!in || !out) {
        cout << "Ошибка открытия файлов!" << endl;
        return;
    }
    
    vector<char> iv(BLOCK_SIZE);
    in.read(iv.data(), BLOCK_SIZE);
    
    vector<char> prevBlock = iv;
    vector<char> buffer(BLOCK_SIZE);
    vector<char> encryptedBlock(BLOCK_SIZE);
    
    in.seekg(0, ios::end);
    streamsize fileSize = in.tellg();
    in.seekg(BLOCK_SIZE, ios::beg);
    
    streamsize bytesLeft = fileSize - BLOCK_SIZE;
    
    while (bytesLeft > 0) {
        streamsize bytesToRead = (bytesLeft >= static_cast<streamsize>(BLOCK_SIZE)) ? BLOCK_SIZE : bytesLeft;
        in.read(buffer.data(), bytesToRead);
        
        // Сохраняем зашифрованную версию для следующего блока
        encryptedBlock = buffer;
        
        // Дешифрование с паролем
        for (size_t i = 0; i < static_cast<size_t>(bytesToRead); i++) {
            buffer[i] ^= password[i % password.size()];
        }
       
        for (size_t i = 0; i < static_cast<size_t>(bytesToRead); i++) {
            buffer[i] ^= prevBlock[i];
        }
        
        // Если это последний блок, убираем дополнение
        if (bytesLeft <= static_cast<streamsize>(BLOCK_SIZE)) {
            char padding = buffer[bytesToRead - 1];
            // Проверяем корректность padding
            if (padding > 0 && padding <= static_cast<char>(BLOCK_SIZE)) {
                out.write(buffer.data(), bytesToRead - padding);
            } else {
                out.write(buffer.data(), bytesToRead);
            }
        } else {
            out.write(buffer.data(), bytesToRead);
        }
        
        prevBlock = encryptedBlock;
        bytesLeft -= bytesToRead;
    }
    
    cout << "Файл расшифрован: " << outputFile << endl;
}

int main() {
    
    while (true) {
        cout << "1 - Шифровать файл" << endl;
        cout << "2 - Дешифровать файл" << endl;
        cout << "3 - Выход" << endl;
        cout << "Выберите: ";
        
        int choice;
        cin >> choice;
        cin.ignore();
        
        if (choice == 3) {
            cout << "Выход." << endl;
            break;
        }
        
        if (choice != 1 && choice != 2) {
            cout << "Неверный выбор!" << endl;
            continue;
        }
        
        string inputFile, outputFile, password;
        
        cout << "Входной файл: ";
        getline(cin, inputFile);
        
        cout << "Выходной файл: ";
        getline(cin, outputFile);
        
        cout << "Пароль: ";
        getline(cin, password);
        
        if (password.empty()) {
            cout << "Пароль не может быть пустым!" << endl;
            continue;
        }
        
        if (choice == 1) {
            cbcEncrypt(inputFile, outputFile, password);
        } else {
            cbcDecrypt(inputFile, outputFile, password);
        }
    }
    
    return 0;
}
