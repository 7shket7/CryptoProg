CXX = g++
CXXFLAGS = -std=c++11 -O2 -Wall
LIBS = -lssl -lcrypto
TARGET = cipher_app
SRC = cipher.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET) *.o *.enc *.dec test_*

test: $(TARGET)
	@echo "=== Тестирование шифрования ==="
	@echo "Создание тестового файла..."
	@echo "This is a secret message for encryption testing!" > test_original.txt
	@echo "Оригинальный файл создан: test_original.txt"
	@echo ""
	@echo "Шифрование..."
	@./$(TARGET) <<< $'1\ntest_original.txt\ntest_encrypted.enc\nmypassword123\n'
	@echo ""
	@echo "Дешифрование..."
	@./$(TARGET) <<< $'2\ntest_encrypted.enc\ntest_decrypted.txt\nmypassword123\n'
	@echo ""
	@echo "Сравнение файлов..."
	@if cmp test_original.txt test_decrypted.txt; then \
		echo "✅ Тест пройден! Файлы идентичны."; \
	else \
		echo "❌ Тест не пройден! Файлы различаются."; \
	fi

.PHONY: clean test
