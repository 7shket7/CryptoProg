CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
TARGET = cipher

$(TARGET): cipher.cpp
	$(CXX) $(CXXFLAGS) cipher.cpp -o $(TARGET)

clean:
	rm -f $(TARGET) *.enc *.dec test_*

test: $(TARGET)
	echo "Это тестовое сообщение для проверки шифрования в режиме CBC!" > test.txt
	./$(TARGET)
