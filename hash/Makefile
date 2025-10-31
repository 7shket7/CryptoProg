CXX = g++
CXXFLAGS = -std=c++11 -O2
LIBS_OPENSSL = -lssl -lcrypto
LIBS_CRYPTOPP = -lcrypto++

TARGET = hash_app
SRC = hash.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS_OPENSSL)

cryptopp: $(SRC)
	$(CXX) $(CXXFLAGS) -DUSE_CRYPTOPP -o $(TARGET) $(SRC) $(LIBS_CRYPTOPP)

clean:
	rm -f $(TARGET) *.o

test: $(TARGET)
	echo "test data for hashing" > test_file.txt
	./$(TARGET) test_file.txt
	sha256sum test_file.txt

.PHONY: clean test cryptopp
