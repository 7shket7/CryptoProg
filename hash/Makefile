CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lcryptopp

hash: hash.cpp
	$(CXX) $(CXXFLAGS) hash.cpp -o hash $(LIBS)

clean:
	rm -f hash *.o

test: hash
	echo "test file" > test.txt
	./hash test.txt
