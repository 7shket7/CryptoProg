CXX = g++
CXXFLAGS = -O2 -std=c++11
LIBS = -lcryptopp
TARGET = cipher

all: $(TARGET)

$(TARGET): cipher.cpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) cipher.cpp $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean install-deps
