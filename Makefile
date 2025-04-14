# Compiler settings
CXX = g++
CXXFLAGS = -Wall -Wextra

# Target executable name
TARGET = nfqnl_test

# Source files
SOURCES = $(wildcard *.cpp)
HEADERS = $(wildcard *.h)

# Library
LIBS = -lnetfilter_queue

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Main target
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LIBS)

# To obtain object files
%.o: %.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) $< -o $@

# Clean target
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJECTS)

# All target
.PHONY: all
all: $(TARGET)