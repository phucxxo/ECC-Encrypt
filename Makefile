CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

TARGET = ecc_core
BUILD_DIR = build

SRCS = main.cpp src/ecc/elliptic_curve.cpp
OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/elliptic_curve.o

.PHONY: all clean

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/main.o: main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/elliptic_curve.o: src/ecc/elliptic_curve.cpp src/ecc/elliptic_curve.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
