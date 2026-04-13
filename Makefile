CXX      = g++
CC       = gcc
CXXFLAGS = -std=c++17 -Wall -O2
CFLAGS   = -Wall -O2
LDFLAGS  = -lgmp -lgmpxx

SRC_DIR   = src
BUILD_DIR = build
TARGET    = ecc_encrypt

# Source files per module
C_SRCS = $(SRC_DIR)/sha256/sha256.c \
         $(SRC_DIR)/hkdf/hkdf.c     \
         $(SRC_DIR)/aes256/aes256.c  \
         $(SRC_DIR)/gcm/gcm.c

C_OBJS = $(BUILD_DIR)/sha256.o \
         $(BUILD_DIR)/hkdf.o   \
         $(BUILD_DIR)/aes256.o \
         $(BUILD_DIR)/gcm.o

INCLUDES = -I$(SRC_DIR) -I$(SRC_DIR)/sha256 -I$(SRC_DIR)/hkdf \
           -I$(SRC_DIR)/aes256 -I$(SRC_DIR)/gcm -I$(SRC_DIR)/ecc -I$(SRC_DIR)/core

.PHONY: all clean

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/sha256.o: $(SRC_DIR)/sha256/sha256.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/hkdf.o: $(SRC_DIR)/hkdf/hkdf.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/aes256.o: $(SRC_DIR)/aes256/aes256.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/gcm.o: $(SRC_DIR)/gcm/gcm.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/main.o: main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(C_OBJS) $(BUILD_DIR)/main.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
