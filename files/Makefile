CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c99
SRCS    = bignum.c ecc.c sha256.c hkdf.c aes256.c gcm.c ecies.c main.c
OBJS    = $(SRCS:.c=.o)
TARGET  = ecies_demo

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
