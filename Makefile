CC      = gcc
CFLAGS  = -Wall -Wextra -Icrypto -Ibootloader -O2

SRCS    = main.c \
          crypto/aes.c \
          crypto/sha256.c \
          crypto/ecdsa.c \
          bootloader/passkey.c \
          bootloader/bootloader.c

OBJS    = $(SRCS:.c=.o)

TEST_SRCS = tests/test_crypto.c \
            crypto/aes.c \
            crypto/sha256.c \
            crypto/ecdsa.c \
            bootloader/passkey.c \
            bootloader/bootloader.c

test: $(TEST_SRCS)
	$(CC) $(CFLAGS) -o test_crypto $(TEST_SRCS)
	./test_crypto

TARGET  = bootloader_demo

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)