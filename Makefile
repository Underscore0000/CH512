CC = gcc
CFLAGS = -O2 -march=native -Wall -Wextra -Iinclude
LDFLAGS = -lm

SRC_DIR = src
OBJ_DIR = obj
TEST_DIR = test
TOOLS_DIR = tools

SOURCES = $(SRC_DIR)/ch512_core.c $(SRC_DIR)/ch512_key.c $(SRC_DIR)/ch512_mode.c $(SRC_DIR)/ch512_utils.c $(SRC_DIR)/ch512_kdf.c $(SRC_DIR)/ch512_gcm.c
OBJECTS = $(OBJ_DIR)/ch512_core.o $(OBJ_DIR)/ch512_key.o $(OBJ_DIR)/ch512_mode.o $(OBJ_DIR)/ch512_utils.o $(OBJ_DIR)/ch512_kdf.o $(OBJ_DIR)/ch512_gcm.o

all: dirs $(OBJ_DIR)/libch512.a ch512_test ch512_nist ch512_enc ch512_dec ch512_bench

dirs:
	@mkdir -p $(OBJ_DIR) bin

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/libch512.a: $(OBJECTS)
	ar rcs $@ $^

ch512_test: $(TEST_DIR)/ch512_test.c $(OBJECTS)
	$(CC) $(CFLAGS) $< $(OBJECTS) -o bin/$@

ch512_nist: $(TEST_DIR)/ch512_nist_test.c $(OBJECTS)
	$(CC) $(CFLAGS) $< $(OBJECTS) -lm -o bin/$@

ch512_enc: $(TOOLS_DIR)/ch512_encrypt_file.c $(OBJECTS)
	$(CC) $(CFLAGS) $< $(OBJECTS) -o bin/$@

ch512_dec: $(TOOLS_DIR)/ch512_decrypt_file.c $(OBJECTS)
	$(CC) $(CFLAGS) $< $(OBJECTS) -o bin/$@

ch512_bench: $(TOOLS_DIR)/ch512_benchmark.c $(OBJECTS)
	$(CC) $(CFLAGS) $< $(OBJECTS) -o bin/$@

clean:
	rm -rf $(OBJ_DIR) bin

.PHONY: all clean dirs