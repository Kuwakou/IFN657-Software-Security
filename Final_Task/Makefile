CC = gcc
CLANG = clang
CFLAGS = -g -O0
SEC_FLAGS = -fno-stack-protector -no-pie
ASAN_FLAGS = -g -fsanitize=address

SRC_VULN = source/sentinel_payload_vulnerable.c
SRC_REM = source/sentinel_payload_remediated.c

BIN_DIR = bin
BIN_GCC = $(BIN_DIR)/sentinel_payload_gcc
BIN_NOPIE = $(BIN_DIR)/sentinel_payload_nopie
BIN_ASAN = $(BIN_DIR)/sentinel_payload_asan
BIN_REM_ASAN = $(BIN_DIR)/sentinel_payload_remediated_asan

.PHONY: all clean test build poc

all: $(BIN_GCC) $(BIN_NOPIE) $(BIN_ASAN) $(BIN_REM_ASAN) poc

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_GCC): $(SRC_VULN) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(SRC_VULN) -o $(BIN_GCC)

$(BIN_NOPIE): $(SRC_VULN) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(SEC_FLAGS) $(SRC_VULN) -o $(BIN_NOPIE)

$(BIN_ASAN): $(SRC_VULN) | $(BIN_DIR)
	$(CLANG) $(ASAN_FLAGS) $(SRC_VULN) -o $(BIN_ASAN)

$(BIN_REM_ASAN): $(SRC_REM) | $(BIN_DIR)
	$(CLANG) $(ASAN_FLAGS) $(SRC_REM) -o $(BIN_REM_ASAN)

poc:
	python3 poc/exploit_payload.py

test: all
	python3 tests/run_tests.py

clean:
	rm -rf $(BIN_DIR)
