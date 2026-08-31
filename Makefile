export RELVER := 0.1

TARGET   := PSPSH
BUILD_DIR := build
SRC_DIR  := src

# PSP build objects
PSP_OBJS := $(SRC_DIR)/app/main.o \
            $(SRC_DIR)/ssh/net_psp.o \
            $(SRC_DIR)/ssh/transport.o \
            $(SRC_DIR)/ssh/client.o \
            $(SRC_DIR)/ssh/buf.o \
            $(SRC_DIR)/crypto/sshcrypto.o \
            $(SRC_DIR)/crypto/tweetnacl.o \
            $(SRC_DIR)/crypto/aes.o \
            $(SRC_DIR)/crypto/sha256.o \
            $(SRC_DIR)/crypto/sha1.o

# Host objects (everything except the PSP net backend + app)
HOST_OBJS := $(SRC_DIR)/ssh/net_host.o \
             $(SRC_DIR)/ssh/transport.o \
             $(SRC_DIR)/ssh/client.o \
             $(SRC_DIR)/ssh/buf.o \
             $(SRC_DIR)/crypto/sshcrypto.o \
             $(SRC_DIR)/crypto/tweetnacl.o \
             $(SRC_DIR)/crypto/aes.o \
             $(SRC_DIR)/crypto/sha256.o \
             $(SRC_DIR)/crypto/sha1.o

INCDIR := $(SRC_DIR) $(SRC_DIR)/crypto $(SRC_DIR)/ssh

# host build flags (PSP build.mak adds its own from INCDIR)
HOST_CFLAGS := -Isrc -Isrc/crypto -Isrc/ssh

ifeq ($(shell psp-config --psp-prefix 2>/dev/null),)
    $(info Note: PSP SDK not found — building host test targets only)
else
    include $(shell psp-config --pspsdk-path 2>/dev/null)/lib/build.mak
endif

# ── Host unit tests: crypto vectors ──
.PHONY: test test-integration pack
test: test/test_crypto
	./test/test_crypto

test/test_crypto: test/test_crypto.c $(HOST_OBJS)
	cc $(HOST_CFLAGS) -o $@ test/test_crypto.c $(HOST_OBJS)

# ── Integration test against real sshd (host) ──
test-integration: test/test_integration
	./test/test_integration

test/test_integration: test/test_integration.c $(HOST_OBJS)
	cc $(HOST_CFLAGS) -o $@ test/test_integration.c $(HOST_OBJS)

# ── PSP EBOOT (requires SDK; DOCKER target for CI) ──
DOCKER_BUILD := docker run --rm -v $(CURDIR):/src -w /src pspdev/pspdev \
		$(MAKE) -f /src/Makefile all

.PHONY: docker
docker:
	$(DOCKER_BUILD)

# pack the EBOOT for manual install
pack: all
	mkdir -p $(BUILD_DIR)/$(TARGET)
	cp $(TARGET)/EBOOT.PBP $(BUILD_DIR)/$(TARGET)/
	cp README.md $(BUILD_DIR)/$(TARGET)/
	cd $(BUILD_DIR) && zip -r $(TARGET)-$(RELVER).zip $(TARGET)

# host-side gcc parts still compile without psp-config:
# (empty rule to let 'make' run from a fresh checkout without SDK)
all:
	@$(MAKE) -s test
	@echo "NOTE: run 'make docker' to build the PSP EBOOT (requires Docker)"