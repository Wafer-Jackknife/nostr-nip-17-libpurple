# Makefile for nostr-purple libpurple plugin

# Plugin info
PLUGIN_NAME = nostr
PLUGIN_SO = lib$(PLUGIN_NAME).so
PLUGIN_DYLIB = lib$(PLUGIN_NAME).dylib

# Directories
SRC_DIR = src
BUILD_DIR = build
NOSTR_CORE_DIR = ../nostr-core

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Compiler
CC = clang

# Flags from pkg-config
PURPLE_CFLAGS = $(shell pkg-config --cflags purple glib-2.0)
PURPLE_LIBS = $(shell pkg-config --libs purple glib-2.0)

# Compiler flags
CFLAGS = -Wall -Wextra -fPIC -g -O2 \
         $(PURPLE_CFLAGS) \
         -I$(NOSTR_CORE_DIR)/include

# Rust static library path
NOSTR_CORE_LIB = $(NOSTR_CORE_DIR)/../target/release/libnostr_core.a

# Linker flags
# Link against the Rust static library directly (not via -l to ensure static linking)
LDFLAGS = $(PURPLE_LIBS) \
          $(NOSTR_CORE_LIB) \
          -framework Security \
          -framework CoreFoundation \
          -liconv

# libpurple expects .so extension even on macOS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SHARED_FLAGS = -dynamiclib -Wl,-undefined,dynamic_lookup
else
    SHARED_FLAGS = -shared
endif

# Always use .so for libpurple plugins
PLUGIN = lib$(PLUGIN_NAME).so

# Install directory
INSTALL_DIR = $(HOME)/.purple/plugins

.PHONY: all clean install nostr-core

all: nostr-core $(BUILD_DIR) $(PLUGIN)

nostr-core:
	cd $(NOSTR_CORE_DIR) && cargo build --release

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(PLUGIN): $(OBJS)
	$(CC) $(SHARED_FLAGS) -o $@ $^ $(LDFLAGS)

install: all
	cp $(PLUGIN) $(INSTALL_DIR)/

clean:
	rm -rf $(BUILD_DIR) $(PLUGIN)

# Debug target to print variables
debug:
	@echo "SRCS: $(SRCS)"
	@echo "OBJS: $(OBJS)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
