CC = gcc
CFLAGS = -g -Os -static -Wall
LDFLAGS = -lpthread

ARCH ?= x86_64
ifeq ($(ARCH),aarch64)
  BUILD_ARCH = arm64
else ifeq ($(ARCH),arm64)
  BUILD_ARCH = arm64
else
  BUILD_ARCH = $(ARCH)
endif

OUT_DIR ?= .

SRCS = nvmm.c $(BUILD_ARCH).c $(if $(filter arm64,$(BUILD_ARCH)),arm64_fdt.c,)
OBJS = $(patsubst %.c,$(OUT_DIR)/%.o,$(SRCS))
TARGET = $(OUT_DIR)/nvmm

override CFLAGS += -I../output_$(BUILD_ARCH)/headers/include

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OUT_DIR)/arm64.o: arm64.c nvmm.h arm64_fdt.h
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/arm64_fdt.o: arm64_fdt.c arm64_fdt.h nvmm.h
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/%.o: %.c nvmm.h
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
