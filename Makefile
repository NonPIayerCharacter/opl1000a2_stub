AS      = $(GCC_BIN)arm-none-eabi-as
CC      = $(GCC_BIN)arm-none-eabi-gcc
CPP     = $(GCC_BIN)arm-none-eabi-g++
LD      = $(GCC_BIN)arm-none-eabi-gcc
OBJCOPY = $(GCC_BIN)arm-none-eabi-objcopy
OBJDUMP = $(GCC_BIN)arm-none-eabi-objdump
SIZE    = $(GCC_BIN)arm-none-eabi-size

CFLAGS = -mcpu=cortex-m3 -std=gnu99 -mthumb -Os -fdata-sections -ffunction-sections -fdiagnostics-color=always -Wall -nostdlib -ffreestanding -flto
LDFLAGS = -Tstub.ld -Wl,-Map=output.map -Wl,--gc-sections -flto

SRC_C = opl_stub.c
OBJ = $(SRC_C:.c=.o) $(SRC_S:.S=.o)

all: stub.elf

stub.elf: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	$(OBJCOPY) -O binary $@ stub.bin
	gzip -k stub.bin
	mv stub.bin.gz OPL1000A2_Stub.bin

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) output.map stub.elf stub.bin OPL1000A2_Stub.bin
