AS      = $(GCC_BIN)arm-none-eabi-as
CC      = $(GCC_BIN)arm-none-eabi-gcc
CPP     = $(GCC_BIN)arm-none-eabi-g++
LD      = $(GCC_BIN)arm-none-eabi-gcc
OBJCOPY = $(GCC_BIN)arm-none-eabi-objcopy
OBJDUMP = $(GCC_BIN)arm-none-eabi-objdump
SIZE    = $(GCC_BIN)arm-none-eabi-size

CFLAGS = -mcpu=cortex-m3 -std=gnu99 -mthumb -Os -fdata-sections -ffunction-sections -fdiagnostics-color=always -Wall -nostdlib -ffreestanding -flto -DTDEFL_LESS_MEMORY -DMINIZ_LITTLE_ENDIAN=1 -DMINIZ_USE_UNALIGNED_LOADS_AND_STORES=1 -DNDEBUG -I.
LDFLAGS = -Tstub.ld -Wl,-Map=output.map -Wl,--gc-sections -flto

SRC_C = opl_stub.c
SRC_C += ../OpenBK7231T_App/libraries/miniz/miniz.c
SRC_C += ../OpenBK7231T_App/libraries/miniz/miniz_tdef.c
SRC_C += ../OpenBK7231T_App/libraries/miniz/miniz_tinfl.c
OBJ = $(SRC_C:.c=.o)

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
