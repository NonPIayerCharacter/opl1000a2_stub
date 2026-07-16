ENTRY(flasher_stub)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x00440400, LENGTH = 0x0000F000
}

SECTIONS
{
    .init ORIGIN(RAM) : ALIGN(4)
    {
        KEEP(*(.init))
    } > RAM

    .text : ALIGN(4)
    {
        *(.text*)
        *(.rodata*)
    } > RAM

    .data : ALIGN(4)
    {
        *(.data*)
    } > RAM

    .bss (NOLOAD) : ALIGN(4)
    {
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        __bss_end__ = .;
    } > RAM

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.comment*)
        *(.note*)
    }
}
INCLUDE "symdefs_gcc.o"
