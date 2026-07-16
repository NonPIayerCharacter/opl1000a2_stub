
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef uint32_t(*func_t)(void);
typedef uint32_t(*T_Hal_DbgUart_BaudRateSet)(uint32_t u32Baud);
typedef uint32_t(*T_Hal_DbgUart_DataSend)(uint32_t u32Data);
typedef uint32_t(*T_Hal_DbgUart_DataRecvTimeOut)(uint32_t* pu32Data, uint32_t u32MilliSec);
extern T_Hal_DbgUart_BaudRateSet Hal_DbgUart_BaudRateSet;
extern T_Hal_DbgUart_DataRecvTimeOut Hal_DbgUart_DataRecvTimeOut;
extern T_Hal_DbgUart_DataSend Hal_DbgUart_DataSend;

__attribute__((section(".baud"), used))
uint32_t Baud = 460800;

void flasher_stub(void);

__attribute__((section(".vectors"), used))
const uint32_t vectors[2] = {
	0x00450000u,
	(uint32_t)flasher_stub
};

int uart_getc(uint8_t* value, uint32_t timeout_ms)
{
	uint32_t word = 0u;
	if(Hal_DbgUart_DataRecvTimeOut(&word, timeout_ms) != 0u)
		return 1;
	*value = (uint8_t)word;
	return 0;
}

void uart_putc(uint8_t value)
{
	while(Hal_DbgUart_DataSend((uint32_t)value) != 0u) __asm volatile("nop");
}

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18
#define CRC_MODE 'C'
#define XMODEM_BLOCK_SIZE_1K 1024
#define XMODEM_BLOCK_SIZE_128 128

static uint16_t crc16_ccitt(const uint8_t* data, uint16_t len)
{
	uint16_t crc = 0;
	while(len--)
	{
		crc ^= (uint16_t)(*data++) << 8;
		for(uint8_t i = 0; i < 8; i++)
			crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
	}
	return crc;
}

void flasher_stub(void)
{
	uint8_t header[3] = { 0x00 };
	uint8_t data[XMODEM_BLOCK_SIZE_1K] = { 0x00 };
	uint8_t crc_bytes[2] = { 0x00 };
	uint16_t crc_calc, crc_recv;
	uint32_t offset = 0;
	uint32_t addr = 0x00440400u;

	__asm volatile ("cpsid i" ::: "memory");
	Hal_DbgUart_BaudRateSet(Baud);

	uart_putc(CRC_MODE);

	for(;;)
	{
		// header
		if(uart_getc(&header[0], 1000) != 0)
		{
			uart_putc(CRC_MODE);
			continue;
		}

		if(header[0] == EOT)
		{
			uart_putc(ACK);
			//Hal_DbgUart_BaudRateSet(115200);
			//uartBoot();
			break;
		}

#define NAKCONTINUE { uart_putc(NAK); continue; }

		if(header[0] != STX) NAKCONTINUE

		if(uart_getc(&header[1], 2000) == -1) NAKCONTINUE
		if(uart_getc(&header[2], 2000) == -1) NAKCONTINUE

		if((header[1] + header[2]) != 0xFF) NAKCONTINUE

		// recv data + crc
		for(int i = 0; i < XMODEM_BLOCK_SIZE_1K; i++)
			if(uart_getc(&data[i], 2000) == -1) NAKCONTINUE
		if(uart_getc(&crc_bytes[0], 2000) == -1) NAKCONTINUE
		if(uart_getc(&crc_bytes[1], 2000) == -1) NAKCONTINUE

		crc_recv = ((uint16_t)crc_bytes[0] << 8) | crc_bytes[1];
		crc_calc = crc16_ccitt(data, XMODEM_BLOCK_SIZE_1K);

		if(crc_recv != crc_calc) NAKCONTINUE

		memcpy((void*)addr + offset, data, XMODEM_BLOCK_SIZE_1K);

		offset += XMODEM_BLOCK_SIZE_1K;

		uart_putc(ACK);
	}
	func_t load = (func_t)0x00440401u;
	load();
}
