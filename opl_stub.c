
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "../OpenBK7231T_App/libraries/miniz/miniz.h"

typedef enum
{
	SPI_IDX_0,
	SPI_IDX_1,
	SPI_IDX_2,
	SPI_IDX_MAX
} E_SpiIdx_t;

typedef enum
{
	APS_CLKTREE_SRC_RC_BB,
	APS_CLKTREE_SRC_XTAL,
	APS_CLKTREE_SRC_XTAL_X2,
	APS_CLKTREE_SRC_XTAL_X4,
	APS_CLKTREE_SRC_DECI,
	APS_CLKTREE_SRC_1P2G_DIV,
	APS_CLKTREE_SRC_EXTERNAL,
	APS_CLKTREE_SRC_1P2G_MIN,
	APS_CLKTREE_SRC_1P2G_078MHZ = APS_CLKTREE_SRC_1P2G_MIN,
	APS_CLKTREE_SRC_1P2G_081MHZ,
	APS_CLKTREE_SRC_1P2G_084MHZ,
	APS_CLKTREE_SRC_1P2G_087MHZ,
	APS_CLKTREE_SRC_1P2G_090MHZ,
	APS_CLKTREE_SRC_1P2G_093MHZ,
	APS_CLKTREE_SRC_1P2G_097MHZ,
	APS_CLKTREE_SRC_1P2G_101MHZ,
	APS_CLKTREE_SRC_1P2G_106MHZ,
	APS_CLKTREE_SRC_1P2G_110MHZ,
	APS_CLKTREE_SRC_1P2G_116MHZ,
	APS_CLKTREE_SRC_1P2G_122MHZ,
	APS_CLKTREE_SRC_1P2G_128MHZ,
	APS_CLKTREE_SRC_1P2G_135MHZ,
	APS_CLKTREE_SRC_1P2G_143MHZ,
	APS_CLKTREE_SRC_1P2G_152MHZ,
	APS_CLKTREE_SRC_1P2G_MAX = APS_CLKTREE_SRC_1P2G_152MHZ
} E_ApsClkTreeSrc_t;

typedef uint32_t(*T_Hal_DbgUart_BaudRateSet)(uint32_t u32Baud);
typedef uint32_t(*T_Hal_DbgUart_DataSend)(uint32_t u32Data);
typedef uint32_t(*T_Hal_DbgUart_DataRecvTimeOut)(uint32_t* pu32Data, uint32_t u32MilliSec);
typedef uint32_t(*T__Hal_Flash_ManufDeviceId)(E_SpiIdx_t u32SpiIdx, uint32_t* pu32Manufacturer, uint32_t* pu32MemoryType, uint32_t* pu32MemoryDensity);
typedef int (*nl_scrt_common_fp_t)(void);
typedef void    (*BootAgent_DelayMs_fp)(uint32_t u32Ms);
typedef uint32_t(*T_Hal_Flash_4KSectorAddrErase_Internal)(E_SpiIdx_t u32SpiIdx, uint32_t u32SecAddr);
typedef uint32_t(*T_Hal_Flash_AddrRead_Internal)(E_SpiIdx_t u32SpiIdx, uint32_t u32StartAddr, uint8_t u8UseQuadMode, uint32_t u32Size, uint8_t* pu8Data);
typedef uint32_t(*T_Hal_Flash_AddrProgram_Internal)(E_SpiIdx_t u32SpiIdx, uint32_t u32StartAddr, uint8_t u8UseQuadMode, uint32_t u32Size, uint8_t* pu8Data);
typedef uint8_t* (*T_Hal_Sys_OtpRead)(uint16_t u16Offset, uint8_t* u8aBuf, uint16_t u16BufSize);
typedef uint32_t(*T_Hal_Sys_ApsClkTreeSetup)(E_ApsClkTreeSrc_t eClkTreeSrc, uint8_t u8ClkDivEn, uint8_t u8PclkDivEn);
typedef uint32_t(*T_Hal_Sys_RetRamTurnOn)(uint32_t u32RetRamIdxs);

extern T_Hal_DbgUart_BaudRateSet Hal_DbgUart_BaudRateSet;
extern T_Hal_DbgUart_DataSend Hal_DbgUart_DataSend;
extern T_Hal_DbgUart_DataRecvTimeOut Hal_DbgUart_DataRecvTimeOut;
extern T__Hal_Flash_ManufDeviceId  _Hal_Flash_ManufDeviceId;
extern nl_scrt_common_fp_t scrt_sem_create;
extern BootAgent_DelayMs_fp BootAgent_DelayMs;
extern T_Hal_Flash_AddrRead_Internal          Hal_Flash_AddrRead_Internal;
extern T_Hal_Flash_4KSectorAddrErase_Internal Hal_Flash_4KSectorAddrErase_Internal;
extern T_Hal_Flash_AddrProgram_Internal       Hal_Flash_AddrProgram_Internal;
extern T_Hal_Sys_OtpRead            Hal_Sys_OtpRead;
extern T_Hal_Sys_ApsClkTreeSetup Hal_Sys_ApsClkTreeSetup;
extern T_Hal_Sys_RetRamTurnOn     Hal_Sys_RetRamTurnOn;

#define SHA256_BLOCK_LENGTH 64
typedef struct
{
	uint32_t total[2];          /*!< number of bytes processed  */
	uint32_t state[8];          /*!< intermediate digest state  */
	unsigned char buffer[SHA256_BLOCK_LENGTH];   /*!< data block being processed */
	int is224;                  /*!< 0 => SHA-256, else SHA-224 */
}
mbedtls_sha256_context;

#define TC_SHA256_BLOCK_SIZE (64)
#define TC_SHA256_DIGEST_SIZE (32)
#define TC_SHA256_STATE_BLOCKS (TC_SHA256_DIGEST_SIZE/4)

struct tc_sha256_state_struct
{
	unsigned int iv[TC_SHA256_STATE_BLOCKS];
	uint64_t bits_hashed;
	uint8_t leftover[TC_SHA256_BLOCK_SIZE];
	size_t leftover_offset;
};

typedef struct tc_sha256_state_struct* TCSha256State_t;

extern uint8_t __bss_start__[];
extern uint8_t __bss_end__[];
void flasher_stub(void);

#define MAGIC 						0xA5
#define ACK_MAGIC 					0x5A 

#define STATE_ERR					0xFF
#define STATE_SYN					0x00
#define STATE_RAM_DOWNLOAD			0x01
#define STATE_FLASH_DOWNLOAD		0x02
#define STATE_FLASH_UPLOAD			0x03
#define STATE_FLASH_ERASE			0x04
#define STATE_FLASH_CHIPERASE		0x05
#define STATE_RUN					0x06
#define STATE_BOUND					0x07
#define STATE_MAX					0x08

#define STATUS_SUCCESS				0x00
#define STATUS_ERROR				0x01
#define STATUS_ADDR_ERROR			0x02
#define STATUS_TYPE_ERROR			0x03
#define STATUS_LEN_ERROR			0x04
#define STATUS_CRC_ERROR			0x05

#define RESPONSE_FAIL				0xFF
#define RESPONSE_OK					0x00
#define RESPONSE_SYNC_BOOTROM		0x01
#define RESPONSE_SYNC_SBL			0x02

#define ACK_OK  0x00
#define ACK_ERR 0x01

#define MSG_OK 0x00
#define MSG_ERR -1

#define SYNC_REQUEST_VALUE			0x73796E63
#define SYNC_REQUEST_SIZE			0x04
#define SYNC_REQUEST_TIMEOUT		120

#define HEAD_SIZE					4
#define CFG_SIZE					8
#define ACK_SIZE					6
#define CMD_DATA_MAX_LEN 			(4 + 1 + 1024*4 + 2)
#define RESPONSE_SIZE				0x01
#define LOAD_MAX_SIZE_BIG			0x10000

struct sburner_cmd
{
	unsigned int msg_type;
	unsigned int arg0;
	unsigned int arg1;
};

struct message_rec_head
{
	unsigned char magic;
	unsigned char type;
	unsigned short data_len;
	unsigned int run_addr;
	unsigned char CRC8;
};

#define MESSAGE_REC_SIZE sizeof(struct message_rec_head)

struct message_ack_head
{
	unsigned char magic;
	unsigned char type;
	unsigned short data_len;
	unsigned char status;
	unsigned char CRC8;
};
#define MESSAGE_ACK_SIZE sizeof(struct message_ack_head)

struct load_cfg_msg
{
	unsigned int	addr;
	unsigned int	len;
} load_cfg_msg_t;
#define MESSAGE_LOAD_SIZE sizeof(struct load_cfg_msg)

#pragma pack(1)
typedef struct message_head
{
	uint8_t sof;
	uint8_t type;
	uint32_t data_len;
	uint8_t sub_type;
	uint32_t check_sum;
} message_head_t;
#pragma pack()

struct download_cfg_msg
{
	int msg_type;
	int addr;
	int len;
};

struct download_t
{
	int download_state;
	int download_addr;
	int download_len;
	int download_timeout;
	char* downloader_buf;
};

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18
#define CRC_MODE 'C'
#define XMODEM_BLOCK_SIZE_1K 1024
#define XMODEM_BLOCK_SIZE_128 128
uint32_t g_flash_id = 0;
unsigned int g_flash_size = 0;
struct message_ack_head ACK_msg =
{
	.magic = ACK_MAGIC,
	.type = 0,
	.data_len = 0,
	.status = STATUS_SUCCESS,
	.CRC8 = 0
};
unsigned char cmd_data_buf[CMD_DATA_MAX_LEN] = { 0 };

int uart_cmd_parser(void);
void sburner_flash_init(void);

__attribute__((section(".init"), used))
void flasher_stub(void)
{
	Hal_Sys_RetRamTurnOn(0);
	memset((void*)__bss_start__, 0, (__bss_end__ - __bss_start__));
	//scrt_sem_create(); // for mbedtls sha256
	Hal_Sys_ApsClkTreeSetup(APS_CLKTREE_SRC_XTAL_X2, 0, 0);
	Hal_DbgUart_BaudRateSet(115200);
	sburner_flash_init();
	while(1) uart_cmd_parser();
}

void uart_fifo_reset(void)
{

}

void uart_putc(uint8_t value)
{
	while(Hal_DbgUart_DataSend((uint32_t)value) != 0u) __asm volatile("nop");
}

void uart_write(unsigned char* data, uint32_t len)
{
	if(!data || !len)
	{
		return;
	}

	for(size_t i = 0; i < len; ++i)
	{
		uart_putc(data[i]);
	}
}

int uart_getc(uint8_t* value, uint32_t timeout_ms)
{
	uint32_t word = 0u;
	if(Hal_DbgUart_DataRecvTimeOut(&word, timeout_ms) != 0u)
		return 1;
	*value = (uint8_t)word;
	return 0;
}

void FLASH_EraseByLength(uint32_t Address, uint32_t Length)
{
	if((Address & 0x3) != 0)
		return;
	if(Length == 0)
		return;

	uint32_t cur = Address;
	uint32_t end = Address + Length;

	while(cur < end)
	{
		Hal_Flash_4KSectorAddrErase_Internal(0, cur);
		cur += 0x1000U;
	}

	return;
}

unsigned char uboot_mesage_check(unsigned char* buf, unsigned short length)
{
	unsigned int crc = 0;
	unsigned char ret = 0;
	unsigned int i = 0;

	for(i = 0; i < length; i++)
	{
		crc += buf[i];
	}
	ret = crc % 256;
	return ret;
}

void sburner_flash_init(void)
{
	uint32_t flashId[3];
	_Hal_Flash_ManufDeviceId(0, &flashId[0], &flashId[1], &flashId[2]);
	g_flash_id = ((flashId[2] & 0xFF) << 16) | ((flashId[1] & 0xFF) << 8) | (flashId[0] & 0xFF);
	unsigned char id = (g_flash_id >> 16) & 0xff;
	switch(id)
	{
		case 0x13:
		case 0x33:
			g_flash_size = 0x80000; break;
		default:
		case 0x14:
		case 0x34:
			g_flash_size = 0x100000; break;
		case 0x15:
		case 0x35:
			g_flash_size = 0x200000; break;
		case 0x16:
		case 0x36:
			g_flash_size = 0x400000; break;
		case 0x17:
		case 0x37:
			g_flash_size = 0x800000; break;
		case 0x18:
		case 0x38:
			g_flash_size = 0x1000000; break;
		case 0x19:
		case 0x39:
			g_flash_size = 0x2000000; break;
		case 0x1A:
		case 0x3A:
			g_flash_size = 0x4000000; break;
		case 0x1B:
			g_flash_size = 0x8000000; break;
		case 0x1C:
			g_flash_size = 0x10000000; break;
	}
}

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

void uboot_sync(void)
{
	unsigned int i = 0;
	struct message_rec_head* msg = (struct message_rec_head*)cmd_data_buf;

	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.status = STATUS_SUCCESS;

	//SYNC
	for(i = 0; i < SYNC_REQUEST_SIZE; i++)
	{
		if(cmd_data_buf[HEAD_SIZE + i] != (char)((SYNC_REQUEST_VALUE >> (i * 8)) & 0xff))
		{
			ACK_msg.status = STATUS_ERROR;
			ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
			uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
			return;	//eroor, again
		}
	}
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
}

void uboot_flash_erase_handle(void* buf)
{
	struct load_cfg_msg cfg_msg;
	struct message_rec_head* msg = (struct message_rec_head*)buf;

	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.status = STATUS_SUCCESS;

	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);

	if((cfg_msg.addr + cfg_msg.len) > g_flash_size)
	{
		ACK_msg.status = STATUS_ADDR_ERROR;
		ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
		return;
	}

	FLASH_EraseByLength(cfg_msg.addr, cfg_msg.len);
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
}

void uboot_flash_chiperase_handle(void* buf)
{
	struct message_rec_head* msg = (struct message_rec_head*)buf;

	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.status = STATUS_SUCCESS;

	FLASH_EraseByLength(0, g_flash_size);
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
}

void uboot_buad(void)
{
	struct message_rec_head* msg = (struct message_rec_head*)cmd_data_buf;
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.status = STATUS_SUCCESS;
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
	Hal_DbgUart_BaudRateSet(msg->run_addr);
	BootAgent_DelayMs(95);
	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
}

void uboot_flashid(void)
{
	struct message_rec_head* msg = (struct message_rec_head*)cmd_data_buf;
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.status = STATUS_SUCCESS;
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
	ACK_msg.data_len = 4;
	memcpy(cmd_data_buf, &ACK_msg, HEAD_SIZE);
	memcpy(&cmd_data_buf[HEAD_SIZE], &g_flash_id, 4);
	cmd_data_buf[HEAD_SIZE + 4] = STATUS_SUCCESS;
	cmd_data_buf[HEAD_SIZE + 4 + 1] = uboot_mesage_check((unsigned char*)cmd_data_buf, HEAD_SIZE + 4 + 1);
	uart_write((unsigned char*)cmd_data_buf, HEAD_SIZE + 4 + 2);
}

void uboot_flash_xmodem_ul(bool isRaw, void* buf)
{
	uint8_t block_num = 1;
	uint8_t resp = 0;
	uint32_t offset = 0;
	int retry;
	int ret;
	bool use_1k = true;
	bool use_crc = true;

	uint8_t* packet = (uint8_t*)&cmd_data_buf;
	struct load_cfg_msg cfg_msg;
	struct message_rec_head* msg = (struct message_rec_head*)buf;

	ACK_msg.status = STATUS_SUCCESS;
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);

	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);
	uint32_t data_len = cfg_msg.len;

	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);

	int timeout = 10000;
	while(timeout > 0)
	{
		if(uart_getc(&resp, 100) == 0)
		{
			if(resp == CRC_MODE)
			{
				use_crc = true;
				use_1k = true;
				break;
			}
			else if(resp == NAK)
			{
				use_crc = false;
				use_1k = false;
				break;
			}
			else if(resp == CAN)
			{
				return;
			}
		}

		timeout -= 100;
	}

	if(timeout <= 0)
	{
		uart_putc(CAN);
		uart_putc(CAN);
		return;
	}

	while(data_len > 0)
	{
		uint32_t block_size;
		uint8_t header;

		if(use_1k)
		{
			block_size = XMODEM_BLOCK_SIZE_1K;
			header = STX;
		}
		else
		{
			block_size = 128;
			header = SOH;
		}

		uint32_t chunk = (data_len >= block_size) ? block_size : data_len;

		retry = 0;
		while(retry < 10)
		{
			memset(packet, 0xFF, sizeof(packet));

			packet[0] = header;
			packet[1] = block_num;
			packet[2] = ~block_num;

			if(isRaw) memcpy(&packet[3], (const void*)(cfg_msg.addr + offset), chunk);
			else Hal_Flash_AddrRead_Internal(0, cfg_msg.addr + offset, 0, chunk, &packet[3]);

			if(chunk < block_size)
			{
				memset(&packet[3 + chunk], 0xFF, block_size - chunk);
			}

			uint32_t pkt_len = 3 + block_size;
			if(use_crc)
			{
				uint16_t crc = crc16_ccitt(&packet[3], block_size);
				packet[pkt_len++] = (crc >> 8) & 0xff;
				packet[pkt_len++] = crc & 0xff;
			}
			else
			{
				uint8_t sum = 0;
				for(uint32_t i = 0; i < block_size; ++i)
				{
					sum += packet[3 + i];
				}
				packet[pkt_len++] = sum;
			}

			uart_write(packet, pkt_len);

			ret = uart_getc(&resp, 5000);
			if(ret == 0 && resp == ACK)
			{
				break;
			}

			if(ret == 0 && resp == CAN)
			{
				if(uart_getc(&resp, 1000) == 0 && resp == CAN)
				{
					return;
				}
			}

			++retry;
		}

		if(use_1k && retry >= 7)
		{
			use_1k = false;
		}

		if(retry >= 10)
		{
			uart_putc(CAN);
			uart_putc(CAN);
			return;
		}

		offset += chunk;
		data_len -= chunk;
		++block_num;
	}

	retry = 0;
	while(retry < 10)
	{
		uart_putc(EOT);

		ret = uart_getc(&resp, 5000);
		if(ret == 0 && resp == ACK)
		{
			return;
		}
		++retry;
	}

	uart_putc(CAN);
	uart_putc(CAN);
}

// slower version
//void uboot_flash_sha256(void* buf)
//{
//	struct load_cfg_msg cfg_msg;
//	struct message_rec_head* msg = (struct message_rec_head*)buf;
//
//	ACK_msg.magic = ACK_MAGIC;
//	ACK_msg.type = msg->type;
//	ACK_msg.data_len = 32;
//
//	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);
//
//	uint8_t hash[32] = { 0 };
//
//	if((cfg_msg.addr + cfg_msg.len) > g_flash_size)
//	{
//		ACK_msg.data_len = 0;
//		ACK_msg.status = STATUS_ADDR_ERROR;
//		ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
//		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
//		return;
//	}
//
//	mbedtls_sha256_context ctx = { 0 };
//	mbedtls_sha256_init(&ctx);
//	uint32_t addr = cfg_msg.addr;
//	uint32_t remaining = cfg_msg.len;
//	mbedtls_sha256_starts(&ctx, 0);
//	while(remaining > 0)
//	{
//		uint32_t chunk = remaining > 0x1000 ? 0x1000 : remaining;
//		Hal_Flash_AddrRead_Internal(0, addr, 0, chunk, &cmd_data_buf);
//		mbedtls_sha256_update(&ctx, &cmd_data_buf, chunk);
//		addr += chunk;
//		remaining -= chunk;
//	}
//
//	mbedtls_sha256_finish(&ctx, hash);
//	mbedtls_sha256_free(&ctx);
//	memcpy(cmd_data_buf, &ACK_msg, HEAD_SIZE);
//	memcpy(&cmd_data_buf[HEAD_SIZE], &hash, 32);
//	cmd_data_buf[HEAD_SIZE + 32] = STATUS_SUCCESS;
//	cmd_data_buf[HEAD_SIZE + 32 + 1] = uboot_mesage_check((unsigned char*)cmd_data_buf, HEAD_SIZE + 32 + 1);
//	uart_write((unsigned char*)cmd_data_buf, HEAD_SIZE + 32 + 2);
//}

// faster version
//void uboot_flash_sha256(void* buf)
//{
//	struct load_cfg_msg cfg_msg;
//	struct message_rec_head* msg = (struct message_rec_head*)buf;
//
//	ACK_msg.magic = ACK_MAGIC;
//	ACK_msg.type = msg->type;
//	ACK_msg.data_len = 32;
//
//	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);
//
//	uint8_t hash[32] = { 0 };
//
//	if((cfg_msg.addr + cfg_msg.len) > g_flash_size)
//	{
//		ACK_msg.data_len = 0;
//		ACK_msg.status = STATUS_ADDR_ERROR;
//		ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
//		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
//		return;
//	}
//
//	struct tc_sha256_state_struct ctx = { 0 };
//	tc_sha256_init(&ctx);
//	uint32_t addr = cfg_msg.addr;
//	uint32_t remaining = cfg_msg.len;
//	while(remaining > 0)
//	{
//		uint32_t chunk = remaining > 0x1000 ? 0x1000 : remaining;
//		Hal_Flash_AddrRead_Internal(0, addr, 0, chunk, &cmd_data_buf);
//		tc_sha256_update(&ctx, &cmd_data_buf, chunk);
//		addr += chunk;
//		remaining -= chunk;
//	}
//
//	tc_sha256_final(hash, &ctx);
//	memcpy(cmd_data_buf, &ACK_msg, HEAD_SIZE);
//	memcpy(&cmd_data_buf[HEAD_SIZE], &hash, 32);
//	cmd_data_buf[HEAD_SIZE + 32] = STATUS_SUCCESS;
//	cmd_data_buf[HEAD_SIZE + 32 + 1] = uboot_mesage_check((unsigned char*)cmd_data_buf, HEAD_SIZE + 32 + 1);
//	uart_write((unsigned char*)cmd_data_buf, HEAD_SIZE + 32 + 2);
//}

void uboot_flash_xmodem_dl(void* buf)
{
	uint8_t header[3] = { 0x00 };
	uint8_t data[XMODEM_BLOCK_SIZE_1K] = { 0x00 };
	uint8_t crc_bytes[2] = { 0x00 };
	uint16_t crc_calc, crc_recv;
	uint32_t offset = 0;
	struct load_cfg_msg cfg_msg;
	struct message_rec_head* msg = (struct message_rec_head*)buf;
	ACK_msg.status = STATUS_SUCCESS;
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);

	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);

	if((cfg_msg.addr + cfg_msg.len) > g_flash_size)
	{
		ACK_msg.status = STATUS_ADDR_ERROR;
		ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
		return;
	}

	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);

	FLASH_EraseByLength(cfg_msg.addr, cfg_msg.len);

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

		Hal_Flash_AddrProgram_Internal(0, cfg_msg.addr + offset, 0, XMODEM_BLOCK_SIZE_1K, data);
		offset += XMODEM_BLOCK_SIZE_1K;

		uart_putc(ACK);
	}
}

void uboot_flash_crc32(void* buf)
{
	struct load_cfg_msg cfg_msg;
	struct message_rec_head* msg = (struct message_rec_head*)buf;

	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 4;

	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);
	uint32_t crc = 0;

	if((cfg_msg.addr + cfg_msg.len) > g_flash_size)
	{
		ACK_msg.data_len = 0;
		ACK_msg.status = STATUS_ADDR_ERROR;
		ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
		return;
	}
	uint32_t addr = cfg_msg.addr;
	uint32_t remaining = cfg_msg.len;
	while(remaining > 0)
	{
		uint32_t chunk = remaining > 0x1000 ? 0x1000 : remaining;
		Hal_Flash_AddrRead_Internal(0, addr, 0, chunk, (uint8_t*)&cmd_data_buf);
		extern uint32_t crc32_opl(uint8_t* data, uint32_t size);
		crc += crc32_opl((uint8_t*)&cmd_data_buf, chunk);
		addr += chunk;
		remaining -= chunk;
	}
	memcpy(cmd_data_buf, &ACK_msg, HEAD_SIZE);
	memcpy(&cmd_data_buf[HEAD_SIZE], &crc, 4);
	cmd_data_buf[HEAD_SIZE + 4] = STATUS_SUCCESS;
	cmd_data_buf[HEAD_SIZE + 4 + 1] = uboot_mesage_check((unsigned char*)cmd_data_buf, HEAD_SIZE + 4 + 1);
	uart_write((unsigned char*)cmd_data_buf, HEAD_SIZE + 4 + 2);
}

void uboot_read_efuse(void)
{
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = 0x99;
	ACK_msg.data_len = 0x200;

	memcpy(cmd_data_buf, &ACK_msg, HEAD_SIZE);

	Hal_Sys_OtpRead(0, cmd_data_buf + HEAD_SIZE, ACK_msg.data_len);

	cmd_data_buf[HEAD_SIZE + ACK_msg.data_len] = STATUS_SUCCESS;
	cmd_data_buf[HEAD_SIZE + ACK_msg.data_len + 1] = uboot_mesage_check((unsigned char*)cmd_data_buf, HEAD_SIZE + ACK_msg.data_len + 1);
	uart_write((unsigned char*)cmd_data_buf, HEAD_SIZE + ACK_msg.data_len + 2);
}

void free(void* ptr) {}
void* malloc(size_t size)
{
	return (void*)0x410000;
}

int mz_deflateInit3(mz_streamp pStream, int level, int method, int window_bits, int mem_level, int strategy)
{
	tdefl_compressor* pComp;
	mz_uint comp_flags = tdefl_create_comp_flags_from_zip_params(level, window_bits, strategy);

	if(!pStream)
		return MZ_STREAM_ERROR;
	if((method != MZ_DEFLATED) || ((mem_level < 1) || (mem_level > 9)) || ((window_bits != MZ_DEFAULT_WINDOW_BITS) && (-window_bits != MZ_DEFAULT_WINDOW_BITS)))
		return MZ_PARAM_ERROR;

	pStream->data_type = 0;
	pStream->adler = 0;
	pStream->msg = NULL;
	pStream->reserved = 0;
	pStream->total_in = 0;
	pStream->total_out = 0;
	if(!pStream->zalloc)
		pStream->zalloc = miniz_def_alloc_func;
	if(!pStream->zfree)
		pStream->zfree = miniz_def_free_func;

	pComp = (tdefl_compressor*)pStream->zalloc(pStream->opaque, 1, sizeof(tdefl_compressor));
	if(!pComp)
		return MZ_MEM_ERROR;

	pStream->state = (struct mz_internal_state*)pComp;

	if(tdefl_init(pComp, NULL, NULL, comp_flags) != TDEFL_STATUS_OKAY)
	{
		mz_deflateEnd(pStream);
		return MZ_PARAM_ERROR;
	}

	return MZ_OK;
}

void uboot_flash_xmodem_ul_z(void* buf)
{
	uint8_t block_num = 1;
	uint8_t resp = 0;
	int retry;
	int ret;
	bool use_1k = true;
	bool use_crc = true;

	uint8_t packet[3 + XMODEM_BLOCK_SIZE_1K + 2];

	struct load_cfg_msg cfg_msg;
	struct message_rec_head* msg = (struct message_rec_head*)buf;

	ACK_msg.status = STATUS_SUCCESS;
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);

	uint8_t comp_level = cmd_data_buf[HEAD_SIZE + CFG_SIZE];
	if(comp_level < 1 || comp_level > 10) comp_level = 5;

	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);

	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);

	int timeout = 10000;

	while(timeout > 0)
	{
		if(uart_getc(&resp, 1000) == 0)
		{
			if(resp == CRC_MODE)
			{
				use_crc = true;
				use_1k = true;
				break;
			}

			if(resp == NAK)
			{
				use_crc = false;
				use_1k = false;
				break;
			}

			if(resp == CAN) return;
		}

		timeout -= 1000;
	}

	if(timeout <= 0)
	{
		uart_putc(CAN);
		uart_putc(CAN);
		return;
	}

	uint32_t remaining = cfg_msg.len;

	z_stream stream;

	memset(&stream, 0, sizeof(stream));

	if(mz_deflateInit3(&stream, comp_level, MZ_DEFLATED, -MZ_DEFAULT_WINDOW_BITS, 9, MZ_DEFAULT_STRATEGY) != Z_OK)
	{
		return;
	}

	bool finished = false;

	while(!finished)
	{
		uint32_t block_size;
		uint8_t header;

		if(use_1k)
		{
			block_size = XMODEM_BLOCK_SIZE_1K;
			header = STX;
		}
		else
		{
			block_size = 128;
			header = SOH;
		}

		memset(packet, 0xFF, sizeof(packet));

		packet[0] = header;
		packet[1] = block_num;
		packet[2] = ~block_num;

		stream.next_out = &packet[3];
		stream.avail_out = block_size;

		while(stream.avail_out)
		{
			if(stream.avail_in == 0 && remaining)
			{
				uint32_t n = remaining;

				if(n > block_size) n = block_size;

				Hal_Flash_AddrRead_Internal(0, cfg_msg.addr + (cfg_msg.len - remaining), 0, n, (unsigned char*)&cmd_data_buf);
				stream.next_in = (unsigned char*)(&cmd_data_buf);

				stream.avail_in = n;

				remaining -= n;
			}

			ret = deflate(&stream, remaining ? Z_NO_FLUSH : Z_FINISH);

			if(ret == Z_STREAM_END)
			{
				finished = true;
				break;
			}

			if(ret != Z_OK)
			{
				deflateEnd(&stream);
				return;
			}
		}

		uint32_t pkt_len = 3 + block_size;

		if(use_crc)
		{
			uint16_t crc = crc16_ccitt(&packet[3], block_size);

			packet[pkt_len++] = crc >> 8;
			packet[pkt_len++] = crc & 0xff;
		}
		else
		{
			uint8_t sum = 0;

			for(uint32_t i = 0; i < block_size; i++)
			{
				sum += packet[3 + i];
			}

			packet[pkt_len++] = sum;
		}

		retry = 0;

		while(retry < 10)
		{
			uart_write(packet, pkt_len);

			ret = uart_getc(&resp, 5000);

			if(ret == 0 && resp == ACK)
			{
				break;
			}

			retry++;
		}

		//if(use_1k && retry >= 7)
		//{
		//	use_1k = false;
		//}

		if(retry >= 10)
		{
			deflateEnd(&stream);

			uart_putc(CAN);
			uart_putc(CAN);

			return;
		}

		block_num++;
	}

	deflateEnd(&stream);

	retry = 0;

	while(retry < 10)
	{
		uart_putc(EOT);

		ret = uart_getc(&resp, 5000);

		if(ret == 0 && resp == ACK)
		{
			return;
		}

		retry++;
	}

	uart_putc(CAN);
	uart_putc(CAN);
}

void uboot_flash_xmodem_dl_z(void* buf)
{
	uint8_t header[3] = { 0x00 };
	uint8_t data[XMODEM_BLOCK_SIZE_1K] = { 0xFF };
	uint8_t crc_bytes[2] = { 0x00 };
	uint16_t crc_calc, crc_recv;
	uint32_t flash_offset = 0;
	struct load_cfg_msg cfg_msg;
	struct message_rec_head* msg = (struct message_rec_head*)buf;

	ACK_msg.status = STATUS_SUCCESS;
	ACK_msg.magic = ACK_MAGIC;
	ACK_msg.type = msg->type;
	ACK_msg.data_len = 0x0000;
	ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);

	memcpy(&cfg_msg, &(cmd_data_buf[HEAD_SIZE]), CFG_SIZE);

	if((cfg_msg.addr + cfg_msg.len) > g_flash_size)
	{
		ACK_msg.status = STATUS_ADDR_ERROR;
		ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
		return;
	}

	uart_write((unsigned char*)&ACK_msg, ACK_SIZE);

	FLASH_EraseByLength(cfg_msg.addr, cfg_msg.len);

	mz_stream stream;
	memset(&stream, 0, sizeof(stream));
	if(mz_inflateInit2(&stream, -MZ_DEFAULT_WINDOW_BITS) != MZ_OK)
	{
		ACK_msg.status = STATUS_ERROR;
		uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
		return;
	}

	uart_putc(CRC_MODE);

	flash_offset = cfg_msg.addr;

	for(;;)
	{
		uint32_t data_size = 0;

		if(uart_getc(&header[0], 3333) != 0)
		{
			uart_putc(CRC_MODE);
			continue;
		}

		if(header[0] == EOT)
		{
			stream.next_in = NULL;
			stream.avail_in = 0;

			while(1)
			{
				stream.next_out = cmd_data_buf;
				stream.avail_out = sizeof(cmd_data_buf);

				int status = mz_inflate(&stream, MZ_NO_FLUSH);
				uint32_t produced = sizeof(cmd_data_buf) - stream.avail_out;

				if(produced > 0)
				{
					if((flash_offset + produced) > (cfg_msg.addr + cfg_msg.len))
					{
						goto abort_decompression;
					}

					Hal_Flash_AddrProgram_Internal(0, flash_offset, 0, produced, cmd_data_buf);
					flash_offset += produced;
				}

				if(status == MZ_STREAM_END) break;

				if(status != MZ_OK && status != MZ_BUF_ERROR)
					goto abort_decompression;
			}

			mz_inflateEnd(&stream);

			uart_putc(ACK);
			return;
		}

		if(header[0] != STX && header[0] != SOH)
		{
			uart_putc(NAK);
			continue;
		}

		data_size = (header[0] == STX) ? XMODEM_BLOCK_SIZE_1K : XMODEM_BLOCK_SIZE_128;

		uart_getc(&header[1], 10000);
		uart_getc(&header[2], 10000);

		if((header[1] + header[2]) != 0xFF)
		{
			uart_putc(NAK);
			continue;
		}

		for(uint32_t i = 0; i < data_size; i++)
			uart_getc(&data[i], 20000);

		uart_getc(&crc_bytes[0], 10000);
		uart_getc(&crc_bytes[1], 10000);

		crc_recv = ((uint16_t)crc_bytes[0] << 8) | crc_bytes[1];
		crc_calc = crc16_ccitt(data, data_size);

		if(crc_recv != crc_calc)
		{
			uart_putc(NAK);
			continue;
		}

		stream.next_in = data;
		stream.avail_in = data_size;

		while(stream.avail_in > 0)
		{
			stream.next_out = cmd_data_buf;
			stream.avail_out = sizeof(cmd_data_buf);

			int status = mz_inflate(&stream, MZ_NO_FLUSH);
			uint32_t produced = sizeof(cmd_data_buf) - stream.avail_out;

			if(produced > 0)
			{
				if((flash_offset + produced) > (cfg_msg.addr + cfg_msg.len))
				{
					goto abort_decompression;
				}

				Hal_Flash_AddrProgram_Internal(0, flash_offset, 0, produced, cmd_data_buf);
				flash_offset += produced;
			}

			if(status == MZ_STREAM_END) break;

			if(status != MZ_OK && status != MZ_BUF_ERROR)
				goto abort_decompression;
		}

		uart_putc(ACK);
	}

abort_decompression:
	mz_inflateEnd(&stream);

	uart_putc(CAN);
	uart_putc(CAN);
}

int uart_cmd_parser(void)
{
	unsigned int i = 0;
	signed char resp = 0;
	unsigned char CRC8 = 0;
	unsigned char buf[HEAD_SIZE] = { 0 };
	struct message_rec_head rec_head;

	unsigned char cfgbuf[CFG_SIZE] = { 0 };

	uart_fifo_reset();

	do
	{
		memset(buf, 0, HEAD_SIZE);
		for(i = 0; i < HEAD_SIZE; ++i)
		{
			resp = uart_getc((unsigned char*)&buf[i], 0xFFFFFFFF);
			if(resp < 0)
			{
				resp = MSG_ERR;
				return resp;
			}
			if((buf[0]) != MAGIC)
			{
				i = 0xFFFFFFFF;
			}
		}

		memcpy(cmd_data_buf, buf, HEAD_SIZE);
		memcpy(&rec_head, buf, HEAD_SIZE);

		if(buf[1] <= 0x9F)
		{
			for(i = 0; i < rec_head.data_len; i++)
			{
				resp = uart_getc((unsigned char*)&cfgbuf[i], 0xFFFFFFFF);
				if(resp < 0)
				{
					resp = MSG_ERR;
					return resp;
				}
			}
			memcpy(&(cmd_data_buf[HEAD_SIZE]), cfgbuf, rec_head.data_len);

			resp = uart_getc((unsigned char*)&cmd_data_buf[HEAD_SIZE + rec_head.data_len], 0xFFFFFFFF);
			if(resp < 0)
			{
				resp = MSG_ERR;
				return resp;
			}
			CRC8 = uboot_mesage_check((unsigned char*)cmd_data_buf, HEAD_SIZE + rec_head.data_len);
			if(cmd_data_buf[HEAD_SIZE + rec_head.data_len] != CRC8)
			{
				rec_head.type = STATE_ERR;
			}
		}
		else
		{
			rec_head.type = STATE_ERR;
		}


		switch(rec_head.type)
		{
			case STATE_SYN:
				uboot_sync();
				break;
			case STATE_FLASH_ERASE: // 0x04
				uboot_flash_erase_handle(&cmd_data_buf);
				break;
			case STATE_FLASH_CHIPERASE: // 0x05
				uboot_flash_chiperase_handle(&cmd_data_buf);
				break;
			case STATE_BOUND: // 0x07
				uboot_buad();
				break;
			//case 0x09:
			//	uboot_flash_sha256(&cmd_data_buf);
			//	break;
			case 0x8F:
				uboot_flash_crc32(&cmd_data_buf);
				break;
			case 0x90:
				uboot_flashid();
				break;
			case 0x91:
				uboot_flash_xmodem_dl(&cmd_data_buf);
				break;
			case 0x92:
				uboot_flash_xmodem_ul(false, &cmd_data_buf);
				break;
			case 0x96:
				uboot_flash_xmodem_ul_z(&cmd_data_buf);
				break;
			case 0x97:
				uboot_flash_xmodem_dl_z(&cmd_data_buf);
				break;
			case 0x98:
				uboot_flash_xmodem_ul(true, &cmd_data_buf);
				break;
			case 0x99:
				uboot_read_efuse();
				break;

			default:
				ACK_msg.type = STATE_ERR;
				ACK_msg.status = STATUS_TYPE_ERROR;
				ACK_msg.CRC8 = uboot_mesage_check((unsigned char*)&ACK_msg, ACK_SIZE - 1);
				uart_write((unsigned char*)&ACK_msg, ACK_SIZE);
				break;
		}
	} while(1);
}
