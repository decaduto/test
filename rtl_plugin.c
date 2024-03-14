/*
	PLUGIN FOR BLACKFI, made by Edoardo Mantovani, 2023
	Simple plugin for interfacing with the rtl8156b hardware, the final goal is to being able to exploit the PHY layer for covert channel and Packet Injection (PiP)
*/

#if CHOOSEN_PLATFORM == 1

#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

/** STANDARD INCLUDE BODY **/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <endian.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>

#define DEBUG_V2		0
#define DEBUG_V1		1
#define DEBUG_WRITE_OPS		0
#define DEBUG_WITH_COLORS	1
#define COMPILE_AS_STANDALONE	1
#define ENABLE_OPTIMIZATION	1

#if DEBUG_V1 == 1 && DEBUG_V2 == 1 && FULL_DEBUG == 0
	#error("IS NOT POSSIBLE TO HAVE ENABLED BOTH DEBUG FEATURES AT THE SAME TIME IF TOTAL_DEBUG ISN'T ENABLED...!")
#endif

#endif

/** HW SPECIFIC DECLARATIONS **/
#include "rtl8156.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
	#pragma message "using little endian!"
	#include <linux/byteorder/little_endian.h>
#else
	#pragma message "using big endian!"
	#include <linux/byteorder/big_endian.h>
#endif

#if CHOOSEN_PLATFORM == 1

#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/swab.h>
#include <linux/mdio.h>
#include <linux/mii.h>
#include <linux/const.h>
#include <libusb-1.0/libusb.h>

#else

/** plan to include baremetal headers here. **/

#endif

/** GENERIC DEFINITIONS, THEY WILL BE MERGED IN THE MAIN PLUGIN INTERFACE SOON! **/
#define TRUE		true
#define FALSE		false
#define MAC_ADDR_LEN	12

#ifndef ALIGN
	#define ALIGN(x, a)	__ALIGN_KERNEL((x), (a))
#endif

#ifndef CONVERT_TO_MS
	#define CONVERT_TO_MS(MSEC)	( MSEC * 1000 )
#endif

#ifndef DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG
	#define DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG	500
#endif

#ifndef swab32
	#define swab32 __swab32
#endif

#ifndef RTL81XX_ADVANCED_IO
        #define RTL81XX_OPTYPE_READ     0
        #define RTL81XX_OPTYPE_WRITE    1
#endif

#define PLUGIN_STRUCT_OPT	__attribute__((packed))

#ifndef PLUGIN_SPECIFIC_STRUCT_OPT
	#define PLUGIN_SPECIFIC_STRUCT_OPT(align_size)	__attribute__((aligned(sizeof(align_size))))
#endif

#define PLUGIN_PREINIT		__attribute__((constructor))
#define PLUGIN_EXIT		__attribute__((destructor))

#if 	DEBUG_WITH_COLORS == 1
	#define BOLD		"\033[1m"
	#define RESET		"\e[m"
	#define CLEAR		"\\033[2K"
	#define UNDERLINE	"\\033[4m"
	#define ERASE_END	"\\033[K"
#endif


#if	ENABLE_OPTIMIZATION
	#pragma message("SPECIFIC I/O FUNCTIONS HAVE THE OPTIMIZATION RULE ENABLED!")
	#define RTL_PLUGIN_IO_OPTIMIZE  __attribute__((optimize("-Ofast")))
#else
	#pragma message("SPECIFIC I/O FUNCTIONS HAVE THE OPTIMIZATION RULE DISABLED!")
	#define RTL_PLUGIN_IO_OPTIMIZE
#endif

#define RTL_PLUGIN_OPS_SECTION 	__attribute__((section(".ops")))

#if DEBUG_V1 == 1 || DEBUG_V2 == 1
	//#define DEBUG_PRINTF(...)	__DEBUG_PRINTF("[%s][line %d] %s". __FUNCTION__, __LINE__, __VA_ARGS__);
	#define   DEBUG_PRINTF(...)	__DEBUG_PRINTF(__VA_ARGS__);
	#define __DEBUG_PRINTF(...)	printf(__VA_ARGS__);
#else
	#define DEBUG_PRINTF(...)	{}

#endif

/** OPERATIONS FOR RTL8152 AND SUPERIOR HARDWARE, PERMITS I/O OPERATIONS THROUGH USB CABLE **/
enum RTL81XX_REG_OPS{
        RTL8152_REQT_READ    = 0xc0,
        RTL8152_REQT_WRITE   = 0x40,
        RTL8152_REQ_GET_REGS = 0x05,
        RTL8152_REQ_SET_REGS = 0x05
};

enum RTL81XX_INTERFACE_MODE{
	RTL81XX_PROMISC_MODE   = 0,
	RTL81XX_MULTICAST_MODE = 1,
};

struct tx_desc {
	__le32 opts1;
#define TX_FS			BIT(31) /* First segment of a packet */
#define TX_LS			BIT(30) /* Final segment of a packet */
#define GTSENDV4		BIT(28)
#define GTSENDV6		BIT(27)
#define GTTCPHO_SHIFT		18
#define GTTCPHO_MAX		0x7fU
#define TX_LEN_MAX		0x3ffffU
	__le32 opts2;
#define UDP_CS			BIT(31) /* Calculate UDP/IP checksum */
#define TCP_CS			BIT(30) /* Calculate TCP/IP checksum */
#define IPV4_CS			BIT(29) /* Calculate IPv4 checksum */
#define IPV6_CS			BIT(28) /* Calculate IPv6 checksum */
#define MSS_SHIFT		17
#define MSS_MAX			0x7ffU
#define TCPHO_SHIFT		17
#define TCPHO_MAX		0x7ffU
#define TX_VLAN_TAG		BIT(16)
};

#if DEBUG_V1
        #pragma message("DEBUG_V1 FEATURE IS ENABLED!")
        static inline bool return_debug_choose(unsigned char *n){
                if( strstr(n, "WRITE") ){
			#if DEBUG_WRITE_OPS == 1
				return TRUE;
			#else
                        	return FALSE;
			#endif
                }else{
                        return TRUE;
                }
        }

        #define xstr(a) str(a)
        #define str(a) #a
        #if DEBUG_WITH_COLORS == 1
                #define DEBUG_RTL81XX(function){                        \
                        function;                                       \
                        if( return_debug_choose(xstr(function)) ){      \
                                printf("[" BOLD "%s" RESET "][line " BOLD "%d" RESET "] %s returns %u\n", __FUNCTION__, __LINE__, xstr(function), return_context);       \
                                }                                                                                                                                        \
                        }
        #else
                #define DEBUG_RTL81XX(function){                                                                                        \
                        function;                                                                                                       \
                        if( return_debug_choose(xstr(function)) ){                                                                      \
                                printf("[%s][line: %d] %s returns %u\n", __FUNCTION__, __LINE__, xstr(function), return_context);       \
                                }                                                                                                       \
                        }
        #endif
#else
        #pragma message("DEBUG_V1 FEATURE IS DISABLED!")
        #define DEBUG_RTL81XX(function)
#endif

#if DEBUG_V2
        #pragma message("DEBUG_V2 FEATURE IS ENABLED!")
	#define RTL81XX_DISABLE_INSTRUMENT	__attribute__((no_instrument_function))
        RTL81XX_DISABLE_INSTRUMENT void __cyg_profile_func_enter(void *this_fn, void *call_site){
		printf("Function name: %pS\n", __builtin_return_address(0));
	}
	RTL81XX_DISABLE_INSTRUMENT void __cyg_profile_func_exit(void *this_fn, void *call_site){}

#else
        #pragma message("DEBUG_V2 FEATURE IS DISABLED")
	#define RTL81XX_DISABLE_INSTRUMENT
#endif

/** prototypes of every Misc functions **/
RTL_PLUGIN_IO_OPTIMIZE static inline bool RTL81XX_IS_VALID_ETHER_ADDR(const uint8_t *addr);
RTL_PLUGIN_IO_OPTIMIZE static inline bool RTL81XX_IS_ZERO_ETHER_ADDR(const uint8_t *addr);
RTL_PLUGIN_IO_OPTIMIZE static inline bool RTL81XX_IS_MULTICAST_ETHER_ADDR(const uint8_t *addr);

/** prototypes of every primitive **/
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_MANIP_REG(uint16_t value, uint16_t index, uint16_t size, unsigned char *data, enum RTL81XX_REG_OPS OPS);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_GENERIC_REG_READ(uint16_t index, uint16_t size, void *data, uint16_t type);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_GENERIC_REG_WRITE(uint16_t index, uint16_t byteen, uint16_t size, void *data, uint16_t type);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_READ(uint16_t type, uint16_t index);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_WRITE(uint16_t type, uint16_t index, uint32_t data);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_READ_WORD(uint16_t type, uint16_t index);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_WRITE_WORD(uint16_t type, uint16_t index, uint32_t data);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_READ_DWORD(uint16_t type, uint16_t index);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_WRITE_DWORD(uint16_t type, uint16_t index, uint32_t data);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_REG_READ(uint16_t addr);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_REG_WRITE(uint16_t addr, uint16_t data);
RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_IO_SRAM(unsigned char op_type, uint16_t addr, uint16_t data);

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_INIT(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_POST_INIT(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_DISABLE(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_NIC_RESET(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_HW_PHY_WORK(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_RX_VLAN_ENABLE(unsigned char enable);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_INITIALIZE_USB_INTERFACE(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_GET_HW_VERSION(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_ASSIGN_MTU(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_GET_WOWLAN(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SET_WOWLAN(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_PHY_PATCH_REQUEST(bool request, bool wait);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_ENABLE_GREEN_FEATURE(bool enable);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_DEINITIALIZE_USB_INTERFACE(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SET_MAC_ADDR(unsigned char new_mac_addr[MAC_ADDR_LEN]);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SET_RX_MODE(enum RTL81XX_INTERFACE_MODE mode);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_LOAD_FIRMWARE(bool power_cut);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_DO_TRANSMIT(void *tx_buf, unsigned int tx_len);

/** DEVICE SPECIFIC INIT AND EXIT FUNCTIONS **/
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_HW_PHY_CFG(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_INIT(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_EXIT(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_CHANGE_MTU(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_UP(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_DOWN(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156_GET_EEE(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156_SET_EEE(void);

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8153_INIT(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL8153_EXIT(void);
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SHUTDOWN(void);

#ifdef DEBUG
	static inline void RTL81XX_PRINT(char function_level, ...);
	static inline void RTL81XX_DUMP_ROM(void);
#endif


enum usbdev_enum_t{
	RTL8153,
	RTL8156B,
	RTL_NULL,
};


PLUGIN_STRUCT_OPT struct plugin_context{
	short 		PLUGIN_ID;
	short 		PLUGIN_CONTROLLED_ID;
	short 		CONTEXT_CURRENT_FLAGS;
	short		CONTEXT_GENERIC_INPUT_OPERATIONS;
	void 		*CONTEXT_GENERIC_DATA_BUFFER;
	unsigned	CONTEXT_GENERIC_DATA_SIZE;
	/** --- for vendor defined features --- **/
	short	 	CONTEXT_VENDOR_FLAGS;
	void	 	*CONTEXT_VENDOR_DATA_BUFFER;
	unsigned 	CONTEXT_VENDOR_DATA_SIZE;
};

extern struct plugin_context global_plugin_context_controller_instance;

/** -------THIS WILL BE ENCRYPTED------- **/
PLUGIN_SPECIFIC_STRUCT_OPT(void *) struct plugin_cb_installer{
	void (*plugin_handle_pm)(struct plugin_context *passed_ctx);
	void (*plugin_handle_rx)(struct plugin_context *passed_ctx);
	void (*plugin_handle_tx)(struct plugin_context *passed_ctx);
	void (*plugin_handle_tui)(struct plugin_context *passed_ctx);
	void (*plugin_handle_vendor_features)(struct plugin_context *passed_ctx);
	void (*plugin_handle_debugging)(struct plugin_context *passed_ctx);
	void (*plugin_handle_emergency)(void);
};

/** -------THIS WILL BE ENCRYPTED------- **/
PLUGIN_SPECIFIC_STRUCT_OPT(void *) struct usbdev_ops{
	void (*rtl_init)(void);
	void (*rtl_exit)(void);
	void (*rtl_tx)(void *tx_buffer, unsigned tx_size, unsigned timeout);
	void (*rtl_rx)(void *rx_buffer, unsigned rx_size, unsigned timeout);
	void (*rtl_intf_up)(char rtl_index, unsigned timeout);
	void (*rtl_intf_down)();
	void (*rtl_unload)(void);
	void (*rtl_get_eee)(void);
	void (*rtl_set_eee)(void);
	void (*rtl_nic_reset)(void);
	void (*rtl_open)(void);
	void (*rtl_close)(void);
	void (*rtl_set_rx_mode)(void);
	void (*rtl_set_mac_addr)(void);
	void (*rtl_set_features)(void);
	void (*rtl_set_packet_filter)(void);
	void (*rtl_reset_packet_filter)(void);
	void *rtl_io_ops;	/** for this driver is unused **/
}rtl_ops[] = {
	[RTL8153]  = {
		.rtl_init 	= RTL8153_INIT,
		.rtl_exit 	= RTL8153_EXIT,
		.rtl_tx  	= NULL,
		.rtl_rx   	= NULL,
	},
	[RTL8156B] = {
		.rtl_init 	= RTL8156B_INIT,

	},

};


PLUGIN_SPECIFIC_STRUCT_OPT(unsigned long) struct device_flags{
	unsigned long flags;
	unsigned long capabilities;
	unsigned long rx_timeout;
	unsigned long tx_timeout;
};

#ifndef RTL_VER_SIZE
        #define RTL_VER_SIZE            32
#endif


enum fw_blob_name_idx{
	RTL81XX_FIRMWARE_BLOB_8153A_2,
	RTL81XX_FIRMWARE_BLOB_8153A_3,
	RTL81XX_FIRMWARE_BLOB_8153A_4,
	RTL81XX_FIRMWARE_BLOB_8153B_2,
	RTL81XX_FIRMWARE_BLOB_8153C_1,
	RTL81XX_FIRMWARE_BLOB_8156A_2,
	RTL81XX_FIRMWARE_BLOB_8156B_2,
};

unsigned char *fw_blob_names[] = {
	[RTL81XX_FIRMWARE_BLOB_8153A_2] = "rtl8153a-2.fw",
	[RTL81XX_FIRMWARE_BLOB_8153A_3] = "rtl8153a-3.fw",
	[RTL81XX_FIRMWARE_BLOB_8153A_4] = "rtl8153a-4.fw",
	[RTL81XX_FIRMWARE_BLOB_8153B_2] = "rtl8153b-2.fw",
	[RTL81XX_FIRMWARE_BLOB_8153C_1] = "rtl8153c-1.fw",
	[RTL81XX_FIRMWARE_BLOB_8156A_2] = "rtl8156a-2.fw",
	[RTL81XX_FIRMWARE_BLOB_8156B_2] = "RTL8156B"
};

PLUGIN_STRUCT_OPT struct fw_block{
        __le32 type;
        __le32 length;
};

PLUGIN_STRUCT_OPT struct fw_phy_nc {
	struct fw_block blk_hdr;
	__le16 fw_offset;
	__le16 fw_reg;
	__le16 ba_reg;
	__le16 ba_data;
	__le16 patch_en_addr;
	__le16 patch_en_value;
	__le16 mode_reg;
	__le16 mode_pre;
	__le16 mode_post;
	__le16 reserved;
	__le16 bp_start;
	__le16 bp_num;
	__le16 bp[4];
	char info[];
};

PLUGIN_STRUCT_OPT struct fw_phy_set{
	__le16 addr;
	__le16 data;
};


PLUGIN_STRUCT_OPT struct fw_phy_speed_up{
	struct fw_block blk_hdr;
	__le16 fw_offset;
	__le16 version;
	__le16 fw_reg;
	__le16 reserved;
	char info[];
};

PLUGIN_STRUCT_OPT struct fw_phy_fixup{
	struct fw_block blk_hdr;
	struct fw_phy_set setting;
	__le16 bit_cmd;
	__le16 reserved;
};

PLUGIN_STRUCT_OPT struct fw_phy_union{
	struct fw_block blk_hdr;
	__le16 fw_offset;
	__le16 fw_reg;
	struct fw_phy_set pre_set[2];
	struct fw_phy_set bp[8];
	struct fw_phy_set bp_en;
	uint8_t pre_num;
	uint8_t bp_num;
	char info[];
};

PLUGIN_STRUCT_OPT struct fw_phy_patch_key{
	struct fw_block blk_hdr;
	__le16 key_reg;
	__le16 key_data;
	__le32 reserved;
};

PLUGIN_STRUCT_OPT struct fw_header{
        uint8_t checksum[32];
        unsigned char version[RTL_VER_SIZE];
	struct fw_block blocks[];
};

PLUGIN_STRUCT_OPT struct fw_mac{
	struct fw_block blk_hdr;
	__le16 fw_offset;
	__le16 fw_reg;
	__le16 bp_ba_addr;
	__le16 bp_ba_value;
	__le16 bp_en_addr;
	__le16 bp_en_value;
	__le16 bp_start;
	__le16 bp_num;
	__le16 bp[16]; /* any value determined by firmware */
	__le32 reserved;
	__le16 fw_ver_reg;
	uint8_t fw_ver_data;
	char info[];
};

#ifndef MAX_FW_DATA_LEN
	#define MAX_FW_DATA_LEN	12610
#endif

PLUGIN_STRUCT_OPT struct firmware{
	unsigned char *fw_name;
	unsigned long fw_size;
	unsigned char fw_data[MAX_FW_DATA_LEN];
};

__attribute__((section(".fw"))) struct firmware firmware_array[] = {
	[RTL8153]  = {
		.fw_name = "RTL8153",
		.fw_data = {
			#include "8153.h"
		},
	},
	[RTL8156B] = {
		.fw_name = "RTL8156B",
		.fw_size = 5448,
		.fw_data = {
			#include "8156.h"
		},
	},
};

PLUGIN_STRUCT_OPT struct device_firmware{
	unsigned char 		*device_fw_blob_name;
	unsigned char 		*device_fw_blob_start;
	unsigned int  		 device_fw_blob_size;
	void			(*device_pre_fw_loading)(void);
	void			(*device_post_fw_loading)(void);
        struct device_firmware  *device_fw_chain_next;
        struct device_firmware  *device_fw_chain_prev;
};

/** -------THIS WILL BE ENCRYPTED------- **/
PLUGIN_STRUCT_OPT struct usbdev_identifier{
	unsigned char *device_name;
	unsigned long device_pid;
	unsigned long device_vid;
	unsigned long device_version_identifier;
	unsigned long device_max_mtu;
	struct libusb_device_handle *device_handler;
	struct device_firmware	    *device_firmware;
	struct ethtool_eee	    *device_eee;
	struct usbdev_ops	    *device_cb;
	struct device_flags	    dev_flags;
	void        		    *dev_priv_data;
};

RTL_PLUGIN_OPS_SECTION struct usbdev_identifier RTL81XX_LIST[] = {
	[RTL8153] = {
		.device_name 			= "RTL8153",
		.device_pid  			= 0x2357,
		.device_vid  			= 0x0601,
		.device_version_identifier	= 0x00,
		.device_handler 		= NULL,
		.device_cb      		= NULL,
	},

	[RTL8156B] = {
		.device_name 			= "RTL8156B",
		.device_pid 			= 0xA69C, //0x0bda,
		.device_vid 			= 0x88dd, //0x8156,
		.device_version_identifier 	= 0x00,
		.device_handler 		= NULL,
		.device_cb			= NULL,
		.device_firmware		= NULL,
	},
	[RTL_NULL] = {
		.device_name 			= NULL,
		.device_pid 			= 0x00,
		.device_vid 			= 0x00,
		.device_version_identifier 	= 0x00,
		.device_handler 		= NULL,
		.device_cb			= NULL,
	}
};

/** GLOBAL VARIABLES MAIN DECLARATION **/
struct   usbdev_identifier	*device_context 	= NULL;
unsigned char			*data_context 		= NULL;
signed   int			return_context 		= 0;
signed   int			wolopts 		= 0;
uint16_t			global_ocp_base         = 0;

enum error_handler_t{
	NO_ERROR,
	ERROR_DEV_NOT_FOUND = 1,
	FAILED_TO_GET_DUMP,
	ERROR_INVALID_ARGS,
	ERROR_INVALID_SIZE,
	ERROR_OUT_OF_TIME,
	ERROR_FAILED_TO_IDENTIFY_ADAPTER,
	ERROR_FAILED_TO_READ_HW_VERSION,
	ERROR_OPERATION_NOT_SUPPORTED,
	ERROR_MAXIMUN_VALUE_POSSIBLE,
};

enum error_def{
	ERROR_DEFINITION_SUCCESS,
	ERROR_INVALICABLE,
	ERROR_DEBUG,
};

#if DEBUG_V1 == 1 || DEBUG_V2 == 1
struct error_translation_handler_t{
	unsigned char *ERROR_STRING;
	enum error_def ERROR_DEFINITION;
	unsigned char  IS_ABORTABLE : 1;
	signed char  SHUTDOWN_TIMEOUT : 1;		/** second number to wait before shutting down the entire program,  -1 for NO SHUTDOWN**/
}PLUGIN_STRUCT_OPT error_translation[] = {
	[NO_ERROR] = {
		.ERROR_STRING 	  = "success",
		.ERROR_DEFINITION = ERROR_DEFINITION_SUCCESS,
		.IS_ABORTABLE     = FALSE,
		.SHUTDOWN_TIMEOUT = -1,
	},
	[ERROR_DEV_NOT_FOUND] = {
		.ERROR_STRING     = "device not found in the USB bus!",
		.ERROR_DEFINITION = ERROR_INVALICABLE,
		.IS_ABORTABLE	  = TRUE,
		.SHUTDOWN_TIMEOUT = 1,
	},
	[FAILED_TO_GET_DUMP] = {
		.ERROR_STRING	  = "failed to get the BOOT ROM firmware dump!",
		.ERROR_DEFINITION = ERROR_DEBUG,
		.IS_ABORTABLE	  = FALSE,
	},
	[ERROR_INVALID_ARGS] = {
		.ERROR_STRING	  = "invalid args have been passed!",
                .ERROR_DEFINITION = ERROR_INVALICABLE,
                .IS_ABORTABLE     = TRUE,

	},
	[ERROR_INVALID_SIZE] = {
		.ERROR_STRING 	  = "invalid args have mismatching memory related size offset!",
	        .ERROR_DEFINITION = ERROR_INVALICABLE,
                .IS_ABORTABLE     = TRUE,

	},
	[ERROR_FAILED_TO_IDENTIFY_ADAPTER] = {
		.ERROR_STRING	  = "invalid adapter HW value detected, this can be caused by a reading error or a casting problem!",
                .ERROR_DEFINITION = ERROR_INVALICABLE,
                .IS_ABORTABLE     = TRUE,
	},
	[ERROR_FAILED_TO_READ_HW_VERSION] = {
		.ERROR_STRING	  = "failed to find a valid HW version identifier!",
                .ERROR_DEFINITION = ERROR_INVALICABLE,
                .IS_ABORTABLE     = TRUE,
	}
};

static inline void RTL81XX_CATCHDOWN(){
	if( return_context < 0 && return_context < ERROR_MAXIMUN_VALUE_POSSIBLE ){

	}
}

#endif

#ifndef TIMING_COUNTER
	#define TIMING_COUNTER 10
#endif

/** Misc utilities, plan to move them in another file **/

/**
 * is_zero_ether_addr - Determine if give Ethernet address is all zeros.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is all zeroes.
 *
 * Please note: addr must be aligned to u16.
 */
RTL_PLUGIN_IO_OPTIMIZE static inline bool RTL81XX_IS_ZERO_ETHER_ADDR(const uint8_t *addr){
        return( *(const uint16_t *)(addr + 0) | *(const uint16_t *)(addr + 2) | *(const uint16_t *)(addr + 4)) == 0;
}

/**
 * is_multicast_ether_addr - Determine if the Ethernet address is a multicast.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a multicast address.
 * By definition the broadcast address is also a multicast address.
 */
RTL_PLUGIN_IO_OPTIMIZE static inline bool RTL81XX_IS_MULTICAST_ETHER_ADDR(const uint8_t *addr){
        uint16_t a = *(const uint16_t  *)addr;
	#ifdef __BIG_ENDIAN
        	return 0x01 & (a >> ((sizeof(a) * 8) - 8));
	#else
	        return 0x01 & a;
	#endif
}

/**
 * is_valid_ether_addr - Determine if the given Ethernet address is valid
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Check that the Ethernet address (MAC) is not 00:00:00:00:00:00, is not
 * a multicast address, and is not FF:FF:FF:FF:FF:FF.
 *
 * Return true if the address is valid.
 *
 * Please note: addr must be aligned to u16.
 */
RTL_PLUGIN_IO_OPTIMIZE static inline bool RTL81XX_IS_VALID_ETHER_ADDR(const uint8_t *addr){
        /* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
         * explicitly check for it here. */
        return !( RTL81XX_IS_MULTICAST_ETHER_ADDR(addr) ) && !( RTL81XX_IS_ZERO_ETHER_ADDR(addr) );
}


/* let's work on the primitives (R/W) via the usb interface **/

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_MANIP_REG(uint16_t value, uint16_t index, uint16_t size, unsigned char *data, enum RTL81XX_REG_OPS OPS){
	if( data == NULL ){
		data = (unsigned char *)malloc(size);
		memset(data, 0x00, size);
	}
	if( size == 0 ){
		size += 96;
	}
	unsigned char *tmp = (unsigned char *)malloc(size);
	switch(OPS){
	case RTL8152_REQT_WRITE:
				{
				signed int r = 0;
				r = libusb_control_transfer(
						device_context->device_handler,
	                	                RTL8152_REQT_WRITE,
        	                	        RTL8152_REQ_SET_REGS,
						value,
						index,
						tmp,
						size,
						DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG
						);
				return_context = r;
				break;
				}
	case RTL8152_REQT_READ:
				{
				signed int r = 0;
                		r = libusb_control_transfer(
                                                device_context->device_handler,
                                                RTL8152_REQT_READ,
                                                RTL8152_REQ_GET_REGS,
                                                value,
                                                index,
                                                tmp,
                                                size,
                                                DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG
                                                );
				if(r < 0){
					memset(data, 0xFF, size);
				}else{
					memcpy(data, tmp, size);
				}
				return_context = r;
				//printf("%s\n", libusb_error_name(r));
				break;
				}
	default:
		return_context = -ERROR_OPERATION_NOT_SUPPORTED;
	break;
	}
	free(tmp);
	#if DEBUG
		/** STILL TO THIN ON IT **/
		if( OPS == RTL8152_REQT_READ ){
		}
	#endif
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_GENERIC_REG_READ(uint16_t index, uint16_t size, void *data, uint16_t type){
	uint16_t limit = 64;
	int ret = 0;

	if ((size & 3) || !size || (index & 3) || !data){
		return_context = -ERROR_INVALID_ARGS;
		return;
	}

	if ((uint32_t)index + (uint32_t)size > 0xffff){
		return_context = -ERROR_INVALID_SIZE;
		return;
	}
	while (size) {
		if (size > limit) {
			RTL81XX_MANIP_REG(index, type, limit, data, RTL8152_REQT_READ);
			if (return_context < 0){
				break;
			}
			index += limit;
			data += limit;
			size -= limit;
		} else {
			RTL81XX_MANIP_REG(index, type, size, data, RTL8152_REQT_READ);
			if (return_context < 0){
				break;
			}
			index += size;
			data += size;
			size = 0;
			break;
		}
	}

}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_GENERIC_REG_WRITE(uint16_t index, uint16_t byteen, uint16_t size, void *data, uint16_t type){
	uint16_t byteen_start, byteen_end, byen;
	uint16_t limit = 512;
	/* both size and indix must be 4 bytes align */
	if ((size & 3) || !size || (index & 3) || !data){
		return_context = -ERROR_INVALID_ARGS;
		return;
	}

	if ((uint32_t)index + (uint32_t)size > 0xffff){
	        return_context = -ERROR_INVALID_SIZE;
		return;
	}
	#ifndef BYTE_MASK
		#define BYTE_EN_START_MASK		0x0f
		#define BYTE_EN_END_MASK		0xf0
	#endif
	byteen_start = byteen & BYTE_EN_START_MASK;
	byteen_end = byteen & BYTE_EN_END_MASK;
	byen = byteen_start | (byteen_start << 4);
	RTL81XX_MANIP_REG(index, type | byen, 4, data, RTL8152_REQT_WRITE);

	index += 4;
	data += 4;
	size -= 4;

	if (size) {
		size -= 4;

		while (size) {
			if (size > limit) {
				RTL81XX_MANIP_REG(index, type | BYTE_EN_DWORD, limit, data, RTL8152_REQT_WRITE);
				if (return_context < 0){
					return;
				}
				index += limit;
				data += limit;
				size -= limit;
			} else {
				RTL81XX_MANIP_REG(index, type | BYTE_EN_DWORD, size, data, RTL8152_REQT_WRITE);
				if (return_context < 0){
					return;
				}
				index += size;
				data += size;
				size = 0;
				break;
			}
		}

		byen = byteen_end | (byteen_end >> 4);
		RTL81XX_MANIP_REG(index, type | byen, 4, data, RTL8152_REQT_WRITE);
		//if (return_context < 0)
			// todo
	}
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_READ(uint16_t type, uint16_t index){
	uint32_t data = 0;
	__le32 tmp    = 0;
	uint8_t shift = index & 3;

	index &= ~3;

	RTL81XX_GENERIC_REG_READ(index, sizeof(tmp), &tmp, type);

	data = __le32_to_cpu(tmp);
	data >>= (shift * 8);
	data &= 0xff;

	return_context = (uint8_t)data;
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_READ_WORD(uint16_t type, uint16_t index){
	uint32_t data;
	__le32 tmp;
	uint16_t byen = BYTE_EN_WORD;
	uint8_t shift = index & 2;

	index &= ~3;
	byen <<= shift;

	RTL81XX_GENERIC_REG_READ(index, sizeof(tmp), &tmp, type | byen);

	data = __le32_to_cpu(tmp);
	data >>= (shift * 8);
	data &= 0xffff;

	return_context = (uint16_t)data;
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_WRITE(uint16_t type, uint16_t index, uint32_t data){
	uint32_t mask = 0xff;
	__le32 tmp;
	uint16_t byen = BYTE_EN_BYTE;
	uint8_t shift = index & 3;

	data &= mask;

	if (index & 3) {
		byen <<= shift;
		mask <<= (shift * 8);
		data <<= (shift * 8);
		index &= ~3;
	}

	tmp = __cpu_to_le32(data);

	RTL81XX_GENERIC_REG_WRITE(index, byen, sizeof(tmp), &tmp, type);
	return_context = 0;
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_WRITE_WORD(uint16_t type, uint16_t index, uint32_t data){
	uint32_t mask = 0xffff;
	__le32 tmp;
	uint16_t byen = BYTE_EN_WORD;
	uint8_t shift = index & 2;

	data &= mask;

	if (index & 2) {
		byen <<= shift;
		mask <<= (shift * 8);
		data <<= (shift * 8);
		index &= ~3;
	}

	tmp = __cpu_to_le32(data);

	RTL81XX_GENERIC_REG_WRITE(index, byen, sizeof(tmp), &tmp, type);
	return_context = 0;
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_READ_DWORD(uint16_t type, uint16_t index){
	__le32 data = 0;
	RTL81XX_GENERIC_REG_READ(index, sizeof(data), &data, type);
	return_context = __le32_to_cpu(data);
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_WRITE_DWORD(uint16_t type, uint16_t index, uint32_t data){
	__le32 tmp = __cpu_to_le32(data);
	RTL81XX_GENERIC_REG_WRITE(index, BYTE_EN_DWORD, sizeof(tmp), &tmp, type);
	return_context = 0;
}


RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_REG_READ(uint16_t addr){
	uint16_t ocp_base  = 0;
	uint16_t ocp_index = 0;

	ocp_base = addr & 0xf000;
	if (ocp_base != global_ocp_base) {
		RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_OCP_GPHY_BASE, ocp_base);
		global_ocp_base = ocp_base;
	}

	ocp_index = (addr & 0x0fff) | 0xb000;
	RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, ocp_index);

}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_REG_WRITE(uint16_t addr, uint16_t data){
	uint16_t ocp_base  = 0;
	uint16_t ocp_index = 0;
	ocp_base = addr & 0xf000;

	if (ocp_base != global_ocp_base) {
		RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_OCP_GPHY_BASE, ocp_base);
		global_ocp_base = ocp_base;
	}

	ocp_index = (addr & 0x0fff) | 0xb000;
	RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, ocp_index, data);
	return_context = 0;
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_PHY_PATCH_REQUEST(bool request, bool wait){
	uint16_t data  = 0;
	uint16_t check = 0;
	uint32_t ocp_data = 0;

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_PATCH_CMD ) );
        data = return_context;
        if(request){
  		data |= PATCH_REQUEST;
                check = 0;
        }else{
 	       data &= ~PATCH_REQUEST;
               check = PATCH_READY;
        }
        DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_PHY_PATCH_CMD, data ) );
        for (int i = 0; wait && i < 5000; i++) {
        	usleep(1500);
        	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_PATCH_STAT) );
        	ocp_data = return_context;
                if ((ocp_data & PATCH_READY) ^ check){
        	        break;
                 }
        }
        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_PATCH_STAT ) );
        ocp_data = return_context;

	if (request && wait && !(ocp_data & PATCH_READY) ) {
		RTL81XX_PHY_PATCH_REQUEST(false, false);
		DEBUG_PRINTF("[%s][line %d] %s\n", __FUNCTION__, __LINE__, "returned ERROR_OUT_OF_TIME!");
		return_context = -ERROR_OUT_OF_TIME;
		return;
	} else {
		DEBUG_PRINTF("[%s][line %d] %s\n", __FUNCTION__, __LINE__, "returned 0!");
		return_context = 0;
		return;
	}
}

/** static void rtl_hw_phy_work_func_t(struct work_struct *work) **/

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_HW_PHY_WORK(void){



}

/** HW INDEPENDENT FUNCTIONS, WORKS BY SWITCHING THE HW IDENTIFIER **/

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_INIT(void){
	switch(device_context->device_version_identifier){
		case RTL_VER_12:
		case RTL_VER_13:
		case RTL_VER_15:
			device_context->device_cb = &rtl_ops[RTL8156B];
		break;
		case RTL_VER_08:
		case RTL_VER_09:
			device_context->device_cb = &rtl_ops[RTL8153];
		break;
		default:
			device_context->device_cb = NULL;
		break;
	}
	/** let's start the init callback! **/
	if( device_context->device_cb->rtl_init != NULL ){
		device_context->device_cb->rtl_init();
	}else{
		DEBUG_PRINTF("rtl_init callback is missing!\n");
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_DISABLE(void){
	uint32_t ocp_data = 0;
	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_RCR) );
	ocp_data = return_context;
	ocp_data &= ~RCR_ACPT_ALL;
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_DWORD( MCU_TYPE_PLA, PLA_RCR, ocp_data) );

	/** static void rxdy_gated_en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_MISC_1 ) );
		ocp_data = return_context;
		ocp_data |= RXDY_GATED_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_MISC_1, ocp_data) );
	}

	for (short i = 0; i < (DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG * 2); i++) {
		DEBUG_RTL81XX( RTL81XX_OCP_READ( MCU_TYPE_PLA, PLA_OOB_CTRL ) );
		ocp_data = return_context;
		if( (ocp_data & FIFO_EMPTY) == FIFO_EMPTY){
			break;
		}
		usleep(1100);
	}

	for (short i = 0; i < (DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG * 2); i++) {
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_TCR0 ) );
		ocp_data = return_context;
		if( ocp_data & TCR0_TX_EMPTY ){
			break;
		}
		usleep(1100);
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_NIC_RESET(void){
	uint32_t ocp_data = 0;
        switch(device_context->device_version_identifier){
		case RTL_TEST_01:
		case RTL_VER_10:
		case RTL_VER_11:
			DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_PLA, PLA_CR) );
			ocp_data = return_context;
			ocp_data &= ~CR_TE;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_CR, ocp_data) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_BMU_RESET) );
			ocp_data = return_context;
			ocp_data &= ~BMU_RESET_EP_IN;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_BMU_RESET, ocp_data) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_USB_CTRL) );
			ocp_data = return_context;
			ocp_data |= CDC_ECM_EN;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_USB_CTRL, ocp_data) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_PLA, PLA_CR) );
			ocp_data = return_context;
			ocp_data &= ~CR_RE;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_CR, ocp_data) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_BMU_RESET) );
			ocp_data = return_context;
			ocp_data |= BMU_RESET_EP_IN;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_BMU_RESET, ocp_data) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_USB_CTRL) );
			ocp_data = return_context;
			ocp_data &= ~CDC_ECM_EN;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_USB_CTRL, ocp_data) );
		break;
		default:
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_CR, CR_RST) );
			for(short j = 0; j < (DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG * 2); j++) {
				DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_PLA, PLA_CR) );
				ocp_data = return_context;
				if(!ocp_data & CR_RST){
					break;
				}
				usleep(240);
			}
		break;
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_RX_VLAN_ENABLE(unsigned char enable){
        uint32_t ocp_data = 0;
        switch(device_context->device_version_identifier){
		case RTL_VER_01:
		case RTL_VER_02:
		case RTL_VER_03:
		case RTL_VER_04:
		case RTL_VER_05:
		case RTL_VER_06:
		case RTL_VER_07:
		case RTL_VER_08:
		case RTL_VER_09:
		case RTL_VER_14:
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_CPCR) );
			ocp_data = return_context;
			if (enable){
				ocp_data |= CPCR_RX_VLAN;
			}else{
				ocp_data &= ~CPCR_RX_VLAN;
			}
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_CPCR, ocp_data) );
		break;

		case RTL_TEST_01:
		case RTL_VER_10:
		case RTL_VER_11:
		case RTL_VER_12:
		case RTL_VER_13:
		case RTL_VER_15:
		default:
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_RCR1) );
			ocp_data = return_context;
			if(enable){
				ocp_data |= OUTER_VLAN | INNER_VLAN;
			}else{
				ocp_data &= ~(OUTER_VLAN | INNER_VLAN);
			}
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_RCR1, ocp_data) );
		break;
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SET_MAC_ADDR(unsigned char new_mac_addr[MAC_ADDR_LEN]){
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_CRWECR, CRWECR_CONFIG) );
	DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE(PLA_IDR, BYTE_EN_SIX_BYTES, 8, new_mac_addr, MCU_TYPE_PLA) );
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_CRWECR, CRWECR_NORAML) );
	usleep( CONVERT_TO_MS( 20 ) );
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SET_RX_MODE(enum RTL81XX_INTERFACE_MODE mode){
	uint32_t mc_filter[2];	/* Multicast hash filter */
	__le32 tmp[2] = { 0 };

	uint32_t ocp_data = 0;
	DEBUG_RTL81XX( RTL81XX_OCP_READ_DWORD(MCU_TYPE_PLA, PLA_RCR) );
	ocp_data = return_context;
	ocp_data &= ~RCR_ACPT_ALL;
	ocp_data |= RCR_AB | RCR_APM;

	switch(mode){
		case RTL81XX_PROMISC_MODE:
			ocp_data |= RCR_AM | RCR_AAP;
			mc_filter[1] = 0xffffffff;
			mc_filter[0] = 0xffffffff;

		break;

		case RTL81XX_MULTICAST_MODE:
			ocp_data |= RCR_AM;
			mc_filter[1] = 0xffffffff;
			mc_filter[0] = 0xffffffff;
		break;

		default:
			/** do nothing... */
		break;
	}
	tmp[0] = __cpu_to_le32(swab32(mc_filter[1]));
	tmp[1] = __cpu_to_le32(swab32(mc_filter[0]));
	DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE(PLA_MAR, BYTE_EN_DWORD, sizeof(tmp), tmp, MCU_TYPE_PLA) );
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_DWORD(MCU_TYPE_PLA, PLA_RCR, ocp_data) );

}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_LOAD_FIRMWARE(bool power_cut){
	/** FIRST PART: AUTO DETECT THE FIRMWARE BLOB **/
	{

	#define STATIC_STRING_SIZE(x)	(sizeof(x)/sizeof(char))
	/** allocate device_firmware */
	device_context->device_firmware = (struct device_firmware *)malloc(sizeof(struct device_firmware));
	switch(device_context->device_version_identifier){
		case RTL_VER_04:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_2]));
			strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_2], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_2]) );
			DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
			//rtl_fw->pre_fw		= r8153_pre_firmware_1;
			//rtl_fw->post_fw		= r8153_post_firmware_1;
		break;
		case RTL_VER_05:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_3]));
                        strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_3], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_3]) );
                        DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
			//rtl_fw->pre_fw		= r8153_pre_firmware_2;
			//rtl_fw->post_fw		= r8153_post_firmware_2;
		break;
		case RTL_VER_06:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_4]));
                        strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_4], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153A_4]) );
		        #if DEBUG_V1 == 1 || DEBUG_V2 == 1
                                DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
                        #endif
			//rtl_fw->post_fw		= r8153_post_firmware_3;
		break;
		case RTL_VER_09:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153B_2]));
                        strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153B_2], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153B_2]) );
		        #if DEBUG_V1 == 1 || DEBUG_V2 == 1
                                DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
                        #endif
			//rtl_fw->pre_fw		= r8153b_pre_firmware_1;
			//rtl_fw->post_fw		= r8153b_post_firmware_1;
		break;
		case RTL_VER_11:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153C_1]));
                        strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153C_1], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153C_1]) );
		        #if DEBUG_V1 == 1 || DEBUG_V2 == 1
                                DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
                        #endif
			//rtl_fw->post_fw		= r8156a_post_firmware_1;
		break;
		case RTL_VER_13:
		case RTL_VER_15:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8156B_2]) + 1);
                        strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8156B_2], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8156B_2]) );
                        DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
			/** NOTE: the rtl8156b adapter doesn't have both pre/post fw loading callbacks... **/
			device_context->device_firmware->device_pre_fw_loading  = NULL;
			device_context->device_firmware->device_post_fw_loading = NULL;
		break;
		case RTL_VER_14:
			device_context->device_firmware->device_fw_blob_name = (unsigned char *)malloc(STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153C_1]));
                        strncpy( device_context->device_firmware->device_fw_blob_name, fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153C_1], STATIC_STRING_SIZE(fw_blob_names[RTL81XX_FIRMWARE_BLOB_8153C_1]) );
		        #if DEBUG_V1 == 1 || DEBUG_V2 == 1
                                DEBUG_PRINTF("[%s][line %d] current firmware name is: %s\n", __FUNCTION__, __LINE__, device_context->device_firmware->device_fw_blob_name );
                        #endif
			//rtl_fw->pre_fw		= r8153b_pre_firmware_1;
			//rtl_fw->post_fw		= r8153c_post_firmware_1;
		break;
		default:
			/** THROWN AN EXCEPTION **/
			/** TODO **/
		break;
	}
	}
	/** SECOND PART: PARSE THE FIRMWARE BLOB AND CHOOSE WHAT TO DO **/
	{
		uint16_t key_addr = 0;
		unsigned char patch_phy = 1;
		struct fw_phy_patch_key *key = NULL;
		struct fw_header *fw_hdr = (struct fw_header *)device_context->device_firmware->device_fw_blob_start;

		if( device_context->device_firmware->device_pre_fw_loading != NULL ){
			device_context->device_firmware->device_pre_fw_loading();
		}else{
			DEBUG_PRINTF("the preloading is disabled for this module!\n");
		}

		for(int i = 0; firmware_array[i].fw_name != NULL; i++){
			if( strcmp(device_context->device_firmware->device_fw_blob_name, firmware_array[i].fw_name) == 0 ){
				device_context->device_firmware->device_fw_blob_size = firmware_array[i].fw_size;
				device_context->device_firmware->device_fw_blob_start = &firmware_array[i].fw_data;
				DEBUG_PRINTF("[%s] device blob length is %d\n", device_context->device_firmware->device_fw_blob_name, device_context->device_firmware->device_fw_blob_size);
				#if defined(DEBUG_V1) || defined(DEBUG_V2)
				auto void DEBUG_SHOW_HEX_PRETTY_PRINTF(const void* data, size_t size) {
				        char ascii[17];
        				size_t i, j;
        				ascii[16] = '\0';
					DEBUG_PRINTF("\n");
        				for (i = 0; i < size; ++i) {
                				DEBUG_PRINTF("%02X ", ((unsigned char*)data)[i]);
                				if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
                				        ascii[i % 16] = ((unsigned char*)data)[i];
                				} else {
                        				ascii[i % 16] = '.';
                				}
               	 				if ((i+1) % 8 == 0 || i+1 == size) {
                        			DEBUG_PRINTF(" ");
                        			if ((i+1) % 16 == 0) {
                                			DEBUG_PRINTF("|  %s \n", ascii);
                        			} else if (i+1 == size) {
                                			ascii[(i+1) % 16] = '\0';
                                			if ((i+1) % 16 <= 8) {
                                        			DEBUG_PRINTF(" ");
                                			}
                                		for (j = (i+1) % 16; j < 16; ++j) {
                                        		DEBUG_PRINTF("   ");
                                		}
                                		DEBUG_PRINTF("|  %s \n", ascii);
                        			}
                				}
        				}
					DEBUG_PRINTF("\n");
				}
				DEBUG_PRINTF("[!] DUMPING THE CONTENT OF THE FIRMWARE DATA...\n");
				DEBUG_SHOW_HEX_PRETTY_PRINTF(device_context->device_firmware->device_fw_blob_start, device_context->device_firmware->device_fw_blob_size);
				#endif
				break;
			}
		}

		/** preliminar switch only used for detecting the blocks retrieved from the fw blob **/
		#if ( DEBUG_V1 == 1 ) || ( DEBUG_V2 == 1 )
			for ( short i = offsetof(struct fw_header, blocks); i < device_context->device_firmware->device_fw_blob_size; ){
				struct fw_block *block = (struct fw_block *)&device_context->device_firmware->device_fw_blob_start[i];
				switch (__le32_to_cpu(block->type)){
					case RTL_FW_END:
						DEBUG_PRINTF("[!] catched RTL_FW_END!\n");
					break;
					case RTL_FW_PLA:
					case RTL_FW_USB:
						DEBUG_PRINTF("[!] catched RTL_FW_PLA!\n");
					break;
					case RTL_FW_PHY_START:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_START!\n");
					break;
					case RTL_FW_PHY_STOP:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_STOP!\n");
					break;
					case RTL_FW_PHY_NC:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_NC!\n");
					break;
					case RTL_FW_PHY_VER:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_VER!\n");
					break;
				        case RTL_FW_PHY_UNION_NC:
                                	case RTL_FW_PHY_UNION_NC1:
                                	case RTL_FW_PHY_UNION_NC2:
                                	case RTL_FW_PHY_UNION_UC2:
                                	case RTL_FW_PHY_UNION_UC:
                                	case RTL_FW_PHY_UNION_MISC:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_UNION_NCx!\n");
					break;
					case RTL_FW_PHY_FIXUP:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_FIXUP!\n");
					break;
					case RTL_FW_PHY_SPEED_UP:
						DEBUG_PRINTF("[!] catched RTL_FW_PHY_SPEED_UP!\n");
					break;
				}
				i += ALIGN(__le32_to_cpu(block->length), 8);
			}
		#endif

		for ( short i = offsetof(struct fw_header, blocks); i < device_context->device_firmware->device_fw_blob_size; ){
			struct fw_block *block = (struct fw_block *)&device_context->device_firmware->device_fw_blob_start[i];
			switch (__le32_to_cpu(block->type)){
				case RTL_FW_END:
					goto post_fw;
				case RTL_FW_PLA:
				case RTL_FW_USB:
					/** static void rtl8152_fw_mac_apply(struct r8152 *tp, struct fw_mac *mac) **/
					{
						uint16_t bp_en_addr = 0;
						uint16_t type       = 0;
						uint16_t fw_ver_reg = 0;
						uint32_t length     = 0;
						uint32_t ocp_data   = 0;
						uint8_t *data       = NULL;

						struct fw_mac *mac = (struct fw_mac *)block;
						switch (__le32_to_cpu(mac->blk_hdr.type)) {
							case RTL_FW_PLA:
								type = MCU_TYPE_PLA;
							break;
							case RTL_FW_USB:
								type = MCU_TYPE_USB;
							break;
							default:
								return;
						}

						fw_ver_reg = __le16_to_cpu(mac->fw_ver_reg);
						DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_USB, fw_ver_reg) );
						ocp_data = return_context;
						if (fw_ver_reg && ocp_data >= mac->fw_ver_data) {
							// do nothing..
						}else{

						/** reset ocp_data **/
						ocp_data = 0;
						{
							uint16_t bp[16] = {0};
							uint16_t bp_num = 0;

							switch ( device_context->device_version_identifier ) {
								case RTL_VER_08:
								case RTL_VER_09:
								case RTL_VER_10:
								case RTL_VER_11:
								case RTL_VER_12:
								case RTL_VER_13:
								case RTL_VER_15:
									if (type == MCU_TYPE_USB) {
										DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_BP2_EN, 0 ) );
										bp_num = 16;
										break;
									}
								__attribute__((fallthrough));
								case RTL_VER_03:
								case RTL_VER_04:
								case RTL_VER_05:
								case RTL_VER_06:
									DEBUG_RTL81XX( RTL81XX_OCP_WRITE( type, PLA_BP_EN, 0 ) );
								__attribute__((fallthrough));
								case RTL_VER_01:
								case RTL_VER_02:
								case RTL_VER_07:
									bp_num = 8;
								break;
								case RTL_VER_14:
								default:
									DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( type, USB_BP2_EN, 0 ) );
									bp_num = 16;
									break;
							}

							DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE( PLA_BP_0, BYTE_EN_DWORD, bp_num << 1, bp, type ) );

							/* wait 3 ms to make sure the firmware is stopped */
							usleep(4500);
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( type, PLA_BP_BA, 0 ) );

						}
						/* Enable backup/restore of MACDBG. This is required after clearing PLA
	 					 * break points and before applying the PLA firmware.
	 					 */
						DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_MACDBG_POST ) );
						ocp_data = return_context;

						if ( device_context->device_version_identifier == RTL_VER_04 && type == MCU_TYPE_PLA && ( !(return_context) & DEBUG_OE) ) {
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_MACDBG_PRE, DEBUG_LTSSM) );
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_MACDBG_POST, DEBUG_LTSSM) ) ;
						}

						length = __le32_to_cpu(mac->blk_hdr.length);
						length -= __le16_to_cpu(mac->fw_offset);

						data = (uint8_t *)mac;
						data += __le16_to_cpu(mac->fw_offset);

						DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE(__le16_to_cpu(mac->fw_reg), 0xff, length, data, type) );

						DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(type, __le16_to_cpu(mac->bp_ba_addr), __le16_to_cpu(mac->bp_ba_value)) );

						DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE(__le16_to_cpu(mac->bp_start), BYTE_EN_DWORD, __le16_to_cpu(mac->bp_num) << 1, mac->bp, type) );

						bp_en_addr = __le16_to_cpu(mac->bp_en_addr);
						if (bp_en_addr){
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( type, bp_en_addr, __le16_to_cpu(mac->bp_en_value )) );
						}
						if (fw_ver_reg){
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_USB, fw_ver_reg, mac->fw_ver_data ) );
						}
						}
					}
				break;
				case RTL_FW_PHY_START:
					if (!patch_phy){
						break;
					}
					key = (struct fw_phy_patch_key *)block;
					key_addr = __le16_to_cpu(key->key_reg);
					/** static int rtl_pre_ram_code(struct r8152 *tp, u16 key_addr, u16 patch_key, bool wait) **/
					{
						uint16_t key_a     = key_addr;
						uint16_t patch_key = __le16_to_cpu(key->key_data);
						char     wait      = !power_cut;
						/** static int rtl_phy_patch_request(struct r8152 *tp, bool request, bool wait) **/
						{


						}
						/** static void rtl_patch_key_set(struct r8152 *tp, u16 key_addr, u16 patch_key) **/
						{
							uint16_t key_a     = key_addr;
							uint16_t ptch_key  = patch_key;
							uint16_t data      = 0;
							uint16_t check     = 0;
							uint32_t ocp_data  = 0;
							char request;

						}
					}
				break;
				case RTL_FW_PHY_STOP:
					if (!patch_phy){
						break;
					}
					/** static int rtl_post_ram_code(struct r8152 *tp, u16 key_addr, bool wait) **/
					{
						/** static void rtl_patch_key_set(struct r8152 *tp, u16 key_addr, u16 patch_key) **/
						{
							uint16_t key_a     = key_addr;
							uint16_t patch_key = 0;
							uint16_t data      = 0;
							if(patch_key && key_addr){
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, key_addr, patch_key ) );
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, SRAM_PHY_LOCK, PHY_PATCH_LOCK ) );
							}else if(key_addr){
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x0000, 0x0000 ) );
								DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_LOCK ) );
								data = return_context;
								data &= ~PATCH_LOCK;
								DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_PHY_LOCK, data ) );
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM(RTL81XX_OPTYPE_WRITE, key_addr, 0x0000 ) );
							}
						}
						/** static int rtl_phy_patch_request(struct r8152 *tp, bool request, bool wait) **/
						{
							char wait         = !power_cut;
							char request      = FALSE;
							uint16_t data     = 0;
							uint16_t check    = 0;
							uint32_t ocp_data = 0;
							DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_PATCH_CMD ) );
							data = return_context;
							if(request){
								data |= PATCH_REQUEST;
								check = 0;
							}else{
								data &= ~PATCH_REQUEST;
								check = PATCH_READY;
							}
							DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_PHY_PATCH_CMD, data ) );

							for (int i = 0; wait && i < ( DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG * 10 ); i++) {
								usleep(1500);
								DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_PATCH_STAT ) );
								ocp_data = return_context;
								if ((ocp_data & PATCH_READY) ^ check){
									break;
								}
							}
							DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_PHY_PATCH_STAT ) );
							ocp_data = return_context;
							if( request && wait && !(ocp_data & PATCH_READY) ){
		                                                /** static int rtl_phy_patch_request(struct r8152 *tp, bool request, bool wait) **/
								{

								}

							}
						}
					}
				break;
				case RTL_FW_PHY_NC:
					/** static void rtl8152_fw_phy_nc_apply(struct r8152 *tp, struct fw_phy_nc *phy) **/
					{
						struct fw_phy_nc *phy = (struct fw_phy_nc *)block;
						uint16_t mode_reg = 0;
						uint16_t bp_index = 0;
						uint32_t length   = 0;
						uint32_t  num     = 0;
						__le16 *data      = NULL;

                                                /** reset the global_ocp_base offset **/
                                                global_ocp_base = -1;

						mode_reg = __le16_to_cpu(phy->mode_reg);
						DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, mode_reg, __le16_to_cpu(phy->mode_pre) ) );
						DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, __le16_to_cpu(phy->ba_reg), __le16_to_cpu(phy->ba_data) ) );

						length = __le32_to_cpu(phy->blk_hdr.length);
						length -= __le16_to_cpu(phy->fw_offset);
						num = length / 2;
						data = (__le16 *)((uint8_t *)phy + __le16_to_cpu(phy->fw_offset));

						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_ADDR, __le16_to_cpu(phy->fw_reg) ) );
						for (int i = 0; i < num; i++){
							DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_DATA, __le16_to_cpu(data[i]) ) );
						}
						DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, __le16_to_cpu(phy->patch_en_addr), __le16_to_cpu(phy->patch_en_value)) );

						bp_index = __le16_to_cpu(phy->bp_start);
						num = __le16_to_cpu(phy->bp_num);
						for (int i = 0; i < num; i++) {
							DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, bp_index, __le16_to_cpu(phy->bp[i])) );
							bp_index += 2;
						}
						DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, mode_reg, __le16_to_cpu(phy->mode_post)) );
					}
				break;
				case RTL_FW_PHY_VER:
					//patch_phy = rtl8152_fw_phy_ver(tp, (struct fw_phy_ver *)block);
				break;
				case RTL_FW_PHY_UNION_NC:
				case RTL_FW_PHY_UNION_NC1:
				case RTL_FW_PHY_UNION_NC2:
				case RTL_FW_PHY_UNION_UC2:
				case RTL_FW_PHY_UNION_UC:
				case RTL_FW_PHY_UNION_MISC:
					if (patch_phy){
						/** static void rtl8152_fw_phy_union_apply(struct r8152 *tp, struct fw_phy_union *phy) **/
						{
							struct fw_phy_union *phy = (struct fw_phy_union *)block;
							__le16 *data    = NULL;
							uint32_t length = 0;
							int num = 0;

                                                        /** reset the global_ocp_base offset **/
                                                        global_ocp_base = -1;

							num = phy->pre_num;
							for(int i = 0; i < num; i++){
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, __le16_to_cpu(phy->pre_set[i].addr), __le16_to_cpu(phy->pre_set[i].data)) );
							}
							length = __le32_to_cpu(phy->blk_hdr.length);
							length -= __le16_to_cpu(phy->fw_offset);
							num = length / 2;
							data = (__le16 *)((uint8_t *)phy + __le16_to_cpu(phy->fw_offset));
							DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_ADDR, __le16_to_cpu(phy->fw_reg)) );
							for(int i = 0; i < num; i++){
								DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_DATA, __le16_to_cpu(data[i])) );
							}
							num = phy->bp_num;
							for(int i = 0; i < num; i++){
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, __le16_to_cpu(phy->bp[i].addr), __le16_to_cpu(phy->bp[i].data)) );
							}
							if( phy->bp_num && phy->bp_en.addr ){
								DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, __le16_to_cpu(phy->bp_en.addr), __le16_to_cpu(phy->bp_en.data)) );
							}
						}
					}
				break;
				case RTL_FW_PHY_FIXUP:
					if (patch_phy){
						/** static void rtl8152_fw_phy_fixup(struct r8152 *tp, struct fw_phy_fixup *fix) **/
						{
							uint16_t addr = 0;
							uint16_t data = 0;

							/** reset the global_ocp_base offset **/
							global_ocp_base = -1;

							struct fw_phy_fixup *fix = (struct fw_phy_fixup *)block;
							addr = __le16_to_cpu(fix->setting.addr);
							DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(addr) );
							data = return_context;
							switch (__le16_to_cpu(fix->bit_cmd)) {
								case FW_FIXUP_AND:
									data &= __le16_to_cpu(fix->setting.data);
								break;
								case FW_FIXUP_OR:
									data |= __le16_to_cpu(fix->setting.data);
								break;
								case FW_FIXUP_NOT:
									data &= ~__le16_to_cpu(fix->setting.data);
								break;
								case FW_FIXUP_XOR:
									data ^= __le16_to_cpu(fix->setting.data);
								break;
							default:
							return;
							}
							DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(addr, data) );
						}
					}
				break;
				case RTL_FW_PHY_SPEED_UP:
					/** static void rtl_ram_code_speed_up(struct r8152 *tp, struct fw_phy_speed_up *phy, bool wait) **/
					{
						uint32_t len  	  = 0;
						uint32_t ocp_base = 0;
						uint8_t *data     = NULL;
						uint32_t ocp_data = 0;

						struct fw_phy_speed_up *phy = (struct fw_phy_speed_up *)block;
						bool wait = !power_cut;

					        /** reset the global_ocp_base offset **/
                                                global_ocp_base = -1;

						DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM(RTL81XX_OPTYPE_READ, SRAM_GPHY_FW_VER, 0) );
						ocp_data = return_context;
						if( ocp_data >= __le16_to_cpu(phy->version)){
							// do nothing
						}

						len = __le32_to_cpu(phy->blk_hdr.length);
						DEBUG_PRINTF("[!] initial len value is %d, offset is %d\n", len, __le16_to_cpu(phy->fw_offset));
						len -= __le16_to_cpu(phy->fw_offset);
						data = (uint8_t *)phy + __le16_to_cpu(phy->fw_offset);
                                                /** static int rtl_phy_patch_request(struct r8152 *tp, bool request, bool wait) **/
						RTL81XX_PHY_PATCH_REQUEST(true, wait);
						if (return_context){
							DEBUG_PRINTF("[!] returning from RTL81XX_PHY_PATCH_REQUEST\n");
							return;
						}
						while(len){
							uint32_t size = 0;
							if( len < 2048 ){
								size = len;
							}else{
								size = 2048;
							}
							DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_GPHY_CTRL ) );
							ocp_data = return_context;
							ocp_data |= GPHY_PATCH_DONE | BACKUP_RESTRORE;
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_GPHY_CTRL, ocp_data ) );

							DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE(__le16_to_cpu(phy->fw_reg), 0xff, size, data, MCU_TYPE_USB) );

							data += size;
							len -= size;

							DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_POL_GPIO_CTRL ) );
							ocp_data = return_context;
							ocp_data |= POL_GPHY_PATCH;
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_POL_GPIO_CTRL, ocp_data ) );

							for (short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++) {
								DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_POL_GPIO_CTRL ) );
								ocp_data = return_context;
								if (!(ocp_data) & POL_GPHY_PATCH){
									break;
								}
							}
						}
						/** reset the global_ocp_base offset **/
                                                global_ocp_base = -1;
						RTL81XX_PHY_PATCH_REQUEST(false, wait);
					}
				break;
				default:
					/** DO NOTHING **/
				break;
			}
		i += ALIGN(__le32_to_cpu(block->length), 8);
		}
	post_fw:
		if( device_context->device_firmware->device_post_fw_loading != NULL ){
			device_context->device_firmware->device_post_fw_loading();
		}else{
			DEBUG_PRINTF("[!] device_post_fw_loading is disabled!\n");
		}
		//strncpy(rtl_fw->version, fw_hdr->version, RTL_VER_SIZE);
	        /** reset the global_ocp_base offset **/
                global_ocp_base = -1;
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_DO_TRANSMIT(void *tx_buf, unsigned int tx_len){


}

/** MAIN DETECTION ROUTINE, IT WILL BE MERGED IN THE GENERIC SUBSYSTEM USB INTERFACE SOON! **/
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_INITIALIZE_USB_INTERFACE(void){
	libusb_init(NULL);
        struct libusb_device_handle *dev = NULL;
	for(short j = 0; j < TIMING_COUNTER; j++){
		for(int z = 0; RTL81XX_LIST[z].device_name != NULL; z++){
			dev = libusb_open_device_with_vid_pid(NULL, RTL81XX_LIST[z].device_pid, RTL81XX_LIST[z].device_vid);
			if( dev != NULL ){
				RTL81XX_LIST[z].device_handler = dev;
				// set the device context
				device_context = &RTL81XX_LIST[z];
                                DEBUG_PRINTF("[!] found a new device: %s!\n", device_context->device_name);
				return;
			}
			if( RTL81XX_LIST[z + 1].device_name == NULL ){
				z -= z;
			}
		}

		sleep(TIMING_COUNTER / TIMING_COUNTER);
	}
	DEBUG_PRINTF("[!] failed to search for a new device!\n");
	exit(-ERROR_DEV_NOT_FOUND);
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_GET_HW_VERSION(void){
        __le32 *version_buffer = malloc(sizeof(*version_buffer));
        memset(version_buffer, 0x00, sizeof(*version_buffer));
        if( libusb_control_transfer(
                                device_context->device_handler,
                                RTL8152_REQT_READ,
                                RTL8152_REQ_GET_REGS,
                                PLA_TCR0,
                                0x100,
                                (__le32 *)version_buffer,
                                sizeof(*version_buffer),
                                DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG
                                ) > 0 ){
                #ifndef VERSION_MASK
                        #define VERSION_MASK 0x7cf0
                #endif
                uint32_t ocp_data =  ( __le32_to_cpu(*version_buffer)  >> 16) & VERSION_MASK;
               	if( ocp_data ){
		switch (ocp_data) {
			case 0x4c00:
				device_context->device_version_identifier = RTL_VER_01;
			break;
			case 0x4c10:
				device_context->device_version_identifier = RTL_VER_02;
			break;
			case 0x5c00:
				device_context->device_version_identifier = RTL_VER_03;
			break;
			case 0x5c10:
				device_context->device_version_identifier = RTL_VER_04;
			break;
			case 0x5c20:
				device_context->device_version_identifier = RTL_VER_05;
			break;
			case 0x5c30:
				device_context->device_version_identifier = RTL_VER_06;
			break;
			case 0x4800:
				device_context->device_version_identifier = RTL_VER_07;
			break;
			case 0x6000:
				device_context->device_version_identifier = RTL_VER_08;
			break;
			case 0x6010:
				device_context->device_version_identifier = RTL_VER_09;
			break;
			case 0x7010:
				device_context->device_version_identifier = RTL_TEST_01;
			break;
			case 0x7020:
				device_context->device_version_identifier = RTL_VER_10;
			break;
			case 0x7030:
				device_context->device_version_identifier = RTL_VER_11;
			break;
			case 0x7400:
				device_context->device_version_identifier = RTL_VER_12;
			break;
			case 0x7410:
				device_context->device_version_identifier = RTL_VER_13;
			break;
			case 0x6400:
				device_context->device_version_identifier = RTL_VER_14;
			break;
			case 0x7420:
				device_context->device_version_identifier = RTL_VER_15;
			break;
			default:
				device_context->device_version_identifier = RTL_VER_UNKNOWN;
				if( device_context->device_version_identifier = RTL_VER_UNKNOWN ){
					exit(-ERROR_FAILED_TO_READ_HW_VERSION);
				}
			break;
	}
			DEBUG_PRINTF("[!] THE IDENTIFIED ADAPTER VERSION IS %d\n", ocp_data);
		}
	}else{
			device_context->device_version_identifier = ERROR_FAILED_TO_IDENTIFY_ADAPTER;
			if( device_context->device_version_identifier == ERROR_FAILED_TO_IDENTIFY_ADAPTER ){
				DEBUG_PRINTF("[!] FAILED...\n");
				exit(-ERROR_FAILED_TO_IDENTIFY_ADAPTER);
			}
	}
	free(version_buffer);
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_ASSIGN_MTU(void){
	switch(device_context->device_version_identifier){
		case RTL_VER_03:
		case RTL_VER_04:
		case RTL_VER_05:
		case RTL_VER_06:
		case RTL_VER_08:
		case RTL_VER_09:
		case RTL_VER_14:
			device_context->device_max_mtu = size_to_mtu(9 * 1024);
		break;
		case RTL_VER_10:
		case RTL_VER_11:
			device_context->device_max_mtu = size_to_mtu(15 * 1024);
		break;
		case RTL_VER_12:
		case RTL_VER_13:
		case RTL_VER_15:
			device_context->device_max_mtu = size_to_mtu(16 * 1024);
		break;
		case RTL_VER_01:
		case RTL_VER_02:
		case RTL_VER_07:
		default:
			device_context->device_max_mtu = ETH_DATA_LEN;
		break;
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_ENABLE_GREEN_FEATURE(bool enable){
	uint16_t data = 0;
	if( enable == TRUE ){
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8045, 0 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x804d, 0x1222 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x805d, 0x0022 ) );
	}else{
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8045, 0x2444 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x804D, 0x2444 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x805d, 0x2444 ) );
	}
	/** static void rtl_green_en(struct r8152 *tp, bool enable) **/
	DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, SRAM_GREEN_CFG, 0 ) );
	data = return_context;
	if( enable ){
		data |= GREEN_ETH_EN;
	}else{
		data &= ~GREEN_ETH_EN;
	}
	DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, SRAM_GREEN_CFG, data ) );
}

RTL_PLUGIN_IO_OPTIMIZE static inline void RTL81XX_OCP_IO_SRAM(unsigned char op_type, uint16_t addr, uint16_t data){
	switch(op_type){
		case RTL81XX_OPTYPE_READ:
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_ADDR, addr ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_SRAM_DATA ) );
		break;
		case RTL81XX_OPTYPE_WRITE:
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_ADDR, addr ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_SRAM_DATA, data ) );
		break;
		default:
			/** STILL TO DO **/
		break;
	}
}


#ifdef DEBUG
static inline void RTL81XX_DUMP_ROM(void){
	#ifndef MAX_READ_LEN
		#define MAX_READ_LEN	64000
	#endif
        FILE *ptr = NULL;
        ptr = fopen("FW.bin", "wb");
        short tmp_buffer_s = 16;
        unsigned char *fw_dump = (unsigned char *)malloc(tmp_buffer_s);
        for(int value_counter = 0; value_counter < MAX_READ_LEN; value_counter += tmp_buffer_s){
        if( libusb_control_transfer(
                                device_context->device_handler,
                                RTL8152_REQT_READ,
                                RTL8152_REQ_GET_REGS,
                                value_counter, // value
                                0x100, 	       //index,
                                fw_dump,
                                tmp_buffer_s,
                                DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG
                                ) > 0 ){
                fwrite(fw_dump, tmp_buffer_s, sizeof(char), ptr);
                memset(fw_dump, 0x00, tmp_buffer_s);
        }else{
                DEBUG_PRINTF("[!] fail after %d bytes written...\n", value_counter);
        	free(fw_dump);
	        return_context = -FAILED_TO_GET_DUMP;
 	       }
        }
	free(fw_dump);
}
#endif

/** let's enable the WoWlan feature, which is supported by default since rtl8152 **/
RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_GET_WOWLAN(void){
	uint32_t ocp_data = 0;

	DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_CONFIG ) );

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG34 ) );
	ocp_data = return_context;
	ocp_data &= ~LINK_ON_WAKE_EN;
	if (wolopts & WAKE_PHY){
		ocp_data |= LINK_ON_WAKE_EN;
	}
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CONFIG34, ocp_data ) );

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG5 ) );
	ocp_data = return_context;
	ocp_data &= ~(UWF_EN | BWF_EN | MWF_EN);
	if (wolopts & WAKE_UCAST){
		ocp_data |= UWF_EN;
	}
	if (wolopts & WAKE_BCAST){
		ocp_data |= BWF_EN;
	}
	if (wolopts & WAKE_MCAST){
		ocp_data |= MWF_EN;
	}
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CONFIG5, ocp_data ) );

	DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_NORAML ) );

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CFG_WOL ) );
	ocp_data = return_context;
	ocp_data &= ~MAGIC_EN;
	if (wolopts & WAKE_MAGIC){
		ocp_data |= MAGIC_EN;
	}
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CFG_WOL, ocp_data ) );
	return_context = NO_ERROR;
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_SET_WOWLAN(void){
	uint32_t ocp_data = 0;

	DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_CONFIG ) );

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG34 ) );
	ocp_data = return_context;
	ocp_data &= ~LINK_ON_WAKE_EN;
	if (wolopts & WAKE_PHY){
		ocp_data |= LINK_ON_WAKE_EN;
	}
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CONFIG34, ocp_data) );

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG5 ) );
	ocp_data = return_context;
	ocp_data &= ~(UWF_EN | BWF_EN | MWF_EN);
	if (wolopts & WAKE_UCAST){
		ocp_data |= UWF_EN;
	}
	if (wolopts & WAKE_BCAST){
		ocp_data |= BWF_EN;
	}
	if (wolopts & WAKE_MCAST){
		ocp_data |= MWF_EN;
	}

	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CONFIG5, ocp_data ) );
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_NORAML ) );

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CFG_WOL ) );
	ocp_data = return_context;
	ocp_data &= ~MAGIC_EN;
	if (wolopts & WAKE_MAGIC){
		ocp_data |= MAGIC_EN;
	}
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CFG_WOL, ocp_data ) );
	return_context = NO_ERROR;
}

/** NOTE: RTL8156B_UP is the equivalent for 'rtl8152_open' **/
/** static int rtl8152_open(struct net_device *netdev) **/
//RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_UP(void){
//	int res = 0;


//}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_HW_PHY_CFG(void){
	uint32_t ocp_data = 0;
	uint16_t data     = 0;

	switch ( device_context->device_version_identifier ){
	case RTL_VER_12:
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf86, 0x9000 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xc402 ) );
		data = return_context;
		data |= BIT(10);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xc402, data ) );
		data &= ~BIT(10);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xc402, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbd86, 0x1010 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbd88, 0x1010 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbd4e ) );
		data = return_context;
		data &= ~(BIT(10) | BIT(11));
		data |= BIT(11);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbd4e, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbf46 ) );
		data = return_context;
		data &= ~0xf00;
		data |= 0x700;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf46, data ) );
		break;
	case RTL_VER_13:
	case RTL_VER_15:
                /** static void r8156b_wait_loading_flash(struct r8152 *tp) **/
                {
                	uint32_t ocp_data = 0;
                        uint32_t ocp      = 0;
                        DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_GPHY_CTRL) );
                        ocp_data = return_context;
                        DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_GPHY_CTRL) );
                        ocp = return_context;
                        if( ( ocp_data & GPHY_FLASH ) &&  !(ocp & BYPASS_FLASH)) {
                        	for (short i = 0; i < 100; i++) {
                                	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_GPHY_CTRL) );
                                        ocp_data = return_context;
                                        if ( ocp_data & GPHY_PATCH_DONE ){
                                        	break;
                                        }
                                usleep(1100);
        	        	}
	                }
                }

		break;
	default:
		break;
	}

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_MISC_0 ) );
	ocp_data = return_context;
	if (ocp_data & PCUT_STATUS) {
		ocp_data &= ~PCUT_STATUS;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_MISC_0, ocp_data ) );
	}

        {
                uint16_t _data = 0;
                for (short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++) {
                        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_PHY_STATUS) );
                        _data = return_context;
                        _data &= PHY_STAT_MASK;
                        if(_data == PHY_STAT_LAN_ON || _data == PHY_STAT_PWRDN || _data == PHY_STAT_EXT_INIT) {
                                break;
                        }
                        usleep( CONVERT_TO_MS(20) );
                }
                if (_data == PHY_STAT_EXT_INIT) {
                        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa468) );
                        _data = return_context;
                        _data &= ~(BIT(3) | BIT(1));
                        DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa468, _data) );

                        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa466) );
                        _data = return_context;
                        _data &= ~BIT(0);
                        DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa466, _data) );
                }
		data = _data;
        }

	switch (data) {
	case PHY_STAT_EXT_INIT:
		RTL81XX_LOAD_FIRMWARE( true );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa466 ) );
		data = return_context;
		data &= ~BIT(0);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa466, data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa468 ) );
		data = return_context;
		data &= ~(BIT(3) | BIT(1));
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa468, data ) );
		break;
	case PHY_STAT_LAN_ON:
	case PHY_STAT_PWRDN:
	default:
		RTL81XX_LOAD_FIRMWARE( false );
		break;
	}

	/** static inline int r8152_mdio_read(struct r8152 *tp, u32 reg_addr) **/
        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_BASE_MII + MII_BMCR * 2) );
        data = return_context;

	if (data & BMCR_PDOWN) {
		data &= ~BMCR_PDOWN;
	        /** static inline void r8152_mdio_write(struct r8152 *tp, u32 reg_addr, u32 value) **/
                {
	                DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_BASE_MII + MII_BMCR * 2, data ) );
                }
	}

	/* disable ALDPS before updating the PHY parameters */
	/** static void r8153_aldps_en(struct r8152 *tp, bool enable) **/
	{
		uint16_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_POWER_CFG ) );
		ocp_data = return_context;
		data &= ~EN_ALDPS;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_POWER_CFG, data ) );
		for(char i = 0; i < 20; i++){
			usleep( 1500 );
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, 0xe000 ) );
			if( return_context & 0x0100 ){
				break;
			}
		}
	}

	/* disable EEE before updating the PHY parameters */
	/** static void rtl_eee_enable(struct r8152 *tp, bool enable) **/
	{
		switch( device_context->device_version_identifier ){
			case RTL_VER_01:
			case RTL_VER_02:
			case RTL_VER_07:
				/** static void r8152_eee_en(struct r8152 *tp, bool enable) **/
				{
					uint16_t config1  = 0;
					uint16_t config2  = 0;
					uint16_t config3  = 0;
					uint32_t ocp_data = 0;

					DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EEE_CR ) );
					ocp_data = return_context;
					#ifndef sd_rise_time_mask
						#define fast_snr_mask		0xff80
						#define sd_rise_time_mask	0x0070
					#endif
					/** acquire every value and put them in config1, config2 and config3 **/

					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CONFIG1 ) );
					config1 = return_context & ~sd_rise_time_mask;
					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CONFIG2 ) );
					config2 = return_context;
					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CONFIG3 ) );
					config3 = return_context & ~fast_snr_mask;

					ocp_data &= ~(EEE_RX_EN | EEE_TX_EN);
					config1 &= ~(EEE_10_CAP | EEE_NWAY_EN | TX_QUIET_EN | RX_QUIET_EN);
					config1 |= 7 << 4;
					config2 &= ~(RG_DACQUIET_EN | RG_LDVQUIET_EN);
					config3 |= 0x1ff << 7;

					DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EEE_CR, ocp_data ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CONFIG1, config1 ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CONFIG2, config2 ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CONFIG3, config3 ) );
				}
				/** static void r8152_mmd_write(struct r8152 *tp, u16 dev, u16 reg, u16 data) **/
				{
					/** r8152_mmd_indirect(tp, dev, reg); **/
					{
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_AR, FUN_ADDR | MDIO_MMD_AN ) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_DATA, MDIO_AN_EEE_ADV ) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_AR, FUN_DATA | MDIO_MMD_AN ) );
					}
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_DATA, 0    ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_AR, 0x0000 ) );
				}
			break;
			case RTL_VER_03:
			case RTL_VER_04:
			case RTL_VER_05:
			case RTL_VER_06:
			case RTL_VER_08:
			case RTL_VER_09:
			case RTL_VER_14:
				/** static void r8153_eee_en(struct r8152 *tp, bool enable) **/
				{
					uint32_t ocp_data = 0;
					uint16_t config   = 0;

					DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EEE_CR ) );
					ocp_data = return_context;
					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CFG ) );
					config = return_context;

					ocp_data &= ~(EEE_RX_EN | EEE_TX_EN);
					config &= ~EEE10_EN;

					DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EEE_CR, ocp_data ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CFG, config) );

				}
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_ADV, 0 ) );
			break;
			case RTL_VER_10:
			case RTL_VER_11:
			case RTL_VER_12:
			case RTL_VER_13:
			case RTL_VER_15:
				/** static void r8156_eee_en(struct r8152 *tp, bool enable) **/
				{
					uint16_t config = 0;
					/** static void r8153_eee_en(struct r8152 *tp, bool enable) **/
					{
						uint32_t ocp_data = 0;
						uint16_t config   = 0;

						DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EEE_CR ) );
						ocp_data = return_context;
						DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CFG ) );
						config = return_context;
						ocp_data &= ~(EEE_RX_EN | EEE_TX_EN);
						config &= ~EEE10_EN;
						DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EEE_CR, ocp_data ) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CFG, config ) );
					}
					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_ADV2 ) );
					config = return_context;
					config &= ~MDIO_EEE_2_5GT;
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_ADV2, config ) );
				}
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_ADV, 0 ) );
			break;
			default:
			break;
		}
	}
	/** data = r8153_phy_status(tp, PHY_STAT_LAN_ON) **/;
        {
     	        uint16_t data = 0;
       	        for (short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++) {
 	                DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_PHY_STATUS) );
                        data = return_context;
                        data &= PHY_STAT_MASK;
			if (3) {
				if (data == 3){
					break;
				}
			}
                        if(data == PHY_STAT_LAN_ON || data == PHY_STAT_PWRDN || data == PHY_STAT_EXT_INIT) {
         	               break;
                        }
                usleep( CONVERT_TO_MS(20) );
                }
                if (data == PHY_STAT_EXT_INIT) {
        	        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa468) );
                        data = return_context;
                        data &= ~(BIT(3) | BIT(1));
                        DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa468, data) );

                        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa466) );
                        data = return_context;
                        data &= ~BIT(0);
                        DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa466, data) );
                }
	}

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_PHY_PWR ) );
	ocp_data = return_context;
	ocp_data |= PFM_PWM_SWITCH;
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_PHY_PWR, ocp_data ) );

	switch ( device_context->device_version_identifier ) {
	case RTL_VER_12:
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbc08 ) );
		data = return_context;
		data |= BIT(3) | BIT(2);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbc08, data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x8fff, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x0400;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8fff, data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xacda ) );
		data = return_context;
		data |= 0xff00;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xacda, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xacde ) );
		data = return_context;
		data |= 0xf000;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xacde, data)   );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xac8c, 0x0ffc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xac46, 0xb7b4) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xac50, 0x0fbc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xac3c, 0x9240) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xac4e, 0x0db4) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xacc6, 0x0707) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xacc8, 0xa0d3) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xad08, 0x0007) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8560) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x19cc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8562) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x19cc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8564) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x19cc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8566) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x147d) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8568) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x147d) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x856a) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x147d) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8ffe) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0907) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x80d6) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x2801) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x80f2) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x2801) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x80f4) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x6077) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb506, 0x01e7) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8013) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0700) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fb9) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x2801) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fba) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0100) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fbc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x1900) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fbe) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xe100) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fc0) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0800) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fc2) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xe500) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fc4) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0f00) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fc6) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xf100) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fc8) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0400) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fca) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xf300) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fcc) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xfd00) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fce) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xff00) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fd0) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xfb00) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fd2) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0100) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fd4) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xf400) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fd6) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xff00) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8fd8) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xf600) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ( MCU_TYPE_PLA, PLA_USB_CFG ) );
		ocp_data = return_context;
		ocp_data |= EN_XG_LIP | EN_G_LIP;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_USB_CFG, ocp_data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x813d ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x390e ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x814f ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x790e ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x80b0 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0f31 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbf4c ) );
		data = return_context;
		data |= BIT(1);

		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf4c, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbcca ) );
		data = return_context;
		data |= BIT(9) | BIT(8);

		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xbcca, data  ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xb87c, 0x8141) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xb87e, 0x320e) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xb87c, 0x8153) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xb87e, 0x720e) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xb87c, 0x8529) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(    0xb87e, 0x050e) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CFG ) );
		data = return_context;
		data &= ~CTAP_SHORT_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CFG, data ) );

		{
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x816c, 0xc4a0 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8170, 0xc4a0 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8174, 0x04a0 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8178, 0x04a0 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x817c, 0x0719 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8ff4, 0x0400 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8ff1, 0x0404 ) );
		}

		{
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf4a, 0x001b ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8033 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x7c13 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8037 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x7c13 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x803b ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0xfc32 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x803f ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x7c13 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8043 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x7c13 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8047 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x7c13 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8145 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x370e ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8157 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x770e ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8169 ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x0d0a ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x817b ) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x1d0a ) );
		}

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x8217, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x5000;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8217, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x821a, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x5000;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x821a, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80da, 0x0403 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80dc, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x1000;

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80dc, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80b3, 0x0384 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80b7, 0x2007 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80ba, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x6c00;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80ba, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80b5, 0xf009 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80bd, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x9f00;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80bd, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80c7, 0xf083 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80dd, 0x03f0 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80df, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x1000;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80df, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80cb, 0x2007 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80ce, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x6c00;

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80ce, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80c9, 0x8009 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80d1, 0 ) );
		data &= ~0xff00;
		data |= 0x8000;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80d1, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80a3, 0x200a ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80a5, 0xf0ad ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x809f, 0x6073 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80a1, 0x000b ) );

		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x80a9, 0 ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0xc000;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x80a9, data ) );

		RTL81XX_PHY_PATCH_REQUEST( true, true );
		if( return_context ){
			return;

		}
		{
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xb896 ) );
			data = return_context;
			data &= ~BIT(0);
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb896, data ) );
		}

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xb892 ) );
		data = return_context;
		data &= ~0xff00;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb892, data   ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc23e ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x0000 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc240 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x0103 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc242 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x0507 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc244 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x090b ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc246 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x0c0e ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc248 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x1012 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb88e, 0xc24a ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb890, 0x1416 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xb896 ) );
		data = return_context;
		data |= BIT(0);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb896, data ) );


		RTL81XX_PHY_PATCH_REQUEST( false, true );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa86a ) );
		data = return_context;
		data |= BIT(0);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa86a, data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa6f0 ) );
		data = return_context;
		data |= BIT(0);
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa6f0, data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbfa0, 0xd70d ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbfa2, 0x4100 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbfa4, 0xe868 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbfa6, 0xdc59 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb54c, 0x3c18 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbfa4 ) );
		data = return_context;
		data &= ~BIT(5);

		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbfa4, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, 0x817d, 0 ) );
		data = return_context;
		data |= BIT(12);
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x817d, data ) );

		break;
	case RTL_VER_13:
		/* 2.5G INRX */
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xac46 ) );
		data = return_context;
		data &= ~0x00f0;
		data |= 0x0090;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xac46, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xad30 ) );
		data = return_context;
		data &= ~0x0003;
		data |= 0x0001;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xad30, data ) );
		__attribute__((fallthrough));
	case RTL_VER_15:
		/* EEE parameter */
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x80f5 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x760e ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8107 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, 0x360e ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87c, 0x8551 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xb87e ) );
		data = return_context;
		data &= ~0xff00;
		data |= 0x0800;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xb87e, data ) );

		/* ADC_PGA parameter */
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbf00 ) );
		data = return_context;
		data &= ~0xe000;
		data |= 0xa000;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf00, data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbf46 ) );
		data = return_context;
		data &= ~0x0f00;
		data |= 0x0300;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf46, data ) );

		/* Green Table-PGA, 1G full viterbi */
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8044, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x804a, 0x2317 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8050, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8056, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x805c, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8062, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8068, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x806e, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x8074, 0x2417 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, 0x807a, 0x2417 ) );

		/* XG PLL */
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xbf84 ) );
		data = return_context;
		data &= ~0xe000;
		data |= 0xa000;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xbf84, data ) );
		break;
	default:
		break;
	}

	/* Notify the MAC when the speed is changed to force mode. */
	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_INTR_EN ) );
	data = return_context;
	data |= INTR_SPEED_FORCE;
	DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_INTR_EN, data ) );

	RTL81XX_PHY_PATCH_REQUEST( true, true );
	if( return_context ){
		return;
	}

	DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL4 ) );
	ocp_data = return_context;
	ocp_data |= EEE_SPDWN_EN;
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL4, ocp_data ) );

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_DOWN_SPEED ) );
	data = return_context;
	data &= ~(EN_EEE_100 | EN_EEE_1000);
	data |= EN_10M_CLKDIV;
	DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_DOWN_SPEED, data ) );
	/*
	tp->ups_info._10m_ckdiv = true;
	tp->ups_info.eee_plloff_100 = false;
	tp->ups_info.eee_plloff_giga = false;
	*/

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_POWER_CFG ) );
	data = return_context;
	data &= ~EEE_CLKDIV_EN;
	DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_POWER_CFG, data ) );
	/** tp->ups_info.eee_ckdiv = false; **/

	RTL81XX_PHY_PATCH_REQUEST( false, true );

	/** static void rtl_green_en(struct r8152 *tp, bool enable) **/
	{
		uint16_t data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_READ, SRAM_GREEN_CFG, 0 ) );
		data = return_context;
		data |= GREEN_ETH_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_IO_SRAM( RTL81XX_OPTYPE_WRITE, SRAM_GREEN_CFG, data ) );
	}

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa428 ) );
	data = return_context;
	data &= ~BIT(9);
	DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa428, data ) );
	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa5ea ) );
	data = return_context;
	data &= ~BIT(0);
	DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa5ea, data ) );

	/** static void rtl_eee_enable(struct r8152 *tp, bool enable) **/
	{
		switch( device_context->device_version_identifier ){
			case RTL_VER_01:
			case RTL_VER_02:
			case RTL_VER_07:
			/** static void r8152_eee_en(struct r8152 *tp, bool enable) **/
			{
				#ifndef fast_snr_mask
					#define fast_snr_mask		0xff80
				#endif

				uint16_t config1 = 0;
				uint16_t config2 = 0;
				uint16_t config3 = 0;

				uint32_t ocp_data = 0;

				DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EEE_CR ) );
				ocp_data = return_context;

				DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CONFIG1 ) );
				config1 = return_context & ~sd_rise_time_mask;

				DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CONFIG2 ) );
				config2 = return_context;

				DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CONFIG3 ) );
				config3 = return_context & ~fast_snr_mask;

				ocp_data |= EEE_RX_EN | EEE_TX_EN;
				config1 |= EEE_10_CAP | EEE_NWAY_EN | TX_QUIET_EN | RX_QUIET_EN;
				config1 |= 1 << 4;
				config2 |= RG_DACQUIET_EN | RG_LDVQUIET_EN;
				config3 |= 42 << 7;
				DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EEE_CR, ocp_data ) );
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CONFIG1, config1 ) );
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CONFIG2, config2 ) );
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CONFIG3, config3 ) );
			}

				/** static void r8152_mmd_write(struct r8152 *tp, u16 dev, u16 reg, u16 data) **/
				{
					/** static inline void r8152_mmd_indirect(struct r8152 *tp, u16 dev, u16 reg) **/
					{
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_AR, FUN_ADDR | MDIO_MMD_AN ) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_DATA, MDIO_AN_EEE_ADV ) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_AR, FUN_DATA | MDIO_MMD_AN ) );
					}
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_DATA, MDIO_EEE_100TX ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_AR, 0x0000 ) );
				}
			break;
			case RTL_VER_03:
			case RTL_VER_04:
			case RTL_VER_05:
			case RTL_VER_06:
			case RTL_VER_08:
			case RTL_VER_09:
			case RTL_VER_14:
				/** static void r8153_eee_en(struct r8152 *tp, bool enable) **/
				{
					uint32_t ocp_data = 0;
					uint16_t config   = 0;

					DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EEE_CR ) );
					ocp_data = return_context;
					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CFG ) );
					config = return_context;

					ocp_data |= EEE_RX_EN | EEE_TX_EN;
					config |= EEE10_EN;

					DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EEE_CR, ocp_data ) );
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CFG, config ) );

				}
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_ADV, MDIO_EEE_1000T | MDIO_EEE_100TX ) );
			break;
			case RTL_VER_10:
			case RTL_VER_11:
			case RTL_VER_12:
			case RTL_VER_13:
			case RTL_VER_15:
				/** static void r8156_eee_en(struct r8152 *tp, bool enable) **/
				{
						uint16_t config = 0;

						/** static void r8153_eee_en(struct r8152 *tp, bool enable) **/
						{
							uint32_t ocp_data = 0;
							uint16_t config   = 0;

							DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EEE_CR ) );
							ocp_data = return_context;
							DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_CFG ) );
							config = return_context;

							ocp_data |= EEE_RX_EN | EEE_TX_EN;
							config |= EEE10_EN;
							DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EEE_CR, ocp_data ) );
							DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_CFG, config ) );

						}
						DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_EEE_ADV2 ) );
						config = return_context;
						config |= MDIO_EEE_2_5GT;
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_ADV2, config ) );
				}
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_EEE_ADV, MDIO_EEE_1000T | MDIO_EEE_100TX ) );
			break;
			default:
			break;
		}
	}

        /** static void r8153_aldps_en(struct r8152 *tp, bool enable) **/
        {
                uint16_t data = 0;
                DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_POWER_CFG) );
                data &= ~EN_ALDPS;
                DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(OCP_POWER_CFG, data) );
                for (unsigned char i = 0; i < 20; i++) {
                        usleep(1100);
                        DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, 0xe000) );
                        if( return_context & 0x0100){
                                break;
                        }
                }
        }
	/** static void r8152b_enable_fc(struct r8152 *tp) **/
	{
		uint16_t anar = 0;
	        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_BASE_MII + MII_ADVERTISE * 2) );
		anar = return_context;
		anar |= ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
                /** static inline void r8152_mdio_write(struct r8152 *tp, u32 reg_addr, u32 value) **/
                {
	                DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_BASE_MII + MII_ADVERTISE * 2, anar ) );
                }
	}
	/** static void r8153_u2p3en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_U2P3_CTRL ) );
		ocp_data = return_context;
		ocp_data |= U2P3_ENABLE;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_U2P3_CTRL, ocp_data ) );
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_INIT(void){
	volatile uint32_t ocp_data = 0;
	uint16_t data = 0;

	{
		DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_USB, USB_ECM_OP) );
		ocp_data = return_context;
		ocp_data &= ~EN_ALL_SPEED;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_USB, USB_ECM_OP, ocp_data) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_SPEED_OPTION, 0) );
	}

	{
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_ECM_OPTION) );
		ocp_data = return_context;
		ocp_data |= BYPASS_MAC_RESET;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_ECM_OPTION, ocp_data) );
	}

	{
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_U2P3_CTRL) );
		ocp_data = return_context;
		ocp_data |= RX_DETECT8;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_U2P3_CTRL, ocp_data) );
	}

	/** static void r8153b_u1u2en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_LPM_CONFIG) );
		ocp_data = return_context;
		ocp_data &= ~LPM_U1U2_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_LPM_CONFIG, ocp_data) );
	}
	switch (device_context->device_version_identifier){
		case RTL_VER_13:
		case RTL_VER_15:
			uint32_t ocp_bkp = 0;
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_GPHY_CTRL) );
			ocp_bkp = return_context;
			ocp_bkp &= GPHY_FLASH;
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_GPHY_CTRL) );
			if( ocp_bkp && !(return_context & BYPASS_FLASH ) ){
				for(short i = 0; i < 100; i++) {
					DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_GPHY_CTRL) );
					if( return_context & GPHY_PATCH_DONE ){
						break;
					}
				usleep(1100);
				}
			}
	break;
	default:

	break;
		}

	{

	for(short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++) {
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_BOOT_CTRL) );
	 	if( return_context & AUTOLOAD_DONE ){
			break;
		}
		usleep( CONVERT_TO_MS(20) );
		}
	}
	/** data = r8153_phy_status(tp, 0); **/
	{
		uint16_t data = 0;
		for (short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++) {
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_PHY_STATUS) );
			data = return_context;
			data &= PHY_STAT_MASK;
			if(data == PHY_STAT_LAN_ON || data == PHY_STAT_PWRDN || data == PHY_STAT_EXT_INIT) {
				break;
			}
			usleep( CONVERT_TO_MS(20) );
		}
		if (data == PHY_STAT_EXT_INIT) {
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa468) );
			data = return_context;
			data &= ~(BIT(3) | BIT(1));
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa468, data) );

			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa466) );
			data = return_context;
			data &= ~BIT(0);
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa466, data) );
		}
	}
	/** data = r8152_mdio_read(tp, MII_BMCR); **/
	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_BASE_MII + MII_BMCR * 2) );
	data = return_context;
	if (data & BMCR_PDOWN) {
		data &= ~BMCR_PDOWN;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(OCP_BASE_MII + MII_BMCR * 2, data) );
	}
	/** static u16 r8153_phy_status(struct r8152 *tp, u16 desired) **/
	{
		for(short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++){
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_PHY_STATUS) );
			data = return_context;
			data &= PHY_STAT_MASK;
			if (data == 3){
				break;
			} else if (data == PHY_STAT_LAN_ON || data == PHY_STAT_PWRDN || data == PHY_STAT_EXT_INIT) {
				break;
			}
			usleep( CONVERT_TO_MS( 20 ) );
		}
	}

	/** static void r8153_u2p3en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_U2P3_CTRL) );
		ocp_data = return_context;
		ocp_data &= ~U2P3_ENABLE;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_U2P3_CTRL, ocp_data) );

	}
	{
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_MSC_TIMER, 0x0fff) );
		/* U1/U2/L1 idle timer. 500 us */
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_U1U2_TIMER, 500) );

	}
	/** static void r8153b_power_cut_en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_POWER_CUT) );
		ocp_data = return_context;
		ocp_data &= ~PWR_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_POWER_CUT, ocp_data) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_MISC_0) );
		ocp_data = return_context;
		ocp_data &= ~PCUT_STATUS;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_MISC_0, ocp_data) );

	}
	/** static void r8156_ups_en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		uint32_t ocp 	  = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_USB, USB_POWER_CUT) );
		ocp_data = return_context;

		ocp_data &= ~(UPS_EN | USP_PREWAKE);
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_USB, USB_POWER_CUT, ocp_data) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_USB, USB_MISC_2) );
		ocp_data = return_context;
		ocp_data &= ~UPS_FORCE_PWR_DOWN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_USB, USB_MISC_2, ocp_data) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_MISC_0) );
		ocp = return_context;
		if (ocp & PCUT_STATUS) {
			/** static void r8156b_hw_phy_cfg(struct r8152 *tp) **/
			{
				uint32_t ocp_data = 0;
				uint16_t data     = 0;
			        switch(device_context->device_version_identifier){
					case RTL_VER_12:
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xbf86, 0x9000) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xc402) );
						data = return_context;
						data |= BIT(10);
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xc402, data)   );
						data &= ~BIT(10);
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xc402, data)   );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xbd86, 0x1010) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xbd88, 0x1010) );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xbd4e) );
						data = return_context;
						data &= ~(BIT(10) | BIT(11));
						data |= BIT(11);
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xbd4e, data)   );
						DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xbf46)          );
						data = return_context;
						data &= ~0xf00;
						data |= 0x700;
						DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xbf46, data)   );
					break;
					case RTL_VER_13:
					case RTL_VER_15:
						/** static void r8156b_wait_loading_flash(struct r8152 *tp) **/
						{
							uint32_t ocp_data = 0;
							uint32_t ocp      = 0;
							DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_GPHY_CTRL) );
							ocp_data = return_context;
							DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_GPHY_CTRL) );
							ocp = return_context;
							if( ( ocp_data & GPHY_FLASH ) &&  !(ocp & BYPASS_FLASH)) {
								for (short i = 0; i < 100; i++) {
									DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_GPHY_CTRL) );
									ocp_data = return_context;
									if ( ocp_data & GPHY_PATCH_DONE ){
										break;
									}
								usleep(1100);
								}
							}
						}
					break;

					default:
					break;
				}
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_MISC_0) );
		ocp_data = return_context;
		if( ocp_data & PCUT_STATUS ){
			ocp_data &= ~PCUT_STATUS;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_MISC_0, ocp_data) );
		}
        	/** data = r8153_phy_status(tp, 0); **/
       		{
                	uint16_t data = 0;
                	for (short i = 0; i < DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG; i++) {
                	        DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_PHY_STATUS) );
                	        data = return_context;
                	        data &= PHY_STAT_MASK;
                	        if(data == PHY_STAT_LAN_ON || data == PHY_STAT_PWRDN ||   data == PHY_STAT_EXT_INIT) {
                	                break;
                	        }
                	        usleep( CONVERT_TO_MS( 20 ) );
                	}
                	switch (data){
				case PHY_STAT_EXT_INIT:
					DEBUG_PRINTF("[!] loading the firmware... (TRUE)\n");
					RTL81XX_LOAD_FIRMWARE(TRUE);

					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa466) );
					data = return_context;
					data &= ~BIT(0);
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa466, data) );

					DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(0xa468) );
					data = return_context;
					data &= ~(BIT(3) | BIT(1));
					DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(0xa468, data) );
					break;
				case PHY_STAT_LAN_ON:
				case PHY_STAT_PWRDN:
				default:
					DEBUG_PRINTF("[!] loading the firmware... (FALSE)\n");
					RTL81XX_LOAD_FIRMWARE(FALSE);
				break;
			}
			RTL81XX_ENABLE_GREEN_FEATURE(TRUE);
		}
	}
	}
	/** rtl8152_set_speed(tp, tp->autoneg, tp->speed, tp->duplex, tp->advertising); **/
	/** static int rtl8152_set_speed(struct r8152 *tp, u8 autoneg, u32 speed, u8 duplex, u32 advertising) **/
	{
		/** force the autonegotiation feature, even if the HW did not support it **/
		uint16_t bmcr    = 0;
		uint16_t orig    = 0;
		uint32_t support = 0;
		uint16_t new1    = 0;

		/** static inline int r8152_mdio_read(struct r8152 *tp, u32 reg_addr) **/
		{
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_BASE_MII + MII_ADVERTISE * 2 ) );
			orig = return_context;
		}
		new1 = orig & ~(ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | ADVERTISE_100FULL);
		if( orig != new1 ){
			/** static inline void r8152_mdio_write(struct r8152 *tp, u32 reg_addr, u32 value) **/
			{
				DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_BASE_MII + MII_ADVERTISE * 2, new1) );
			}
		}
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_BASE_MII + MII_CTRL1000 * 2) );
		orig = return_context;
		new1 = orig & ~(ADVERTISE_1000FULL | ADVERTISE_1000HALF);
		if( orig != new1 ){
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_BASE_MII + MII_CTRL1000 * 2, new1 ) );
		}
		/** if ( support 2.5 Gbps ) **/
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_10GBT_CTRL ) );
		orig = return_context;
		new1 = orig & ~MDIO_AN_10GBT_CTRL_ADV2_5G;

		new1 != MDIO_AN_10GBT_CTRL_ADV2_5G;
		if( orig != new1 ){
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_10GBT_CTRL, new1 ) );
		}
		bmcr = BMCR_ANENABLE | BMCR_ANRESTART;

	DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_BASE_MII + MII_BMCR * 2, bmcr ) );
	if( bmcr & BMCR_RESET ){
		for(char i = 0; i < 50; i++){
			usleep( CONVERT_TO_MS(20) );
			DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_BASE_MII + MII_BMCR * 2 ) );
			if( ( return_context & BMCR_RESET ) == 0 ){
				break;
			}
		}
	}
	}
	}
	/** static void r8153_queue_wake(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ( MCU_TYPE_PLA, PLA_INDICATE_FALG ) );
		ocp_data = return_context;
		ocp_data &= ~UPCOMING_RUNTIME_D3;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_INDICATE_FALG, ocp_data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ( MCU_TYPE_PLA, PLA_SUSPEND_FLAG ) );
		ocp_data = return_context;
		ocp_data &= ~LINK_CHG_EVENT;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_SUSPEND_FLAG, ocp_data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EXTRA_STATUS ) );
		ocp_data = return_context;
		ocp_data &= ~LINK_CHANGE_FLAG;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EXTRA_STATUS, ocp_data ) );
	}
	/** static void rtl_runtime_suspend_enable(struct r8152 *tp, bool enable) **/
	{
		/** static void __rtl_set_wol(struct r8152 *tp, u32 wolopts) **/
		{
			uint32_t ocp_data = 0;
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_CONFIG ) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG34 ) );
			ocp_data = return_context;
			ocp_data &= ~LINK_ON_WAKE_EN;
			if (wolopts & WAKE_PHY){
				ocp_data |= LINK_ON_WAKE_EN;
			}
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CONFIG34, ocp_data ) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG5 ) );
			ocp_data = return_context;
			ocp_data &= ~(UWF_EN | BWF_EN | MWF_EN);
			if (wolopts & WAKE_UCAST){
				ocp_data |= UWF_EN;
			}
			if (wolopts & WAKE_BCAST){
				ocp_data |= BWF_EN;
			}
			if (wolopts & WAKE_MCAST){
				ocp_data |= MWF_EN;
			}
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CONFIG5, ocp_data ) );
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_NORAML ) );

			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CFG_WOL ) );
			ocp_data = return_context;
			ocp_data &= ~MAGIC_EN;
			if (wolopts & WAKE_MAGIC){
				ocp_data |= MAGIC_EN;
			}
			DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CFG_WOL, ocp_data ) );
		}
	        uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_CONFIG ) );
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CONFIG34 ) );
		ocp_data = return_context;
		ocp_data &= ~LINK_OFF_WAKE_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CONFIG34, ocp_data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_NORAML ) );
	}
	{
		uint32_t ocp_data = 0;
		uint32_t ocp	  = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_RCR ) );
		ocp_data = return_context;
		ocp_data &= ~SLOT_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RCR, ocp_data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_CPCR ) );
		ocp_data = return_context;
	        ocp_data |= FLOW_CTRL_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_CPCR, ocp_data ) );
		/* enable fc timer and set timer to 600 ms. */
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_FC_TIMER, CTRL_TIMER_EN | (600 / 8) ) );
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_FW_CTRL ) );
		ocp_data = return_context;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_POL_GPIO_CTRL ) );
		ocp = return_context;
		ocp &= DACK_DET_EN;
		if( !ocp ){
			ocp_data  |= FLOW_CTRL_PATCH_2;
		}
		ocp_data &= ~AUTO_SPEEDUP;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_FW_CTRL, ocp_data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_FW_TASK ) );
		ocp_data = return_context;
		ocp_data |= FC_PATCH_TASK;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_FW_TASK, ocp_data ) );
	}
	/** static void r8156_mac_clk_spd(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		/* MAC clock speed down */
		/* aldps_spdwn_ratio, tp10_spdwn_ratio */
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL, 0x0403 ) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL2 ) );
		ocp_data = return_context;
		ocp_data &= ~EEE_SPDWN_RATIO_MASK;
		ocp_data |= MAC_CLK_SPDWN_EN | 0x03; /* eee_spdwn_ratio */
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL2, ocp_data ) );
	}
	{
		uint32_t ocp_data = 0;
		uint32_t ocp = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL3 ) );
		ocp_data = return_context;
		ocp_data &= ~PLA_MCU_SPDWN_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_MAC_PWR_CTRL3, ocp_data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_EXTRA_STATUS ) );
		ocp_data = return_context;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_PHYSTATUS ) );
		ocp = return_context;
		if(ocp & LINK_STATUS){
			ocp_data |= CUR_LINK_OK;
		}else{
			ocp_data &= ~CUR_LINK_OK;
		}
		ocp_data |= POLL_LINK_CHG;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_EXTRA_STATUS, ocp_data ) );
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_USB_CTRL ) );
		ocp_data = return_context;
		ocp_data &= ~(RX_AGG_DISABLE | RX_ZERO_EN);
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_USB_CTRL, ocp_data ) );
	}
	/** static void r8156_mdio_force_mode(struct r8152 *tp) **/
	{
		uint16_t data;
		/* Select force mode through 0xa5b4 bit 15
		 * 0: MDIO force mode
		 * 1: MMD force mode
		 */
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( 0xa5b4 ) );
		data = return_context;
		if (data & BIT(15)) {
			data &= ~BIT(15);
			DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( 0xa5b4, data ) );
		}
	}
	/** static void rtl_tally_reset(struct r8152 *tp) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_RSTTALLY ) );
		ocp_data = return_context;
		ocp_data |= TALLY_RESET;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RSTTALLY, ocp_data ) );
	}
	if( return_context > 0 ){
		/** NOW COMPLETE THE FUNCTION POINTER TABLE OF THE HW SPECIFIC STRUCTURE **/
		rtl_ops[RTL8156B].rtl_exit 	= RTL8156B_EXIT;
		rtl_ops[RTL8156B].rtl_intf_up 	= RTL8156B_UP;
		rtl_ops[RTL8156B].rtl_intf_down = RTL8156B_DOWN;
		rtl_ops[RTL8156B].rtl_get_eee   = RTL8156_GET_EEE;
		rtl_ops[RTL8156B].rtl_set_eee   = RTL8156_SET_EEE;
	}
	DEBUG_PRINTF("[!][%s] initialization finished! everything went fine...\n", device_context->device_firmware->device_fw_blob_name);
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_POST_INIT(void){

	/** static void rtl_hw_phy_work_func_t(struct work_struct *work) **/
	{
		uint32_t ocp_data = 0;
		/** call the pointer to 'tp->rtl_ops.hw_phy_cfg' **/
                /** static void r8156b_hw_phy_cfg(struct r8152 *tp) **/
		{
		
		
		}
	}
	/** static int set_ethernet_addr(struct r8152 *tp, bool in_resume) **/
	{
		int ret = 0;
	        struct sockaddr{
        	        unsigned char signature[1]; /** unused **/
                	unsigned char sa_data[14];
        	};
		struct sockaddr sa = { 0 };

		if( device_context->device_version_identifier == RTL_VER_01 ){
			DEBUG_RTL81XX( RTL81XX_GENERIC_REG_READ(PLA_IDR, 8, sa.sa_data, MCU_TYPE_PLA) );
		}else{
			DEBUG_RTL81XX( RTL81XX_GENERIC_REG_READ(PLA_BACKUP, 8, sa.sa_data, MCU_TYPE_PLA) );
		}
		if( RTL81XX_IS_VALID_ETHER_ADDR(sa.sa_data) ){
			DEBUG_PRINTF("the ethernet address inside the chip, is correct...\n");
			/** static int __rtl8152_set_mac_address(struct net_device *netdev, void *p, bool in_resume) **/
			{
				DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_CONFIG ) );
				DEBUG_RTL81XX( RTL81XX_GENERIC_REG_WRITE( PLA_IDR, BYTE_EN_SIX_BYTES, 8, sa.sa_data, MCU_TYPE_PLA) );
				DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_CRWECR, CRWECR_NORAML ) );
			}
		}else{
			DEBUG_PRINTF("the ethernet address inside the chip, is incorrect...\n");
			/** still to decide what to do **/
		}
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_CHANGE_MTU(void){
	uint32_t rx_max_size = mtu_to_size(device_context->device_max_mtu);
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_RMS, rx_max_size) );
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_MTPS, MTPS_JUMBO) );
	/** static void r8156_fc_parameter(struct r8152 *tp) **/
	{
		uint32_t ofc_pause_on_auto  = 0;
		uint32_t ofc_pause_off_auto = 0;
		ofc_pause_on_auto  = (ALIGN(mtu_to_size(device_context->device_max_mtu), 1024) + 6 * 1024);
		ofc_pause_off_auto = (ALIGN(mtu_to_size(device_context->device_max_mtu), 1024) + 14 * 1024);
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RX_FIFO_FULL,  ofc_pause_on_auto / 16 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RX_FIFO_EMPTY, ofc_pause_off_auto / 16 ) );

	}
	/* TX share fifo free credit full threshold */
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_TXFIFO_CTRL, 512 / 64) );
	DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_TXFIFO_FULL, ALIGN(rx_max_size + sizeof(struct tx_desc), 1024) / 16) );

}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_UP(void){
	/** static void r8153b_u1u2en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_LPM_CONFIG) );
		ocp_data = return_context;
		ocp_data &= ~LPM_U1U2_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_LPM_CONFIG, ocp_data) );
	}
	/** static void r8153_u2p3en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_USB, USB_U2P3_CTRL) );
		ocp_data = return_context;
		ocp_data &= ~U2P3_ENABLE;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_USB, USB_U2P3_CTRL, ocp_data) );
	}
	/** static void r8153_aldps_en(struct r8152 *tp, bool enable) **/
	{
		uint16_t data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_POWER_CFG) );
		data &= ~EN_ALDPS;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE(OCP_POWER_CFG, data) );
		for (unsigned char i = 0; i < 20; i++) {
			usleep(1100);
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, 0xe000) );
			if( return_context & 0x0100){
				break;
			}
		}
	}
	/** static void rxdy_gated_en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_MISC_1) );
		ocp_data = return_context;
		ocp_data |= RXDY_GATED_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_MISC_1, ocp_data) );
	}
	/** static void r8153_teredo_off(struct r8152 *tp) **/
	{
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_TEREDO_CFG, 0xff) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_WDT6_CTRL, WDT6_SET_MODE) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_REALWOW_TIMER, 0) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_TEREDO_TIMER, 0)  );
	}
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_DWORD(MCU_TYPE_PLA, PLA_RCR) );
		ocp_data = return_context;
		ocp_data &= ~RCR_ACPT_ALL;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_DWORD(MCU_TYPE_PLA, PLA_RCR, ocp_data) );
	}
	RTL81XX_NIC_RESET();
	/** static void rtl_reset_bmu(struct r8152 *tp) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_USB, USB_BMU_RESET) );
		ocp_data = return_context;
		ocp_data &= ~(BMU_RESET_EP_IN | BMU_RESET_EP_OUT);
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_USB, USB_BMU_RESET, ocp_data) );
		ocp_data |= BMU_RESET_EP_IN | BMU_RESET_EP_OUT;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_USB, USB_BMU_RESET, ocp_data) );
	}
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_PLA, PLA_OOB_CTRL) );
		ocp_data = return_context;
		ocp_data &= ~NOW_IS_OOB;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_OOB_CTRL, ocp_data) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_SFF_STS_7) );
		ocp_data = return_context;
		ocp_data &= ~MCU_BORW_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_SFF_STS_7, ocp_data) );
	}
	char enable_bit = 0;
	RTL81XX_RX_VLAN_ENABLE(enable_bit);
	/** static void rtl8156_change_mtu(struct r8152 *tp) **/
	{
		RTL8156B_CHANGE_MTU();
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_DOWN(void){
	uint32_t ocp_data = 0;

	{
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD(MCU_TYPE_PLA, PLA_MAC_PWR_CTRL3) );
		ocp_data = return_context;
		ocp_data |= PLA_MCU_SPDWN_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD(MCU_TYPE_PLA, PLA_MAC_PWR_CTRL3, ocp_data) );
	}
	/** static void r8153b_u1u2en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_LPM_CONFIG ) );
		ocp_data = return_context;
		ocp_data &= ~LPM_U1U2_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_LPM_CONFIG, ocp_data ) );
	}
	/** static void r8153_u2p3en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_U2P3_CTRL ) );
		ocp_data = return_context;
		ocp_data &= ~U2P3_ENABLE;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_U2P3_CTRL, ocp_data ) );
	}
	/** static void r8153b_power_cut_en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_POWER_CUT ) );
		ocp_data = return_context;
		ocp_data &= ~PWR_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_POWER_CUT, ocp_data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_USB, USB_MISC_0 ) );
		ocp_data = return_context;
		ocp_data &= ~PCUT_STATUS;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_USB, USB_MISC_0, ocp_data ) );
	}
	/** static void r8153_aldps_en(struct r8152 *tp, bool enable) **/
	{
		uint16_t data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_POWER_CFG) );
		data = return_context;
		data &= ~EN_ALDPS;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_POWER_CFG, data ) );
		for (char i = 0; i < 20; i++) {
			usleep(1100);
			DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, 0xe000 ) );
			if( return_context & 0x0100){
				break;
			}
		}
	}
	{
		DEBUG_RTL81XX( RTL81XX_OCP_READ(MCU_TYPE_PLA, PLA_OOB_CTRL) );
		ocp_data = return_context;
		ocp_data &= ~NOW_IS_OOB;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE(MCU_TYPE_PLA, PLA_OOB_CTRL, ocp_data) );
	}

	{
		/* RX FIFO settings for OOB */
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RXFIFO_FULL, 64 / 16 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RX_FIFO_FULL, 1024 / 16 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RX_FIFO_EMPTY, 4096 / 16 ) );
	}

	RTL81XX_DISABLE();
	/** static void rtl_reset_bmu(struct r8152 *tp) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ( MCU_TYPE_USB, USB_BMU_RESET ) );
		ocp_data = return_context;
		ocp_data &= ~(BMU_RESET_EP_IN | BMU_RESET_EP_OUT);
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_USB, USB_BMU_RESET, ocp_data ) );

		ocp_data |= BMU_RESET_EP_IN | BMU_RESET_EP_OUT;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_USB, USB_BMU_RESET, ocp_data) );
	}
	{
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_RMS, 1522 ) );
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_MTPS, MTPS_DEFAULT) );

		/* Clear teredo wake event. bit[15:8] is the teredo wakeup
		 * type. Set it to zero. bits[7:0] are the W1C bits about
		 * the events. Set them to all 1 to clear them.
		 */
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_TEREDO_WAKE_BASE, 0x00ff ) );
		DEBUG_RTL81XX( RTL81XX_OCP_READ( MCU_TYPE_PLA, PLA_OOB_CTRL ) );
		ocp_data = return_context;
		ocp_data |= NOW_IS_OOB;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE( MCU_TYPE_PLA, PLA_OOB_CTRL, ocp_data ) );

		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_SFF_STS_7 ) );
		ocp_data = return_context;
		ocp_data |= MCU_BORW_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_SFF_STS_7, ocp_data ) );
	}
	RTL81XX_RX_VLAN_ENABLE(TRUE);
	/** static void rxdy_gated_en(struct r8152 *tp, bool enable) **/
	{
		uint32_t ocp_data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_READ_WORD( MCU_TYPE_PLA, PLA_MISC_1 ) );
		ocp_data = return_context;
		ocp_data &= ~RXDY_GATED_EN;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_WORD( MCU_TYPE_PLA, PLA_MISC_1, ocp_data ) );
	}
	{
		DEBUG_RTL81XX( RTL81XX_OCP_READ_DWORD( MCU_TYPE_PLA, PLA_RCR ) );
		ocp_data = return_context;
		ocp_data |= RCR_APM | RCR_AM | RCR_AB;
		DEBUG_RTL81XX( RTL81XX_OCP_WRITE_DWORD( MCU_TYPE_PLA, PLA_RCR, ocp_data ) );
	}
	/** static void r8153_aldps_en(struct r8152 *tp, bool enable) **/
	{
		uint16_t data = 0;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_READ( OCP_POWER_CFG ) );
		data = return_context;
		data |= EN_ALDPS;
		DEBUG_RTL81XX( RTL81XX_OCP_REG_WRITE( OCP_POWER_CFG, data ) );
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156_GET_EEE(void){
	uint32_t eee_supported = 0;
	uint32_t adv	       = 0;
	uint32_t lp            = 0;
	uint16_t val 	       = 0;

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_EEE_ABLE) );
	val = return_context;

	if(val & MDIO_EEE_100TX){
		eee_supported |= SUPPORTED_100baseT_Full;
	}
	if(val & MDIO_EEE_1000T){
		eee_supported |= SUPPORTED_1000baseT_Full;
	}
	if(val & MDIO_EEE_10GT){
		eee_supported |= SUPPORTED_10000baseT_Full;
	}
	if(val & MDIO_EEE_1000KX){
		eee_supported |= SUPPORTED_1000baseKX_Full;
	}
	if(val & MDIO_EEE_10GKX4){
		eee_supported |= SUPPORTED_10000baseKX4_Full;
	}
	if(val & MDIO_EEE_10GKR){
		eee_supported |= SUPPORTED_10000baseKR_Full;
	}

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_EEE_ADV) );
	val = return_context;

	if(val & MDIO_EEE_100TX){
		adv |= ADVERTISED_100baseT_Full;
	}
	if(val & MDIO_EEE_1000T){
		adv |= ADVERTISED_1000baseT_Full;
	}
	if(val & MDIO_EEE_10GT){
		adv |= ADVERTISED_10000baseT_Full;
	}
	if(val & MDIO_EEE_1000KX){
		adv |= ADVERTISED_1000baseKX_Full;
	}
	if(val & MDIO_EEE_10GKX4){
		adv |= ADVERTISED_10000baseKX4_Full;
	}
	if(val & MDIO_EEE_10GKR){
		adv |= ADVERTISED_10000baseKR_Full;
	}

	DEBUG_RTL81XX( RTL81XX_OCP_REG_READ(OCP_EEE_LPABLE) );
	val = return_context;

	if(val & MDIO_EEE_100TX){
		lp |= ADVERTISED_100baseT_Full;
	}
	if(val & MDIO_EEE_1000T){
		lp |= ADVERTISED_1000baseT_Full;
	}
	if(val & MDIO_EEE_10GT){
		lp |= ADVERTISED_10000baseT_Full;
	}
	if(val & MDIO_EEE_1000KX){
		lp |= ADVERTISED_1000baseKX_Full;
	}
	if(val & MDIO_EEE_10GKX4){
		lp |= ADVERTISED_10000baseKX4_Full;
	}
	if(val & MDIO_EEE_10GKR){
		lp |= ADVERTISED_10000baseKR_Full;
	}
	/** EVERYTHING IS FINISH, NOW WE CAN ASSIGN THE OBTAINED VALUES TO OUR GLOBAL STRUCTURE FOR THE SPECIFIC DEVICE! **/
	device_context->device_eee->eee_active    = !!(eee_supported & adv & lp);
	device_context->device_eee->supported  	  = eee_supported;
	device_context->device_eee->advertised 	  = adv;
	device_context->device_eee->lp_advertised = lp;
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156_SET_EEE(void){
	/** WE MUST SUPPOSE THAT THE 'device_eee' HAS BEEN CHANGED IN ORDER TO MODIFY THE EEE OPTIONS **/
	uint16_t adv = 0;

	if(device_context->device_eee->advertised & ADVERTISED_100baseT_Full){
		adv |= MDIO_EEE_100TX;
	}
	if(device_context->device_eee->advertised & ADVERTISED_1000baseT_Full){
		adv |= MDIO_EEE_1000T;
	}
	if(device_context->device_eee->advertised & ADVERTISED_10000baseT_Full){
		adv |= MDIO_EEE_10GT;
	}
	if(device_context->device_eee->advertised & ADVERTISED_1000baseKX_Full){
		adv |= MDIO_EEE_1000KX;
	}
	if(device_context->device_eee->advertised & ADVERTISED_10000baseKX4_Full){
		adv |= MDIO_EEE_10GKX4;
	}
	if(device_context->device_eee->advertised & ADVERTISED_10000baseKR_Full){
		adv |= MDIO_EEE_10GKR;
	}

	device_context->device_eee->advertised = adv;

	/** static void rtl_eee_enable(struct r8152 *tp, bool enable) **/
	{
		switch(device_context->device_version_identifier){
			case RTL_VER_01:
			case RTL_VER_02:
			case RTL_VER_07:
				/* TODO */
			break;

			case RTL_VER_03:
			case RTL_VER_04:
			case RTL_VER_05:
			case RTL_VER_06:
			case RTL_VER_08:
			case RTL_VER_09:
			case RTL_VER_14:

			break;

			case RTL_VER_10:
			case RTL_VER_11:
			case RTL_VER_12:
			case RTL_VER_13:
			case RTL_VER_15:

			break;

			default:

			break;
		}
	}
}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8153_INIT(void){
	return;

}


RTL81XX_DISABLE_INSTRUMENT static inline void RTL8153_EXIT(void){
	return;

}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL8156B_EXIT(void){
	return;

}

RTL81XX_DISABLE_INSTRUMENT PLUGIN_EXIT static inline void RTL81XX_SHUTDOWN(void){
	if( return_context > 0 ){

	}else{
		#if DEBUG_V1 || DEBUG_V2
		if( return_context <= ERROR_MAXIMUN_VALUE_POSSIBLE && error_translation[return_context].ERROR_STRING != NULL ){

		}
		#endif
		RTL81XX_DEINITIALIZE_USB_INTERFACE();
	}

}

RTL81XX_DISABLE_INSTRUMENT static inline void RTL81XX_DEINITIALIZE_USB_INTERFACE(void){
	libusb_exit(NULL);
}

#if	COMPILE_AS_STANDALONE
RTL81XX_DISABLE_INSTRUMENT int main(int argc, char *argv[], char *envp[]){
	/** this is 'rtl8152_probe_once' **/
	RTL81XX_INITIALIZE_USB_INTERFACE();
	/** reproduce the driver's init sequence **/
	RTL81XX_GET_HW_VERSION();
	/** find out if we can use WoWlan feature **/
	RTL81XX_GET_WOWLAN();
	RTL81XX_ASSIGN_MTU();
	RTL81XX_INIT();
	RTL81XX_POST_INIT();
	return 0;
}
#endif
