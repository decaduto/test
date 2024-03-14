/*
        PLUGIN FOR BLACKFI, made by Edoardo Mantovani, 2023
        Simple plugin for interfacing with the mt7921 hardware, the final goal is to being able to exploit the PHY layer for covert channel and Packet Injection (PiP)
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
#include <stdint.h>

#define DEBUG_V2                0
#define DEBUG_V1                1
#define DEBUG_WRITE_OPS         0
#define DEBUG_WITH_COLORS       1
#define COMPILE_AS_STANDALONE   1
#define ENABLE_OPTIMIZATION     1

#if DEBUG_V1 == 1 && DEBUG_V2 == 1 && FULL_DEBUG == 0
        #error("IS NOT POSSIBLE TO HAVE ENABLED BOTH DEBUG FEATURES AT THE SAME TIME IF TOTAL_DEBUG ISN'T ENABLED...!")
#endif

#endif

/** HW SPECIFIC DECLARATIONS **/
#include "mt7921.h"

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
#include <linux/usb/ch9.h>
#include <libusb-1.0/libusb.h>

#else

/** plan to include baremetal headers here. **/

#endif

/** GENERIC DEFINITIONS, THEY WILL BE MERGED IN THE MAIN PLUGIN INTERFACE SOON! **/
#define TRUE            true
#define FALSE           false
#define MAC_ADDR_LEN    12

#ifndef ALIGN
        #define ALIGN(x, a)     __ALIGN_KERNEL((x), (a))
#endif

#ifndef CONVERT_TO_MS
        #define CONVERT_TO_MS(MSEC)     ( MSEC * 1000 )
#endif

#ifndef DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG
        #define DEFAULT_SLEEP_TIME_FOR_USB_CONTROL_MSG  500
#endif

#ifndef swab32
        #define swab32 __swab32
#endif

#define PLUGIN_STRUCT_OPT       __attribute__((packed))

#ifndef PLUGIN_SPECIFIC_STRUCT_OPT
        #define PLUGIN_SPECIFIC_STRUCT_OPT(align_size)  __attribute__((aligned(sizeof(align_size))))
#endif

#define PLUGIN_PREINIT          __attribute__((constructor))
#define PLUGIN_EXIT             __attribute__((destructor))

#if     DEBUG_WITH_COLORS == 1
        #define BOLD            "\033[1m"
        #define RESET           "\e[m"
        #define CLEAR           "\\033[2K"
        #define UNDERLINE       "\\033[4m"
        #define ERASE_END       "\\033[K"
#endif


#if     ENABLE_OPTIMIZATION
        #pragma message("SPECIFIC I/O FUNCTIONS HAVE THE OPTIMIZATION RULE ENABLED!")
        #define MT_PLUGIN_IO_OPTIMIZE  __attribute__((optimize("-Ofast")))
#else
        #pragma message("SPECIFIC I/O FUNCTIONS HAVE THE OPTIMIZATION RULE DISABLED!")
        #define MT_PLUGIN_IO_OPTIMIZE
#endif

#define MT_PLUGIN_OPS_SECTION  __attribute__((section(".ops")))

#if DEBUG_V1 == 1 || DEBUG_V2 == 1
        //#define DEBUG_PRINTF(...)     __DEBUG_PRINTF("[%s][line %d] %s". __FUNCTION__, __LINE__, __VA_ARGS__);
        #define   DEBUG_PRINTF(...)     __DEBUG_PRINTF(__VA_ARGS__);
        #define __DEBUG_PRINTF(...)     printf(__VA_ARGS__);
#else
        #define DEBUG_PRINTF(...)       {}

#endif

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
                #define DEBUG_MT7921(function){                         \
                        function;                                       \
                        if( return_debug_choose(xstr(function)) ){      \
                                printf("[" BOLD "%s" RESET "][line " BOLD "%d" RESET "] %s returns %u\n", __FUNCTION__, __LINE__, xstr(function), return_context);       \
                                }                                                                                                                                        \
                        }
        #else
                #define DEBUG_MT7921(function){                                                                                         \
                        function;                                                                                                       \
                        if( return_debug_choose(xstr(function)) ){                                                                      \
                                printf("[%s][line: %d] %s returns %u\n", __FUNCTION__, __LINE__, xstr(function), return_context);       \
                                }                                                                                                       \
                        }
        #endif
#else
        #pragma message("DEBUG_V1 FEATURE IS DISABLED!")
        #define DEBUG_MT7921(function)
#endif

#if DEBUG_V2
        #pragma message("DEBUG_V2 FEATURE IS ENABLED!")
        #define MT7921_DISABLE_INSTRUMENT      __attribute__((no_instrument_function))
        MT7921_DISABLE_INSTRUMENT void __cyg_profile_func_enter(void *this_fn, void *call_site){
                printf("Function name: %pS\n", __builtin_return_address(0));
        }
        MT7921_DISABLE_INSTRUMENT void __cyg_profile_func_exit(void *this_fn, void *call_site){}

#else
        #pragma message("DEBUG_V2 FEATURE IS DISABLED")
        #define MT7921_DISABLE_INSTRUMENT
#endif


MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_USB_VENDOR_REQUEST(const uint8_t request, const uint8_t direction, const uint16_t val, const uint16_t offset, void *buf, const size_t buflen);
MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_VENDOR_SINGLE_WRITE(const uint8_t req, const uint16_t offset, const uint32_t val);
MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_VENDOR_RR(uint32_t addr);

MT7921_DISABLE_INSTRUMENT static inline void MT7921_VENDOR_RESET(void);

MT7921_DISABLE_INSTRUMENT static inline void MT7921_INIT(void);
MT7921_DISABLE_INSTRUMENT static inline void MT7921_EXIT(void);

enum usbdev_enum_t{
	MT7921,
        MT7921U,
        MT_NULL,
};


enum mt76_rxq_id {
	MT_RXQ_MAIN,
	MT_RXQ_MCU,
	MT_RXQ_MCU_WA,
	MT_RXQ_BAND1,
	MT_RXQ_BAND1_WA,
	MT_RXQ_MAIN_WA,
	MT_RXQ_BAND2,
	MT_RXQ_BAND2_WA,
	__MT_RXQ_MAX
};


enum mt_usb_ep_out {
	MT_EP_OUT_INBAND_CMD,
	MT_EP_OUT_AC_BK,
	MT_EP_OUT_AC_BE,
	MT_EP_OUT_AC_VI,
	MT_EP_OUT_AC_VO,
	MT_EP_OUT_HCCA,
	__MT_EP_OUT_MAX,
};


enum rx_pkt_type {
	PKT_TYPE_TXS,
	PKT_TYPE_TXRXV,
	PKT_TYPE_NORMAL,
	PKT_TYPE_RX_DUP_RFB,
	PKT_TYPE_RX_TMR,
	PKT_TYPE_RETRIEVE,
	PKT_TYPE_TXRX_NOTIFY,
	PKT_TYPE_RX_EVENT,
	PKT_TYPE_NORMAL_MCU,
	PKT_TYPE_RX_FW_MONITOR	= 0x0c,
	PKT_TYPE_TXRX_NOTIFY_V0	= 0x18,
};


/* event table */
enum {
	MCU_EVENT_TARGET_ADDRESS_LEN = 0x01,
	MCU_EVENT_FW_START = 0x01,
	MCU_EVENT_GENERIC = 0x01,
	MCU_EVENT_ACCESS_REG = 0x02,
	MCU_EVENT_MT_PATCH_SEM = 0x04,
	MCU_EVENT_REG_ACCESS = 0x05,
	MCU_EVENT_LP_INFO = 0x07,
	MCU_EVENT_SCAN_DONE = 0x0d,
	MCU_EVENT_TX_DONE = 0x0f,
	MCU_EVENT_ROC = 0x10,
	MCU_EVENT_BSS_ABSENCE  = 0x11,
	MCU_EVENT_BSS_BEACON_LOSS = 0x13,
	MCU_EVENT_CH_PRIVILEGE = 0x18,
	MCU_EVENT_SCHED_SCAN_DONE = 0x23,
	MCU_EVENT_DBG_MSG = 0x27,
	MCU_EVENT_TXPWR = 0xd0,
	MCU_EVENT_EXT = 0xed,
	MCU_EVENT_RESTART_DL = 0xef,
	MCU_EVENT_COREDUMP = 0xf0,
};

/* ext event table */
enum {
	MCU_EXT_EVENT_RATE_REPORT = 0x87,
};

enum mt_vendor_req {
	MT_VEND_DEV_MODE 	=	0x1,
	MT_VEND_WRITE 		=	0x2,
	MT_VEND_POWER_ON 	=	0x4,
	MT_VEND_MULTI_WRITE 	=	0x6,
	MT_VEND_MULTI_READ 	=	0x7,
	MT_VEND_READ_EEPROM	=	0x9,
	MT_VEND_WRITE_FCE 	=	0x42,
	MT_VEND_WRITE_CFG 	=	0x46,
	MT_VEND_READ_CFG 	=	0x47,
	MT_VEND_READ_EXT 	=	0x63,
	MT_VEND_WRITE_EXT 	=	0x66,
	MT_VEND_FEATURE_SET 	=	0x91,
};

PLUGIN_STRUCT_OPT struct plugin_context{
        short           PLUGIN_ID;
        short           PLUGIN_CONTROLLED_ID;
        short           CONTEXT_CURRENT_FLAGS;
        short           CONTEXT_GENERIC_INPUT_OPERATIONS;
        void            *CONTEXT_GENERIC_DATA_BUFFER;
        unsigned        CONTEXT_GENERIC_DATA_SIZE;
        /** --- for vendor defined features --- **/
        short           CONTEXT_VENDOR_FLAGS;
        void            *CONTEXT_VENDOR_DATA_BUFFER;
        unsigned        CONTEXT_VENDOR_DATA_SIZE;
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
        void (*mtk_init)(void);
        void (*mtk_exit)(void);
        void (*mtk_tx)(void *tx_buffer, unsigned tx_size, unsigned timeout);
        void (*mtk_rx)(void *rx_buffer, unsigned rx_size, unsigned timeout);
        void (*mtk_intf_up)(char mt_index, unsigned timeout);
        void (*mtk_intf_down)();
        void (*mtk_unload)(void);
        void (*mtk_get_eee)(void);
        void (*mtk_set_eee)(void);
        void (*mtk_nic_reset)(void);
        void (*mtk_open)(void);
        void (*mtk_close)(void);
        void (*mtk_set_rx_mode)(void);
        void (*mtk_set_mac_addr)(void);
        void (*mtk_set_features)(void);
        void (*mtk_set_packet_filter)(void);
        void (*mtk_reset_packet_filter)(void);
        void *mtk_io_ops;       /** for this driver is unused **/
}mt_ops[] = {
        [MT7921U]  = {
                .mtk_init       = MT7921_INIT,
                .mtk_exit       = MT7921_EXIT,
                .mtk_tx         = NULL,
                .mtk_rx         = NULL,
        },

};


PLUGIN_SPECIFIC_STRUCT_OPT(unsigned long) struct device_flags{
        unsigned long flags;
        unsigned long capabilities;
        unsigned long rx_timeout;
        unsigned long tx_timeout;
};

PLUGIN_STRUCT_OPT struct device_firmware{
        unsigned char           *device_fw_blob_name;
        unsigned char           *device_fw_blob_start;
        unsigned int             device_fw_blob_size;
        void                    (*device_pre_fw_loading)(void);
        void                    (*device_post_fw_loading)(void);
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
        struct device_firmware      *device_firmware;
        struct ethtool_eee          *device_eee;
        struct usbdev_ops           *device_cb;
        struct device_flags         dev_flags;
        void                        *dev_priv_data;
};

MT_PLUGIN_OPS_SECTION struct usbdev_identifier MT7921_LIST[] = {
	[MT7921]  = {
		.device_name			= "Comfast CF-952 AX",
		.device_pid			= 0x3574,
		.device_vid			= 0x6211,
	},
        [MT7921U] = {
                .device_name                    = "MT7921U",
                .device_pid                     = 0x0e8d,
                .device_vid                     = 0x7961,
                .device_version_identifier      = 0x00,
                .device_handler                 = NULL,
                .device_cb                      = NULL,
        },
        [MT_NULL] = {
                .device_name                    = NULL,
                .device_pid                     = 0x00,
                .device_vid                     = 0x00,
                .device_version_identifier      = 0x00,
                .device_handler                 = NULL,
                .device_cb                      = NULL,
        }
};

/** GLOBAL VARIABLES MAIN DECLARATION **/
struct   usbdev_identifier      *device_context         = NULL;
unsigned char                   *data_context           = NULL;
signed   int                    return_context          = 0;

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

struct mt76_connac2_mcu_rxd {
	__le32 rxd[6];

	__le16 len;
	__le16 pkt_type_id;

	uint8_t eid;
	uint8_t seq;
	uint8_t option;
	uint8_t rsv;
	uint8_t ext_eid;
	uint8_t rsv1[2];
	uint8_t s2d_index;

	uint8_t tlv[];
};


PLUGIN_STRUCT_OPT struct mt7921_mcu_eeprom_info {
	__le32 addr;
	__le32 valid;
	uint8_t data[MT7921_EEPROM_BLOCK_SIZE];
};

#ifndef TIMING_COUNTER
        #define TIMING_COUNTER 10
#endif

MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_USB_VENDOR_REQUEST(const uint8_t request, const uint8_t direction, const uint16_t val, const uint16_t offset, void *buf, const size_t buflen){
	int ret = 0;
	const uint8_t req_type = direction | USB_TYPE_VENDOR | USB_RECIP_DEVICE;

	#ifndef MT_VEND_REQ_TOUT_MS
		#define MT_VEND_REQ_TOUT_MS	300
	#endif
	for(char c = 0; c < MT_VEND_REQ_MAX_RETRY; c++){
		ret = libusb_control_transfer(
					device_context->device_handler,
					req_type,
					request,
					val,
					offset,
					buf,
					buflen,
					MT_VEND_REQ_TOUT_MS
					);

		if( ret >= 0 ){
			return_context = ret;
			return;
		}
		usleep(CONVERT_US_TO_MS(5));
	}
	return_context = -ERROR_OPERATION_NOT_SUPPORTED;
}

MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_VENDOR_SINGLE_WRITE(const uint8_t req, const uint16_t offset, const uint32_t val){
	int ret = 0;

	MT7601U_USB_VENDOR_REQUEST(req, USB_DIR_OUT, val & 0xffff, offset, NULL, 0);
	if (!return_context){
		MT7601U_USB_VENDOR_REQUEST(req, USB_DIR_OUT, val >> 16, offset + 2, NULL, 0);
	}
}

MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_VENDOR_RR(uint32_t addr){
	uint8_t req = 0;

	switch (addr & MT_VEND_TYPE_MASK) {
		case MT_VEND_TYPE_EEPROM:
			req = MT_VEND_READ_EEPROM;
		break;
	case MT_VEND_TYPE_CFG:
			req = MT_VEND_READ_CFG;
		break;
	default:
			req = MT_VEND_MULTI_READ;
		break;
	}
	/** ___mt76u_rr(dev, req, USB_DIR_IN | USB_TYPE_VENDOR, addr & ~MT_VEND_TYPE_MASK); **/
	{
		uint32_t data = ~0;
		unsigned char *usb_data = (unsigned char *)malloc(sizeof(__le32));
		memset(usb_data, 0x00, sizeof(__le32));

		MT7601U_USB_VENDOR_REQUEST(req, USB_DIR_IN | USB_TYPE_VENDOR, ( addr & ~MT_VEND_TYPE_MASK ) >> 16, addr, usb_data, sizeof(__le32));
		if (return_context == sizeof(__le32)){
			data = get_unaligned_le32(usb_data);
			return_context = data;
		}else{
			return_context = -ERROR_OPERATION_NOT_SUPPORTED;
		}
		free(usb_data);
	}
}


MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_COPY(uint32_t offset, const void *data, int len){
	const uint8_t *val = NULL;
	int ret = 0;
	int current_batch_size = 0;
	int i = 0;
	val = data;
	unsigned char *usb_data = NULL;

	len = round_up(len, 4);

	//mutex_lock(&usb->usb_ctrl_mtx);
	usb_data = (unsigned char *)malloc(sizeof(__le32));
	memset(usb_data, 0x00, sizeof(__le32));

	#ifndef usb_data_len
		#define usb_data_len	sizeof(__le32)
	#endif
	while (i < len) {
		current_batch_size = MIN(usb_data_len, len - i);
		memcpy(usb_data, val + i, current_batch_size);
		MT7601U_USB_VENDOR_REQUEST(
					MT_VEND_MULTI_WRITE,
				     	USB_DIR_OUT | USB_TYPE_VENDOR,
				     	0,
					offset + i, usb_data,
				     	current_batch_size
					);
		if (return_context < 0){
			break;
		}
		i += current_batch_size;
	}
	//mutex_unlock(&usb->usb_ctrl_mtx);
	free(usb_data);
}

MT_PLUGIN_IO_OPTIMIZE static inline void MT7601U_READ_COPY(uint32_t offset, void *data, int len){
	int i = 0;
	int batch_len = 0;
	int ret = 0;
	uint8_t *val = data;
	unsigned char *usb_data = NULL;
	len = round_up(len, 4);

	//mutex_lock(&usb->usb_ctrl_mtx);
        usb_data = (unsigned char *)malloc(sizeof(__le32));
        memset(usb_data, 0x00, sizeof(__le32));

	while (i < len) {
		batch_len = MIN(usb_data_len, len - i);
		MT7601U_USB_VENDOR_REQUEST(
					MT_VEND_READ_EXT,
					USB_DIR_IN | USB_TYPE_VENDOR,
					(offset + i) >> 16,
					offset + i,
					usb_data,
					batch_len
					);
		if (return_context < 0){
			break;
		}

		memcpy(val + i, usb_data, batch_len);
		i += batch_len;
	}
	//mutex_unlock(&usb->usb_ctrl_mtx);
	free(usb_data);
}

/** MT792X specific HW functions **/

static int MT76_MCU_FILL_MSG(struct sk_buff *skb, int cmd, int *wait_seq){
	int txd_len, mcu_cmd = FIELD_GET(__MCU_CMD_FIELD_ID, cmd);
	struct mt76_connac2_mcu_uni_txd *uni_txd;
	struct mt76_connac2_mcu_txd *mcu_txd;
	__le32 *txd;
	u32 val;
	u8 seq;

	/* TODO: make dynamic based on msg type */
	dev->mcu.timeout = 20 * HZ;

	seq = ++dev->mcu.msg_seq & 0xf;
	if (!seq)
		seq = ++dev->mcu.msg_seq & 0xf;

	if (cmd == MCU_CMD(FW_SCATTER))
		goto exit;

	txd_len = cmd & __MCU_CMD_FIELD_UNI ? sizeof(*uni_txd) : sizeof(*mcu_txd);
	txd = (__le32 *)skb_push(skb, txd_len);

	val = FIELD_PREP(MT_TXD0_TX_BYTES, skb->len) | FIELD_PREP(MT_TXD0_PKT_FMT, MT_TX_TYPE_CMD) | FIELD_PREP(MT_TXD0_Q_IDX, MT_TX_MCU_PORT_RX_Q0);
	txd[0] = cpu_to_le32(val);

	val = MT_TXD1_LONG_FORMAT |
	      FIELD_PREP(MT_TXD1_HDR_FORMAT, MT_HDR_FORMAT_CMD);
	txd[1] = cpu_to_le32(val);

	if (cmd & __MCU_CMD_FIELD_UNI) {
		uni_txd = (struct mt76_connac2_mcu_uni_txd *)txd;
		uni_txd->len = cpu_to_le16(skb->len - sizeof(uni_txd->txd));
		uni_txd->option = MCU_CMD_UNI_EXT_ACK;
		uni_txd->cid = cpu_to_le16(mcu_cmd);
		uni_txd->s2d_index = MCU_S2D_H2N;
		uni_txd->pkt_type = MCU_PKT_ID;
		uni_txd->seq = seq;

		goto exit;
	}

	mcu_txd = (struct mt76_connac2_mcu_txd *)txd;
	mcu_txd->len = cpu_to_le16(skb->len - sizeof(mcu_txd->txd));
	mcu_txd->pq_id = cpu_to_le16(MCU_PQ_ID(MT_TX_PORT_IDX_MCU, MT_TX_MCU_PORT_RX_Q0));
	mcu_txd->pkt_type = MCU_PKT_ID;
	mcu_txd->seq = seq;
	mcu_txd->cid = mcu_cmd;
	mcu_txd->ext_cid = FIELD_GET(__MCU_CMD_FIELD_EXT_ID, cmd);

	if (mcu_txd->ext_cid || (cmd & __MCU_CMD_FIELD_CE)) {
		if (cmd & __MCU_CMD_FIELD_QUERY)
			mcu_txd->set_query = MCU_Q_QUERY;
		else
			mcu_txd->set_query = MCU_Q_SET;
		mcu_txd->ext_cid_ack = !!mcu_txd->ext_cid;
	} else {
		mcu_txd->set_query = MCU_Q_NA;
	}

	if (cmd & __MCU_CMD_FIELD_WA)
		mcu_txd->s2d_index = MCU_S2D_H2C;
	else
		mcu_txd->s2d_index = MCU_S2D_H2N;

exit:
	if (wait_seq)
		*wait_seq = seq;

	return 0;
}

MT_PLUGIN_IO_OPTIMIZE static inline int mt7921u_mcu_send_message(struct sk_buff *skb, int cmd, int *seq){
	struct mt792x_dev *dev = container_of(mdev, struct mt792x_dev, mt76);
	u32 pad, ep;
	int ret;

	ret = MT76_MCU_FILL_MSG(skb, cmd, seq);
	if (ret)
		return ret;

	mdev->mcu.timeout = 3 * HZ;

	if (cmd != MCU_CMD(FW_SCATTER))
		ep = MT_EP_OUT_INBAND_CMD;
	else
		ep = MT_EP_OUT_AC_BE;

	mt792x_skb_add_usb_sdio_hdr(dev, skb, 0);
	pad = round_up(skb->len, 4) + 4 - skb->len;
	__skb_put_zero(skb, pad);

	ret = mt76u_bulk_msg(&dev->mt76, skb->data, skb->len, NULL, 1000, ep);

	return ret;
}

MT_PLUGIN_IO_OPTIMIZE static inline void MT76X02U_MCU_SEND_MSG(struct sk_buff *skb, int cmd, bool wait_resp){
	uint8_t seq = 0;
	uint32_t info = 0;
	int ret;

	info = FIELD_PREP(MT_MCU_MSG_CMD_SEQ, seq) | FIELD_PREP(MT_MCU_MSG_CMD_TYPE, cmd) | MT_MCU_MSG_TYPE_CMD;

	ret = mt76x02u_skb_dma_info(skb, CPU_TX_PORT, info);
	if (return_context){
		return;
	}

	/** static inline int mt76u_bulk_msg(struct mt76_dev *dev, void *data, int len, int *actual_len, int timeout, int ep) **/
	{
		//mt76u_bulk_msg(skb->data, skb->len, NULL, 500, MT_EP_OUT_INBAND_CMD);
		unsigned int pipe = 0;
		pipe = usb_sndbulkpipe(udev, usb->out_ep[ep]);

		libusb_bulk_transfer(
					device_context->device_handler,
					pipe,
					skb->data,
					skb->len,
					NULL,
					500
				    );

	}
	if (return_context){
		return;
	}

	if (wait_resp){
		ret = mt76x02u_mcu_wait_resp(dev, seq);
	}
}


MT_PLUGIN_IO_OPTIMIZE static inline void MT7921_MCU_READ_EEPROM(uint32_t offset, uint8_t *val){
	struct mt7921_mcu_eeprom_info *res, req = {
		#ifndef MT7921_EEPROM_BLOCK_SIZE
			#define MT7921_EEPROM_BLOCK_SIZE	16
		#endif
		.addr = __cpu_to_le32(round_down(offset, MT7921_EEPROM_BLOCK_SIZE)),
	};

	struct sk_buff *skb = NULL;

	mt76_mcu_send_and_get_msg(MCU_EXT_QUERY(EFUSE_ACCESS), &req, sizeof(req), true, &skb);

	if(return_context){
		return;
	}

	res = (struct mt7921_mcu_eeprom_info *)skb->data;
	*val = res->data[offset % MT7921_EEPROM_BLOCK_SIZE];
	free(skb);

	return_context = 0;
}

MT_PLUGIN_IO_OPTIMIZE static inline void MT792XU_COPY(uint32_t offset, const void *data, int len){
	int ret = 0;
	int i   = 0;
	int batch_len = 0;
	const uint8_t *val = data;
	unsigned char *usb_data = (unsigned char *)malloc(sizeof(__le32));
	len = round_up(len, 4);

	//mutex_lock(&usb->usb_ctrl_mtx);
        usb_data = (unsigned char *)malloc(sizeof(__le32));
        memset(usb_data, 0x00, sizeof(__le32));

	while (i < len) {
		batch_len = MIN(usb_data_len, len - i);
		memcpy(usb_data, val + i, batch_len);
		MT7601U_USB_VENDOR_REQUEST(
					MT_VEND_WRITE_EXT,
					USB_DIR_OUT | MT_USB_TYPE_VENDOR,
					(offset + i) >> 16,
					offset + i,
					usb_data,
					batch_len
					);
		if (return_context < 0){
			break;
		}
		i += batch_len;
	}
	//mutex_unlock(&usb->usb_ctrl_mtx);
	free(usb_data);
}

MT7921_DISABLE_INSTRUMENT static inline void MT7921_VENDOR_RESET(void){
	MT7601U_USB_VENDOR_REQUEST(MT_VEND_DEV_MODE, USB_DIR_OUT, MT_VEND_DEV_MODE_RESET, 0, NULL, 0);
}

MT7921_DISABLE_INSTRUMENT static inline void MT7921_INIT(void){

}

MT7921_DISABLE_INSTRUMENT static inline void MT7921_EXIT(void){


}

/** MAIN DETECTION ROUTINE, IT WILL BE MERGED IN THE GENERIC SUBSYSTEM USB INTERFACE SOON! **/
MT7921_DISABLE_INSTRUMENT static inline void MT7921_INITIALIZE_USB_INTERFACE(void){
        libusb_init(NULL);
        struct libusb_device_handle *dev = NULL;
        for(short j = 0; j < TIMING_COUNTER; j++){
                for(int z = 0; MT7921_LIST[z].device_name != NULL; z++){
                        dev = libusb_open_device_with_vid_pid(NULL, MT7921_LIST[z].device_pid, MT7921_LIST[z].device_vid);
                        if( dev != NULL ){
                                MT7921_LIST[z].device_handler = dev;
                                // set the device context
                                device_context = &MT7921_LIST[z];
                                DEBUG_PRINTF("[!] found a new device: %s!\n", device_context->device_name);
                                return;
                        }
                        if( MT7921_LIST[z + 1].device_name == NULL ){
                                z -= z;
                        }
                }

                sleep(TIMING_COUNTER / TIMING_COUNTER);
        }
        DEBUG_PRINTF("[!] failed to search for a new device!\n");
        exit(-ERROR_DEV_NOT_FOUND);
}


int main(int argc, char *argv[], char *envp[]){
	MT7921_INITIALIZE_USB_INTERFACE();
        /** reproduce the driver's init sequence **/

	return 0;
}

