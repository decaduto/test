/*
	Generic configuration for rtl8156b
*/

#ifndef BIT
	#define BIT(nr)			((unsigned long)(1) << (nr))
#endif

#define size_to_mtu(s)		((s) - 18            - ETH_FCS_LEN)
#define mtu_to_size(m)		((m) + 18            + ETH_FCS_LEN)

/* rtl8152 flags */
enum rtl8152_flags {
	RTL8152_INACCESSIBLE = 0,
	RTL8152_SET_RX_MODE,
	WORK_ENABLE,
	RTL8152_LINK_CHG,
	SELECTIVE_SUSPEND,
	PHY_RESET,
	SCHEDULE_TASKLET,
	GREEN_ETHERNET,
	RX_EPROTO,
	IN_PRE_RESET,
	PROBED_WITH_NO_ERRORS,
	PROBE_SHOULD_RETRY,
};

/* PLA_EEE_CR */
#define EEE_RX_EN		0x0001
#define EEE_TX_EN		0x0002

/* OCP_EEE_AR */
/* bit[15:14] function */
#define FUN_ADDR		0x0000
#define FUN_DATA		0x4000

/* OCP_EEE_CONFIG1 */
#define RG_TXLPI_MSK_HFDUP	0x8000
#define RG_MATCLR_EN		0x4000
#define EEE_10_CAP		0x2000
#define EEE_NWAY_EN		0x1000
#define TX_QUIET_EN		0x0200
#define RX_QUIET_EN		0x0100


/* OCP_EEE_CONFIG2 */
#define RG_LPIHYS_NUM		0x7000	/* bit 12 ~ 15 */
#define RG_DACQUIET_EN		0x0400
#define RG_LDVQUIET_EN		0x0200
#define RG_CKRSEL		0x0020
#define RG_EEEPRG_EN		0x0010

/* OCP_POWER_CFG */
#define EEE_CLKDIV_EN		0x8000
#define EN_ALDPS		0x0004
#define EN_10M_PLLOFF		0x0001

/* PLA_MAC_PWR_CTRL4 */
#define PWRSAVE_SPDWN_EN	0x1000
#define RXDV_SPDWN_EN		0x0800
#define TX10MIDLE_EN		0x0100
#define IDLE_SPDWN_EN		BIT(6)
#define TP100_SPDWN_EN		0x0020
#define TP500_SPDWN_EN		0x0010
#define TP1000_SPDWN_EN		0x0008
#define EEE_SPDWN_EN		0x0001

/* OCP_INTR_EN */
#define INTR_SPEED_FORCE	BIT(3)

/* PLA_USB_CFG */
#define EN_XG_LIP		BIT(1)
#define EN_G_LIP		BIT(2)

/* OCP_EEE_CFG */
#define CTAP_SHORT_EN		0x0040
#define EEE10_EN		0x0010

/* OCP Registers */
#define OCP_ALDPS_CONFIG	0x2010
#define OCP_EEE_CONFIG1		0x2080
#define OCP_EEE_CONFIG2		0x2092
#define OCP_EEE_CONFIG3		0x2094
#define OCP_BASE_MII		0xa400
#define OCP_EEE_AR		0xa41a
#define OCP_EEE_DATA		0xa41c
#define OCP_PHY_STATUS		0xa420
#define OCP_INTR_EN		0xa424
#define OCP_NCTL_CFG		0xa42c
#define OCP_POWER_CFG		0xa430
#define OCP_EEE_CFG		0xa432
#define OCP_SRAM_ADDR		0xa436
#define OCP_SRAM_DATA		0xa438
#define OCP_DOWN_SPEED		0xa442
#define OCP_EEE_ABLE		0xa5c4
#define OCP_EEE_ADV		0xa5d0
#define OCP_EEE_LPABLE		0xa5d2
#define OCP_10GBT_CTRL		0xa5d4
#define OCP_10GBT_STAT		0xa5d6
#define OCP_EEE_ADV2		0xa6d4
#define OCP_PHY_STATE		0xa708		/* nway state for 8153 */
#define OCP_PHY_PATCH_STAT	0xb800
#define OCP_PHY_PATCH_CMD	0xb820
#define OCP_PHY_LOCK		0xb82e
#define OCP_ADC_IOFFSET		0xbcfc
#define OCP_ADC_CFG		0xbc06
#define OCP_SYSCLK_CFG		0xc416

/* PLA_PHY_PWR */
#define TX_10M_IDLE_EN		0x0080
#define PFM_PWM_SWITCH		0x0040
#define TEST_IO_OFF		BIT(4)

/* OCP_DOWN_SPEED */
#define EN_EEE_CMODE		BIT(14)
#define EN_EEE_1000		BIT(13)
#define EN_EEE_100		BIT(12)
#define EN_10M_CLKDIV		BIT(11)
#define EN_10M_BGOFF		0x0080

/* SRAM_GREEN_CFG */
#define GREEN_ETH_EN		BIT(15)
#define R_TUNE_EN		BIT(11)

/* PLA_TCR0 */
#define TCR0_TX_EMPTY		0x0800
#define TCR0_AUTO_FIFO		0x0080

/* SRAM_PHY_LOCK */
#define PHY_PATCH_LOCK		0x0001
/* PLA_MTPS */
#define MTPS_JUMBO		(12 * 1024 / 64)
#define MTPS_DEFAULT		(6 * 1024 / 64)

/* PLA_MAC_PWR_CTRL3 */
#define PLA_MCU_SPDWN_EN	BIT(14)
#define PKT_AVAIL_SPDWN_EN	0x0100
#define SUSPEND_SPDWN_EN	0x0004
#define U1U2_SPDWN_EN		0x0002
#define L1_SPDWN_EN		0x0001

/* PLA_OOB_CTRL */
#define NOW_IS_OOB		0x80
#define TXFIFO_EMPTY		0x20
#define RXFIFO_EMPTY		0x10
#define LINK_LIST_READY		0x02
#define DIS_MCU_CLROOB		0x01
#define FIFO_EMPTY		(TXFIFO_EMPTY | RXFIFO_EMPTY)

#define EN_ALDPS		0x0004
/* PLA_MAC_PWR_CTRL2 */
#define EEE_SPDWN_RATIO		0x8007
#define MAC_CLK_SPDWN_EN	BIT(15)
#define EEE_SPDWN_RATIO_MASK	0xff

/* PLA_RCR1 */
#define OUTER_VLAN		BIT(7)
#define INNER_VLAN		BIT(6)

/* PLA_CR */
#define CR_RST			0x10
#define CR_RE			0x08
#define CR_TE			0x04

/* PLA_WDT6_CTRL */
#define WDT6_SET_MODE		0x0010

/* PLA_MISC_1 */
#define RXDY_GATED_EN		0x0008

/* USB_FW_TASK */
#define FC_PATCH_TASK		BIT(1)

/* OCP_PHY_PATCH_STAT */
#define PATCH_READY		BIT(6)

/* OCP_PHY_PATCH_CMD */
#define PATCH_REQUEST		BIT(4)

/* OCP_PHY_LOCK */
#define PATCH_LOCK		BIT(0)

/* PLA_RSTTALLY */
#define TALLY_RESET		0x0001
#define LINK_STATUS		0x02

/* USB_BMU_RESET */
#define BMU_RESET_EP_IN		0x01
#define BMU_RESET_EP_OUT	0x02

/* PLA_POL_GPIO_CTRL */
#define DACK_DET_EN		BIT(15)
#define POL_GPHY_PATCH		BIT(4)

/* USB_USB2PHY */
#define USB2PHY_SUSPEND		0x0001
#define USB2PHY_L1		0x0002


/* USB_ECM_OP */
#define	EN_ALL_SPEED		BIT(0)


/* PLA_INDICATE_FALG */
#define UPCOMING_RUNTIME_D3	BIT(0)

/* PLA_MACDBG_PRE and PLA_MACDBG_POST */
#define DEBUG_OE		BIT(0)
#define DEBUG_LTSSM		0x0082

/* PLA_EXTRA_STATUS */
#define CUR_LINK_OK		BIT(15)
#define U3P3_CHECK_EN		BIT(7)	/* RTL_VER_05 only */
#define LINK_CHANGE_FLAG	BIT(8)
#define POLL_LINK_CHG		BIT(0)

/* USB_GPHY_CTRL */
#define GPHY_PATCH_DONE		BIT(2)
#define BYPASS_FLASH		BIT(5)
#define BACKUP_RESTRORE		BIT(6)

/* USB_SPEED_OPTION */
#define RG_PWRDN_EN		BIT(8)
#define ALL_SPEED_OFF		BIT(9)

/* USB_FW_CTRL */
#define FLOW_CTRL_PATCH_OPT	BIT(1)
#define AUTO_SPEEDUP		BIT(3)
#define FLOW_CTRL_PATCH_2	BIT(8)

/* USB_FC_TIMER */
#define CTRL_TIMER_EN		BIT(15)

/* USB_USB_CTRL */
#define CDC_ECM_EN		BIT(3)
#define RX_AGG_DISABLE		0x0010
#define RX_ZERO_EN		0x0080

/* USB_U2P3_CTRL */
#define U2P3_ENABLE		0x0001
#define RX_DETECT8		BIT(3)

/* USB_POWER_CUT */
#define PWR_EN			0x0001
#define PHASE2_EN		0x0008
#define UPS_EN			BIT(4)
#define USP_PREWAKE		BIT(5)

#define RE_INIT_LL		0x8000
#define MCU_BORW_EN		0x4000

/* PLA_CPCR */
#define FLOW_CTRL_EN		BIT(0)
#define CPCR_RX_VLAN		0x0040

#define UPCOMING_RUNTIME_D3	BIT(0)
#define LINK_CHG_EVENT		BIT(0)
#define LINK_CHANGE_FLAG	BIT(8)

/* USB_POWER_CUT */
#define PWR_EN			0x0001
#define PHASE2_EN		0x0008
#define UPS_EN			BIT(4)
#define USP_PREWAKE		BIT(5)
#define UPS_FORCE_PWR_DOWN	BIT(0)

#define PCUT_STATUS		0x0001

/* USB_U2P3_CTRL */
#define U2P3_ENABLE		0x0001
#define RX_DETECT8		BIT(3)
#define GPHY_FLASH		BIT(1)
/* USB_GPHY_CTRL */
#define GPHY_PATCH_DONE		BIT(2)
#define BYPASS_FLASH		BIT(5)
#define BACKUP_RESTRORE		BIT(6)

#define BYPASS_MAC_RESET	BIT(5)
#define	EN_ALL_SPEED		BIT(0)
#define LPM_U1U2_EN		BIT(0)


/* OCP_PHY_STATUS */
#define PHY_STAT_MASK		0x0007
#define PHY_STAT_EXT_INIT	2
#define PHY_STAT_LAN_ON		3
#define PHY_STAT_PWRDN		5
#define PLA_TCR0                0xe610

enum rtl_version {
	RTL_VER_UNKNOWN = 0,
	RTL_VER_01,
	RTL_VER_02,
	RTL_VER_03,
	RTL_VER_04,
	RTL_VER_05,
	RTL_VER_06,
	RTL_VER_07,
	RTL_VER_08,
	RTL_VER_09,

	RTL_TEST_01,
	RTL_VER_10,
	RTL_VER_11,
	RTL_VER_12,
	RTL_VER_13,
	RTL_VER_14,
	RTL_VER_15,

	RTL_VER_MAX
};

/** HW RELATED DEFININGS **/

#define BYTE_EN_DWORD                   0xff
#define BYTE_EN_WORD                    0x33
#define BYTE_EN_BYTE                    0x11
#define BYTE_EN_SIX_BYTES               0x3f
#define BYTE_EN_START_MASK              0x0f
#define BYTE_EN_END_MASK                0xf0

#define MCU_TYPE_PLA                    0x0100
#define MCU_TYPE_USB                    0x0000

#define AUTOLOAD_DONE		0x0002

/* WOL */
#define MAGIC_EN		0x0001

/* PLA_CONFIG34 */
#define LINK_ON_WAKE_EN		0x0010
#define LINK_OFF_WAKE_EN	0x0008

#define R8152_PHY_ID		32

/* PLA_CRWECR */
#define CRWECR_NORAML		0x00
#define CRWECR_CONFIG		0xc0


/* PLA_CONFIG5 */
#define BWF_EN			0x0040
#define MWF_EN			0x0020
#define UWF_EN			0x0010
#define LAN_WAKE_EN		0x0002


#define PLA_IDR			0xc000
#define PLA_RCR			0xc010
#define PLA_RCR1		0xc012
#define PLA_RMS			0xc016
#define PLA_RXFIFO_CTRL0	0xc0a0
#define PLA_RXFIFO_FULL		0xc0a2
#define PLA_RXFIFO_CTRL1	0xc0a4
#define PLA_RX_FIFO_FULL	0xc0a6
#define PLA_RXFIFO_CTRL2	0xc0a8
#define PLA_RX_FIFO_EMPTY	0xc0aa
#define PLA_DMY_REG0		0xc0b0
#define PLA_FMC			0xc0b4
#define PLA_CFG_WOL		0xc0b6
#define PLA_TEREDO_CFG		0xc0bc
#define PLA_TEREDO_WAKE_BASE	0xc0c4
#define PLA_MAR			0xcd00
#define PLA_BACKUP		0xd000
#define PLA_BDC_CR		0xd1a0
#define PLA_TEREDO_TIMER	0xd2cc
#define PLA_REALWOW_TIMER	0xd2e8
#define PLA_UPHY_TIMER		0xd388
#define PLA_SUSPEND_FLAG	0xd38a
#define PLA_INDICATE_FALG	0xd38c
#define PLA_MACDBG_PRE		0xd38c	/* RTL_VER_04 only */
#define PLA_MACDBG_POST		0xd38e	/* RTL_VER_04 only */
#define PLA_EXTRA_STATUS	0xd398
#define PLA_GPHY_CTRL		0xd3ae
#define PLA_POL_GPIO_CTRL	0xdc6a
#define PLA_EFUSE_DATA		0xdd00
#define PLA_EFUSE_CMD		0xdd02
#define PLA_LEDSEL		0xdd90
#define PLA_LED_FEATURE		0xdd92
#define PLA_PHYAR		0xde00
#define PLA_BOOT_CTRL		0xe004
#define PLA_LWAKE_CTRL_REG	0xe007
#define PLA_GPHY_INTR_IMR	0xe022
#define PLA_EEE_CR		0xe040
#define PLA_EEE_TXTWSYS		0xe04c
#define PLA_EEE_TXTWSYS_2P5G	0xe058
#define PLA_EEEP_CR		0xe080
#define PLA_MAC_PWR_CTRL	0xe0c0
#define PLA_MAC_PWR_CTRL2	0xe0ca
#define PLA_MAC_PWR_CTRL3	0xe0cc
#define PLA_MAC_PWR_CTRL4	0xe0ce
#define PLA_WDT6_CTRL		0xe428
#define PLA_TCR0		0xe610
#define PLA_TCR1		0xe612
#define PLA_MTPS		0xe615
#define PLA_TXFIFO_CTRL		0xe618
#define PLA_TXFIFO_FULL		0xe61a
#define PLA_RSTTALLY		0xe800
#define PLA_CR			0xe813
#define PLA_CRWECR		0xe81c
#define PLA_CONFIG12		0xe81e	/* CONFIG1, CONFIG2 */
#define PLA_CONFIG34		0xe820	/* CONFIG3, CONFIG4 */
#define PLA_CONFIG5		0xe822
#define PLA_PHY_PWR		0xe84c
#define PLA_OOB_CTRL		0xe84f
#define PLA_CPCR		0xe854
#define PLA_MISC_0		0xe858
#define PLA_MISC_1		0xe85a
#define PLA_OCP_GPHY_BASE	0xe86c
#define PLA_TALLYCNT		0xe890
#define PLA_SFF_STS_7		0xe8de
#define PLA_PHYSTATUS		0xe908
#define PLA_CONFIG6		0xe90a /* CONFIG6 */
#define PLA_USB_CFG		0xe952
#define PLA_BP_BA		0xfc26
#define PLA_BP_0		0xfc28
#define PLA_BP_1		0xfc2a
#define PLA_BP_2		0xfc2c
#define PLA_BP_3		0xfc2e
#define PLA_BP_4		0xfc30
#define PLA_BP_5		0xfc32
#define PLA_BP_6		0xfc34
#define PLA_BP_7		0xfc36
#define PLA_BP_EN		0xfc38

#define USB_USB2PHY		0xb41e
#define USB_SSPHYLINK1		0xb426
#define USB_SSPHYLINK2		0xb428
#define USB_L1_CTRL		0xb45e
#define USB_U2P3_CTRL		0xb460
#define USB_CSR_DUMMY1		0xb464
#define USB_CSR_DUMMY2		0xb466
#define USB_DEV_STAT		0xb808
#define USB_CONNECT_TIMER	0xcbf8
#define USB_MSC_TIMER		0xcbfc
#define USB_BURST_SIZE		0xcfc0
#define USB_FW_FIX_EN0		0xcfca
#define USB_FW_FIX_EN1		0xcfcc
#define USB_LPM_CONFIG		0xcfd8
#define USB_ECM_OPTION		0xcfee
#define USB_CSTMR		0xcfef	/* RTL8153A */
#define USB_MISC_2		0xcfff
#define USB_ECM_OP		0xd26b
#define USB_GPHY_CTRL		0xd284
#define USB_SPEED_OPTION	0xd32a
#define USB_FW_CTRL		0xd334	/* RTL8153B */
#define USB_FC_TIMER		0xd340
#define USB_USB_CTRL		0xd406
#define USB_PHY_CTRL		0xd408
#define USB_TX_AGG		0xd40a
#define USB_RX_BUF_TH		0xd40c
#define USB_USB_TIMER		0xd428
#define USB_RX_EARLY_TIMEOUT	0xd42c
#define USB_RX_EARLY_SIZE	0xd42e
#define USB_PM_CTRL_STATUS	0xd432	/* RTL8153A */
#define USB_RX_EXTRA_AGGR_TMR	0xd432	/* RTL8153B */
#define USB_TX_DMA		0xd434
#define USB_UPT_RXDMA_OWN	0xd437
#define USB_UPHY3_MDCMDIO	0xd480
#define USB_TOLERANCE		0xd490
#define USB_LPM_CTRL		0xd41a
#define USB_BMU_RESET		0xd4b0
#define USB_BMU_CONFIG		0xd4b4
#define USB_U1U2_TIMER		0xd4da
#define USB_FW_TASK		0xd4e8	/* RTL8153B */
#define USB_RX_AGGR_NUM		0xd4ee
#define USB_UPS_CTRL		0xd800
#define USB_POWER_CUT		0xd80a
#define USB_MISC_0		0xd81a
#define USB_MISC_1		0xd81f
#define USB_AFE_CTRL2		0xd824
#define USB_UPHY_XTAL		0xd826
#define USB_UPS_CFG		0xd842
#define USB_UPS_FLAGS		0xd848
#define USB_WDT1_CTRL		0xe404
#define USB_WDT11_CTRL		0xe43c
#define USB_BP_BA		PLA_BP_BA
#define USB_BP_0		PLA_BP_0
#define USB_BP_1		PLA_BP_1
#define USB_BP_2		PLA_BP_2
#define USB_BP_3		PLA_BP_3
#define USB_BP_4		PLA_BP_4
#define USB_BP_5		PLA_BP_5
#define USB_BP_6		PLA_BP_6
#define USB_BP_7		PLA_BP_7
#define USB_BP_EN		PLA_BP_EN	/* RTL8153A */
#define USB_BP_8		0xfc38		/* RTL8153B */
#define USB_BP_9		0xfc3a
#define USB_BP_10		0xfc3c
#define USB_BP_11		0xfc3e
#define USB_BP_12		0xfc40
#define USB_BP_13		0xfc42
#define USB_BP_14		0xfc44
#define USB_BP_15		0xfc46
#define USB_BP2_EN		0xfc48

/* OCP Registers */
#define OCP_ALDPS_CONFIG	0x2010
#define OCP_EEE_CONFIG1		0x2080
#define OCP_EEE_CONFIG2		0x2092
#define OCP_EEE_CONFIG3		0x2094
#define OCP_BASE_MII		0xa400
#define OCP_EEE_AR		0xa41a
#define OCP_EEE_DATA		0xa41c
#define OCP_PHY_STATUS		0xa420
#define OCP_NCTL_CFG		0xa42c
#define OCP_POWER_CFG		0xa430
#define OCP_EEE_CFG		0xa432
#define OCP_SRAM_ADDR		0xa436
#define OCP_SRAM_DATA		0xa438
#define OCP_DOWN_SPEED		0xa442
#define OCP_EEE_ABLE		0xa5c4
#define OCP_EEE_ADV		0xa5d0
#define OCP_EEE_LPABLE		0xa5d2
#define OCP_10GBT_CTRL		0xa5d4
#define OCP_10GBT_STAT		0xa5d6
#define OCP_EEE_ADV2		0xa6d4
#define OCP_PHY_STATE		0xa708		/* nway state for 8153 */
#define OCP_PHY_PATCH_STAT	0xb800
#define OCP_PHY_PATCH_CMD	0xb820
#define OCP_PHY_LOCK		0xb82e
#define OCP_ADC_IOFFSET		0xbcfc
#define OCP_ADC_CFG		0xbc06
#define OCP_SYSCLK_CFG		0xc416

/* SRAM Register */
#define SRAM_GREEN_CFG		0x8011
#define SRAM_LPF_CFG		0x8012
#define SRAM_GPHY_FW_VER	0x801e
#define SRAM_10M_AMP1		0x8080
#define SRAM_10M_AMP2		0x8082
#define SRAM_IMPEDANCE		0x8084
#define SRAM_PHY_LOCK		0xb82e

/* PLA_RCR */
#define RCR_AAP			0x00000001
#define RCR_APM			0x00000002
#define RCR_AM			0x00000004
#define RCR_AB			0x00000008
#define RCR_ACPT_ALL		(RCR_AAP | RCR_APM | RCR_AM | RCR_AB)
#define SLOT_EN			BIT(11)

enum rtl_fw_type {
	RTL_FW_END = 0,
	RTL_FW_PLA,
	RTL_FW_USB,
	RTL_FW_PHY_START,
	RTL_FW_PHY_STOP,
	RTL_FW_PHY_NC,
	RTL_FW_PHY_FIXUP,
	RTL_FW_PHY_UNION_NC,
	RTL_FW_PHY_UNION_NC1,
	RTL_FW_PHY_UNION_NC2,
	RTL_FW_PHY_UNION_UC2,
	RTL_FW_PHY_UNION_UC,
	RTL_FW_PHY_UNION_MISC,
	RTL_FW_PHY_SPEED_UP,
	RTL_FW_PHY_VER,
};

enum rtl8152_fw_fixup_cmd {
	FW_FIXUP_AND = 0,
	FW_FIXUP_OR,
	FW_FIXUP_NOT,
	FW_FIXUP_XOR,
};
