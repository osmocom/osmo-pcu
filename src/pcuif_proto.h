#ifndef _PCUIF_PROTO_H
#define _PCUIF_PROTO_H

#include <osmocom/gsm/l1sap.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/core/signal.h>
#ifdef __cplusplus
}
#endif

#define PCU_IF_VERSION		0x07

/* msg_type */
#define PCU_IF_MSG_DATA_REQ	0x00	/* send data to given channel */
#define PCU_IF_MSG_DATA_CNF	0x01	/* confirm (e.g. transmission on PCH) */
#define PCU_IF_MSG_DATA_IND	0x02	/* receive data from given channel */	
#define PCU_IF_MSG_RTS_REQ	0x10	/* ready to send request */
#define PCU_IF_MSG_RACH_IND	0x22	/* receive RACH */
#define PCU_IF_MSG_INFO_IND	0x32	/* retrieve BTS info */
#define PCU_IF_MSG_ACT_REQ	0x40	/* activate/deactivate PDCH */
#define PCU_IF_MSG_TIME_IND	0x52	/* GSM time indication */
#define PCU_IF_MSG_PAG_REQ	0x60	/* paging request */

/*PCU alarm indication */
#define PCU_IF_MSG_FAILURE_EVT_IND	0x61 /* PCU failure event report indication */

/* sapi */
#define PCU_IF_SAPI_RACH	0x01	/* channel request on CCCH */
#define PCU_IF_SAPI_AGCH	0x02	/* assignment on AGCH */
#define PCU_IF_SAPI_PCH		0x03	/* paging/assignment on PCH */
#define PCU_IF_SAPI_BCCH	0x04	/* SI on BCCH */
#define PCU_IF_SAPI_PDTCH	0x05	/* packet data/control/ccch block */
#define PCU_IF_SAPI_PRACH	0x06	/* packet random access channel */
#define PCU_IF_SAPI_PTCCH	0x07	/* packet TA control channel */

/* flags */
#define PCU_IF_FLAG_ACTIVE	(1 << 0)/* BTS is active */
#define PCU_IF_FLAG_SYSMO	(1 << 1)/* access PDCH of sysmoBTS directly */
#define PCU_IF_FLAG_CS1		(1 << 16)
#define PCU_IF_FLAG_CS2		(1 << 17)
#define PCU_IF_FLAG_CS3		(1 << 18)
#define PCU_IF_FLAG_CS4		(1 << 19)
#define PCU_IF_FLAG_MCS1	(1 << 20)
#define PCU_IF_FLAG_MCS2	(1 << 21)
#define PCU_IF_FLAG_MCS3	(1 << 22)
#define PCU_IF_FLAG_MCS4	(1 << 23)
#define PCU_IF_FLAG_MCS5	(1 << 24)
#define PCU_IF_FLAG_MCS6	(1 << 25)
#define PCU_IF_FLAG_MCS7	(1 << 26)
#define PCU_IF_FLAG_MCS8	(1 << 27)
#define PCU_IF_FLAG_MCS9	(1 << 28)

/* NuRAN Wireless manufacture-defined alarm causes */
enum pcu_nm_event_causes {
	/* Critical causes */
	PCU_NM_EVT_CAUSE_CRIT_OPEN_L1_FAIL	= 0x333b,
	PCU_NM_EVT_CAUSE_CRIT_OPEN_PDCH_FAIL	= 0x3411,
	PCU_NM_EVT_CAUSE_CRIT_BAD_PCU_IF_VER	= 0x3415,
	/* Major causes */
	PCU_NM_EVT_CAUSE_MAJ_UKWN_L1_MSG	= 0x3012,
	PCU_NM_EVT_CAUSE_MAJ_UKWN_L1_PRIM_MSG	= 0x3013,
	PCU_NM_EVT_CAUSE_MAJ_UKWN_BTS_MSG	= 0x3014,
	PCU_NM_EVT_CAUSE_MAJ_PDTCH_QUEUE_FULL	= 0x333a,
	/* Warning causes */
	PCU_NM_EVT_CAUSE_WARN_NO_PDCH_AVAIL	= 0x3011,

};

/* NuRAN Wireless manufacture-defined alarm signals */
enum pcu_fail_evt_rep_sig {
	S_PCU_NM_NO_PDCH_ALARM		= 0x0b1b,
	S_PCU_NM_RX_UNKN_L1_SAP_ALARM,
	S_PCU_NM_RX_UNKN_L1_PRIM_ALARM,
	S_PCU_NM_RX_UNKN_MSG_ALARM,
	S_PCU_NM_FAIL_NSVC_ALARM,
	S_PCU_NM_FAIL_RST_NSVC_ALARM,
	S_PCU_NM_FAIL_UNBLK_NSVC_ALARM,
	S_PCU_NM_FAIL_PTP_BVC_ALARM,
	S_PCU_NM_UNKN_NSEI_BVCI_ALARM,
	S_PCU_NM_UNKN_NSVC_ALARM,
	S_PCU_NM_PDTCH_QUEUE_FULL_ALARM,
	S_PCU_NM_FAIL_OPEN_L1_ALARM,
	S_PCU_NM_FAIL_OPEN_PDCH_ALARM,
	S_PCU_NM_WRONG_IF_VER_ALARM,
};

/* NuRAN Wireless manufacture-defined alarm signal data structure */
struct pcu_fail_evt_rep_sig_data {
	char *add_text;
	int rc;
	uint8_t spare[4];
};

/* NuRAN Wireless manufacture-defined alarm signal list structure */
struct pcu_alarm_list {
	struct llist_head list; /* List of sent failure alarm report */
	uint16_t alarm_signal;	/* Failure alarm report signal cause */
};


struct gsm_pcu_if_data {
	uint8_t		sapi;
	uint8_t		len;
	uint8_t		data[162];
	uint32_t	fn;
	uint16_t	arfcn;
	uint8_t		trx_nr;
	uint8_t		ts_nr;
	uint8_t		block_nr;
	int8_t		rssi;
	uint16_t ber10k;	/*!< \brief BER in units of 0.01% */
	int16_t ta_offs_qbits;	/* !< \brief Burst TA Offset in quarter bits */
	int16_t lqual_cb;	/* !< \brief Link quality in centiBel */
} __attribute__ ((packed));

struct gsm_pcu_if_rts_req {
	uint8_t		sapi;
	uint8_t		spare[3];
	uint32_t	fn;
	uint16_t	arfcn;
	uint8_t		trx_nr;
	uint8_t		ts_nr;
	uint8_t		block_nr;
} __attribute__ ((packed));

struct gsm_pcu_if_rach_ind {
	uint8_t		sapi;
	uint16_t	ra;
	int16_t		qta;
	uint32_t	fn;
	uint16_t	arfcn;
	uint8_t		is_11bit;
	uint8_t		burst_type;
} __attribute__ ((packed));

struct gsm_pcu_if_info_trx {
	uint16_t	arfcn;
	uint8_t		pdch_mask;		/* PDCH channels per TS */
	uint8_t		spare;
	uint8_t		tsc[8];			/* TSC per channel */
	uint32_t	hlayer1;
} __attribute__ ((packed));

struct gsm_pcu_if_info_ind {
	uint32_t	version;
	uint32_t	flags;
	struct gsm_pcu_if_info_trx trx[8];	/* TRX infos per BTS */
	uint8_t		bsic;
	/* RAI */
	uint16_t	mcc, mnc, lac, rac;
	/* NSE */
	uint16_t	nsei;
	uint8_t		nse_timer[7];
	uint8_t		cell_timer[11];
	/* cell  */
	uint16_t	cell_id;
	uint16_t	repeat_time;
	uint8_t		repeat_count;
	uint16_t	bvci;
	uint8_t		t3142;
	uint8_t		t3169;
	uint8_t		t3191;
	uint8_t		t3193_10ms;
	uint8_t		t3195;
	uint8_t		n3101;
	uint8_t		n3103;
	uint8_t		n3105;
	uint8_t		cv_countdown;
	uint16_t	dl_tbf_ext;
	uint16_t	ul_tbf_ext;
	uint8_t		initial_cs;
	uint8_t		initial_mcs;
	/* NSVC */
	uint16_t	nsvci[2];
	uint16_t	local_port[2];
	uint16_t	remote_port[2];
	uint32_t	remote_ip[2];
} __attribute__ ((packed));

struct gsm_pcu_if_act_req {
	uint8_t		activate;
	uint8_t		trx_nr;
	uint8_t		ts_nr;
	uint8_t		spare;
} __attribute__ ((packed));

struct gsm_pcu_if_time_ind {
	uint32_t	fn;
} __attribute__ ((packed));

struct gsm_pcu_if_pag_req {
	uint8_t		sapi;
	uint8_t		chan_needed;
	uint8_t		identity_lv[9];
} __attribute__ ((packed));

struct gsm_pcu_if_fail_evt_ind {
	uint8_t 	event_type;
	uint8_t 	event_severity;
	uint8_t 	cause_type;
	uint16_t 	event_cause;
	char 		add_text[100];
}__attribute__ ((packed));

struct gsm_pcu_if {
	/* context based information */
	uint8_t		msg_type;	/* message type */
	uint8_t		bts_nr;		/* bts number */
	uint8_t		spare[2];

	union {
		struct gsm_pcu_if_data		data_req;
		struct gsm_pcu_if_data		data_cnf;
		struct gsm_pcu_if_data		data_ind;
		struct gsm_pcu_if_rts_req	rts_req;
		struct gsm_pcu_if_rach_ind	rach_ind;
		struct gsm_pcu_if_info_ind	info_ind;
		struct gsm_pcu_if_act_req	act_req;
		struct gsm_pcu_if_time_ind	time_ind;
		struct gsm_pcu_if_pag_req	pag_req;
		struct gsm_pcu_if_fail_evt_ind	failure_evt_ind;
	} u;
} __attribute__ ((packed));

extern struct pcu_fail_evt_rep_sig_data alarm_sig_data;

#endif /* _PCUIF_PROTO_H */
