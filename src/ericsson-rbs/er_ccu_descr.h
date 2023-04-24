#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/trau/trau_pcu_ericsson.h>

struct er_ccu_descr;
struct e1_conn_pars;
typedef void (er_ccu_empty) (struct er_ccu_descr *ccu_descr);
typedef void (er_ccu_rx) (struct er_ccu_descr *ccu_descr, const ubit_t *bits, unsigned int num_bits);

struct er_ccu_descr {

	/* E1-line and timeslot (filled in by user) */
	struct e1_conn_pars *e1_conn_pars;

	/* Callback functions (provided by user) */
	er_ccu_empty *er_ccu_empty_cb;
	er_ccu_rx *er_ccu_rx_cb;

	/* I.460 Subslot */
	struct {
		struct osmo_i460_schan_desc scd;
		struct osmo_i460_subchan *schan;
		struct osmo_fsm_inst *trau_sync_fi;
		bool ccu_connected;
	} link;

	/* TRAU Sync state */
	struct {
		uint32_t pseq_ccu; /* CCU sequence counter (remote) */
		uint32_t pseq_pcu; /* PCU sequence counter (local) */
		uint32_t last_afn_ul; /* Adjusted frame number, uplink */
		uint32_t last_afn_dl; /* Adjusted frame number, downlink */
		enum time_adj_val tav; /* Last time adjustment value */
		bool ul_frame_err; /* True when last uplink TRAU frame was bad */
		bool ccu_synced; /* True when PCU is in sync with CCU */
	} sync;

	/* PCU related context */
	struct {
		uint8_t trx_no;
		uint8_t bts_nr;
		uint8_t ts;
	} pcu;


};

struct er_trx_descr {
       struct er_ccu_descr ts_ccu_descr[8];
};
