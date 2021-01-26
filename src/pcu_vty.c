/* OsmoBTS VTY interface */


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <osmocom/core/tdef.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/pcu/pcuif_proto.h>
#include <osmocom/gprs/gprs_ns2.h>
#include "pcu_vty.h"
#include "gprs_rlcmac.h"
#include <pdch.h>
#include "bts.h"
#include "tbf.h"
#include "pcu_vty_functions.h"

#define X(x) (1 << x)

extern void *tall_pcu_ctx;

static const struct value_string pcu_gsmtap_categ_names[] = {
	{ PCU_GSMTAP_C_DL_UNKNOWN,	"dl-unknown" },
	{ PCU_GSMTAP_C_DL_DUMMY,	"dl-dummy" },
	{ PCU_GSMTAP_C_DL_CTRL,		"dl-ctrl" },
	{ PCU_GSMTAP_C_DL_DATA_GPRS,	"dl-data-gprs" },
	{ PCU_GSMTAP_C_DL_DATA_EGPRS,	"dl-data-egprs" },
	{ PCU_GSMTAP_C_DL_PTCCH,	"dl-ptcch" },
	{ PCU_GSMTAP_C_DL_AGCH,		"dl-agch" },
	{ PCU_GSMTAP_C_DL_PCH,		"dl-pch" },

	{ PCU_GSMTAP_C_UL_UNKNOWN,	"ul-unknown" },
	{ PCU_GSMTAP_C_UL_DUMMY,	"ul-dummy" },
	{ PCU_GSMTAP_C_UL_CTRL,		"ul-ctrl" },
	{ PCU_GSMTAP_C_UL_DATA_GPRS,	"ul-data-gprs" },
	{ PCU_GSMTAP_C_UL_DATA_EGPRS,	"ul-data-egprs" },
	{ PCU_GSMTAP_C_UL_RACH,		"ul-rach" },
	{ PCU_GSMTAP_C_UL_PTCCH,	"ul-ptcch" },

	{ 0, NULL }
};

static const struct value_string pcu_gsmtap_categ_help[] = {
	{ PCU_GSMTAP_C_DL_UNKNOWN,	"Unknown / Unparseable / Erroneous Downlink Blocks" },
	{ PCU_GSMTAP_C_DL_DUMMY,	"Downlink Dummy Blocks" },
	{ PCU_GSMTAP_C_DL_CTRL,		"Downlink Control Blocks" },
	{ PCU_GSMTAP_C_DL_DATA_GPRS,	"Downlink Data Blocks (GPRS)" },
	{ PCU_GSMTAP_C_DL_DATA_EGPRS,	"Downlink Data Blocks (EGPRS)" },
	{ PCU_GSMTAP_C_DL_PTCCH,	"Downlink PTCCH Blocks" },
	{ PCU_GSMTAP_C_DL_AGCH,		"Downlink AGCH Blocks" },
	{ PCU_GSMTAP_C_DL_PCH,		"Downlink PCH Blocks" },

	{ PCU_GSMTAP_C_UL_UNKNOWN,	"Unknown / Unparseable / Erroneous Downlink Blocks" },
	{ PCU_GSMTAP_C_UL_DUMMY,	"Uplink Dummy Blocks" },
	{ PCU_GSMTAP_C_UL_CTRL,		"Uplink Control Blocks" },
	{ PCU_GSMTAP_C_UL_DATA_GPRS,	"Uplink Data Blocks (GPRS)" },
	{ PCU_GSMTAP_C_UL_DATA_EGPRS,	"Uplink Data Blocks (EGPRS)" },
	{ PCU_GSMTAP_C_UL_RACH,		"Uplink RACH Bursts" },
	{ PCU_GSMTAP_C_UL_PTCCH,	"Uplink PTCCH Bursts" },

	{ 0, NULL }
};


DEFUN(cfg_pcu_gsmtap_categ, cfg_pcu_gsmtap_categ_cmd, "HIDDEN", "HIDDEN")
{
	int categ;

	categ = get_string_value(pcu_gsmtap_categ_names, argv[0]);
	if (categ < 0)
		return CMD_WARNING;

	the_pcu->gsmtap_categ_mask |= (1 << categ);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_gsmtap_categ, cfg_pcu_no_gsmtap_categ_cmd, "HIDDEN", "HIDDEN")
{
	int categ;

	categ = get_string_value(pcu_gsmtap_categ_names, argv[0]);
	if (categ < 0)
		return CMD_WARNING;

	the_pcu->gsmtap_categ_mask &= ~(1 << categ);

	return CMD_SUCCESS;
}

static struct cmd_node pcu_node = {
	(enum node_type) PCU_NODE,
	"%s(config-pcu)# ",
	1,
};

static int config_write_pcu(struct vty *vty)
{
	unsigned int i;

	vty_out(vty, "pcu%s", VTY_NEWLINE);
	vty_out(vty, " flow-control-interval %d%s", the_pcu->vty.fc_interval,
		VTY_NEWLINE);
	if (the_pcu->vty.fc_bvc_bucket_size)
		vty_out(vty, " flow-control force-bvc-bucket-size %d%s",
			the_pcu->vty.fc_bvc_bucket_size, VTY_NEWLINE);
	if (the_pcu->vty.fc_bvc_leak_rate)
		vty_out(vty, " flow-control force-bvc-leak-rate %d%s",
			the_pcu->vty.fc_bvc_leak_rate, VTY_NEWLINE);
	if (the_pcu->vty.fc_ms_bucket_size)
		vty_out(vty, " flow-control force-ms-bucket-size %d%s",
			the_pcu->vty.fc_ms_bucket_size, VTY_NEWLINE);
	if (the_pcu->vty.fc_ms_leak_rate)
		vty_out(vty, " flow-control force-ms-leak-rate %d%s",
			the_pcu->vty.fc_ms_leak_rate, VTY_NEWLINE);
	if (the_pcu->vty.force_initial_cs) {
		if (the_pcu->vty.initial_cs_ul == the_pcu->vty.initial_cs_dl)
			vty_out(vty, " cs %d%s", the_pcu->vty.initial_cs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " cs %d %d%s", the_pcu->vty.initial_cs_dl,
				the_pcu->vty.initial_cs_ul, VTY_NEWLINE);
	}
	if (the_pcu->vty.max_cs_dl && the_pcu->vty.max_cs_ul) {
		if (the_pcu->vty.max_cs_ul == the_pcu->vty.max_cs_dl)
			vty_out(vty, " cs max %d%s", the_pcu->vty.max_cs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " cs max %d %d%s", the_pcu->vty.max_cs_dl,
				the_pcu->vty.max_cs_ul, VTY_NEWLINE);
	}
	if (the_pcu->vty.cs_adj_enabled)
		vty_out(vty, " cs threshold %d %d%s",
			the_pcu->vty.cs_adj_lower_limit, the_pcu->vty.cs_adj_upper_limit,
			VTY_NEWLINE);
	else
		vty_out(vty, " no cs threshold%s", VTY_NEWLINE);

	if (the_pcu->vty.cs_downgrade_threshold)
		vty_out(vty, " cs downgrade-threshold %d%s",
			the_pcu->vty.cs_downgrade_threshold, VTY_NEWLINE);
	else
		vty_out(vty, " no cs downgrade-threshold%s", VTY_NEWLINE);

	vty_out(vty, " cs link-quality-ranges cs1 %d cs2 %d %d cs3 %d %d cs4 %d%s",
		the_pcu->vty.cs_lqual_ranges[0].high,
		the_pcu->vty.cs_lqual_ranges[1].low,
		the_pcu->vty.cs_lqual_ranges[1].high,
		the_pcu->vty.cs_lqual_ranges[2].low,
		the_pcu->vty.cs_lqual_ranges[2].high,
		the_pcu->vty.cs_lqual_ranges[3].low,
		VTY_NEWLINE);

	vty_out(vty, " mcs link-quality-ranges mcs1 %d mcs2 %d %d mcs3 %d %d mcs4 %d %d mcs5 %d %d mcs6 %d %d mcs7 %d %d mcs8 %d %d mcs9 %d%s",
		the_pcu->vty.mcs_lqual_ranges[0].high,
		the_pcu->vty.mcs_lqual_ranges[1].low,
		the_pcu->vty.mcs_lqual_ranges[1].high,
		the_pcu->vty.mcs_lqual_ranges[2].low,
		the_pcu->vty.mcs_lqual_ranges[2].high,
		the_pcu->vty.mcs_lqual_ranges[3].low,
		the_pcu->vty.mcs_lqual_ranges[3].high,
		the_pcu->vty.mcs_lqual_ranges[4].low,
		the_pcu->vty.mcs_lqual_ranges[4].high,
		the_pcu->vty.mcs_lqual_ranges[5].low,
		the_pcu->vty.mcs_lqual_ranges[5].high,
		the_pcu->vty.mcs_lqual_ranges[6].low,
		the_pcu->vty.mcs_lqual_ranges[6].high,
		the_pcu->vty.mcs_lqual_ranges[7].low,
		the_pcu->vty.mcs_lqual_ranges[7].high,
		the_pcu->vty.mcs_lqual_ranges[8].low,
		VTY_NEWLINE);

	if (the_pcu->vty.force_initial_mcs) {
		if (the_pcu->vty.initial_mcs_ul == the_pcu->vty.initial_mcs_dl)
			vty_out(vty, " mcs %d%s", the_pcu->vty.initial_mcs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " mcs %d %d%s", the_pcu->vty.initial_mcs_dl,
				the_pcu->vty.initial_mcs_ul, VTY_NEWLINE);
	}

	if (the_pcu->vty.max_mcs_dl && the_pcu->vty.max_mcs_ul) {
		if (the_pcu->vty.max_mcs_ul == the_pcu->vty.max_mcs_dl)
			vty_out(vty, " mcs max %d%s", the_pcu->vty.max_mcs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " mcs max %d %d%s", the_pcu->vty.max_mcs_dl,
				the_pcu->vty.max_mcs_ul, VTY_NEWLINE);
	}

	vty_out(vty, " window-size %d %d%s", the_pcu->vty.ws_base, the_pcu->vty.ws_pdch,
		VTY_NEWLINE);

	if (the_pcu->vty.dl_arq_type == EGPRS_ARQ2)
		vty_out(vty, " egprs dl arq-type arq2%s", VTY_NEWLINE);

	if (the_pcu->vty.force_llc_lifetime == 0xffff)
		vty_out(vty, " queue lifetime infinite%s", VTY_NEWLINE);
	else if (the_pcu->vty.force_llc_lifetime)
		vty_out(vty, " queue lifetime %d%s", the_pcu->vty.force_llc_lifetime,
			VTY_NEWLINE);
	if (the_pcu->vty.llc_discard_csec)
		vty_out(vty, " queue hysteresis %d%s", the_pcu->vty.llc_discard_csec,
			VTY_NEWLINE);
	if (the_pcu->vty.llc_idle_ack_csec)
		vty_out(vty, " queue idle-ack-delay %d%s", the_pcu->vty.llc_idle_ack_csec,
			VTY_NEWLINE);
	if (the_pcu->vty.llc_codel_interval_msec == LLC_CODEL_USE_DEFAULT)
		vty_out(vty, " queue codel%s", VTY_NEWLINE);
	else if (the_pcu->vty.llc_codel_interval_msec == LLC_CODEL_DISABLE)
		vty_out(vty, " no queue codel%s", VTY_NEWLINE);
	else
		vty_out(vty, " queue codel interval %d%s",
			the_pcu->vty.llc_codel_interval_msec/10, VTY_NEWLINE);

	if (the_pcu->alloc_algorithm == alloc_algorithm_a)
		vty_out(vty, " alloc-algorithm a%s", VTY_NEWLINE);
	if (the_pcu->alloc_algorithm == alloc_algorithm_b)
		vty_out(vty, " alloc-algorithm b%s", VTY_NEWLINE);
	if (the_pcu->alloc_algorithm == alloc_algorithm_dynamic)
		vty_out(vty, " alloc-algorithm dynamic%s", VTY_NEWLINE);
	if (the_pcu->vty.force_two_phase)
		vty_out(vty, " two-phase-access%s", VTY_NEWLINE);
	vty_out(vty, " alpha %d%s", the_pcu->vty.alpha, VTY_NEWLINE);
	vty_out(vty, " gamma %d%s", the_pcu->vty.gamma * 2, VTY_NEWLINE);
	if (!the_pcu->vty.dl_tbf_preemptive_retransmission)
		vty_out(vty, " no dl-tbf-preemptive-retransmission%s", VTY_NEWLINE);
	if (strcmp(the_pcu->pcu_sock_path, PCU_SOCK_DEFAULT))
		vty_out(vty, " pcu-socket %s%s", the_pcu->pcu_sock_path, VTY_NEWLINE);

	for (i = 0; i < 32; i++) {
		unsigned int cs = (1 << i);
		if (the_pcu->gsmtap_categ_mask & cs) {
			vty_out(vty, " gsmtap-category %s%s",
				get_value_string(pcu_gsmtap_categ_names, i), VTY_NEWLINE);
		}
	}

	if (the_pcu->vty.ns_dialect == GPRS_NS2_DIALECT_SNS)
		vty_out(vty, " gb-dialect ip-sns%s", VTY_NEWLINE);
	else
		vty_out(vty, " gb-dialect classic%s", VTY_NEWLINE);

	osmo_tdef_vty_write(vty, the_pcu->T_defs, " timer ");

	return CMD_SUCCESS;
}

/* per-BTS configuration */
DEFUN_ATTR(cfg_pcu,
	   cfg_pcu_cmd,
	   "pcu",
	   "BTS specific configure",
	   CMD_ATTR_IMMEDIATE)
{
	vty->node = PCU_NODE;

	return CMD_SUCCESS;
}

#define EGPRS_STR "EGPRS configuration\n"

DEFUN_DEPRECATED(cfg_pcu_egprs,
		 cfg_pcu_egprs_cmd,
		 "egprs only",
		 EGPRS_STR "Use EGPRS and disable plain GPRS\n")
{
	vty_out (vty, "'egprs only' is deprecated, egprs support is controled from BTS/BSC config, this is now a no-op%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_pcu_no_egprs,
		 cfg_pcu_no_egprs_cmd,
		 "no egprs",
		 NO_STR EGPRS_STR)
{
	vty_out (vty, "'no egprs only' is deprecated, egprs support is controled from BTS/BSC config, this is now a no-op%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_fc_interval,
	   cfg_pcu_fc_interval_cmd,
	   "flow-control-interval <1-10>",
	   "Interval between sending subsequent Flow Control PDUs\n"
	   "Interval time in seconds\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_interval = atoi(argv[0]);
	return CMD_SUCCESS;
}
#define FC_STR "BSSGP Flow Control configuration\n"
#define FC_BMAX_STR(who) "Force a fixed value for the " who " bucket size\n"
#define FC_LR_STR(who) "Force a fixed value for the " who " leak rate\n"

DEFUN_ATTR(cfg_pcu_fc_bvc_bucket_size,
	   cfg_pcu_fc_bvc_bucket_size_cmd,
	   "flow-control force-bvc-bucket-size <1-6553500>",
	   FC_STR FC_BMAX_STR("BVC") "Bucket size in octets\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_bvc_bucket_size = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_fc_bvc_bucket_size,
	   cfg_pcu_no_fc_bvc_bucket_size_cmd,
	   "no flow-control force-bvc-bucket-size",
	   NO_STR FC_STR FC_BMAX_STR("BVC"),
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_bvc_bucket_size = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_fc_bvc_leak_rate,
	   cfg_pcu_fc_bvc_leak_rate_cmd,
	   "flow-control force-bvc-leak-rate <1-6553500>",
	   FC_STR FC_LR_STR("BVC") "Leak rate in bit/s\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_bvc_leak_rate = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_fc_bvc_leak_rate,
	   cfg_pcu_no_fc_bvc_leak_rate_cmd,
	   "no flow-control force-bvc-leak-rate",
	   NO_STR FC_STR FC_LR_STR("BVC"),
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_bvc_leak_rate = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_fc_ms_bucket_size,
	   cfg_pcu_fc_ms_bucket_size_cmd,
	   "flow-control force-ms-bucket-size <1-6553500>",
	   FC_STR FC_BMAX_STR("default MS") "Bucket size in octets\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_ms_bucket_size = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_fc_ms_bucket_size,
	   cfg_pcu_no_fc_ms_bucket_size_cmd,
	   "no flow-control force-ms-bucket-size",
	   NO_STR FC_STR FC_BMAX_STR("default MS"),
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_ms_bucket_size = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_fc_ms_leak_rate,
	   cfg_pcu_fc_ms_leak_rate_cmd,
	   "flow-control force-ms-leak-rate <1-6553500>",
	   FC_STR FC_LR_STR("default MS") "Leak rate in bit/s\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_ms_leak_rate = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_fc_ms_leak_rate,
	   cfg_pcu_no_fc_ms_leak_rate_cmd,
	   "no flow-control force-ms-leak-rate",
	   NO_STR FC_STR FC_LR_STR("default MS"),
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_ms_leak_rate = 0;
	return CMD_SUCCESS;
}

#define FC_BTIME_STR "Set target downlink maximum queueing time (only affects the advertised bucket size)\n"
DEFUN_ATTR(cfg_pcu_fc_bucket_time,
	   cfg_pcu_fc_bucket_time_cmd,
	   "flow-control bucket-time <1-65534>",
	   FC_STR FC_BTIME_STR "Time in centi-seconds\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_bucket_time = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_fc_bucket_time,
	   cfg_pcu_no_fc_bucket_time_cmd,
	   "no flow-control bucket-time",
	   NO_STR FC_STR FC_BTIME_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.fc_bucket_time = 0;
	return CMD_SUCCESS;
}

#define CS_STR "Coding Scheme configuration\n"

DEFUN_ATTR(cfg_pcu_cs,
	   cfg_pcu_cs_cmd,
	   "cs <1-4> [<1-4>]",
	   CS_STR
	   "Initial CS value to be used (overrides BTS config)\n"
	   "Use a different initial CS value for the uplink",
	   CMD_ATTR_IMMEDIATE)
{
	uint8_t cs_dl, cs_ul;
	cs_dl = atoi(argv[0]);
	if (argc > 1)
		cs_ul = atoi(argv[1]);
	else
		cs_ul = cs_dl;
	the_pcu->vty.force_initial_cs = true;
	gprs_pcu_set_initial_cs(the_pcu, cs_dl, cs_ul);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_cs,
	   cfg_pcu_no_cs_cmd,
	   "no cs",
	   NO_STR CS_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.force_initial_cs = false;
	gprs_pcu_set_initial_cs(the_pcu, 0, 0);
	return CMD_SUCCESS;
}

#define CS_MAX_STR "Set maximum values for adaptive CS selection (overrides BTS config)\n"
DEFUN_ATTR(cfg_pcu_cs_max,
	   cfg_pcu_cs_max_cmd,
	   "cs max <1-4> [<1-4>]",
	   CS_STR
	   CS_MAX_STR
	   "Maximum CS value to be used\n"
	   "Use a different maximum CS value for the uplink",
	   CMD_ATTR_IMMEDIATE)
{
	uint8_t cs_dl = atoi(argv[0]);
	uint8_t cs_ul;

	if (argc > 1)
		cs_ul = atoi(argv[1]);
	else
		cs_ul = cs_dl;

	gprs_pcu_set_max_cs(the_pcu, cs_dl, cs_ul);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_cs_max,
	   cfg_pcu_no_cs_max_cmd,
	   "no cs max",
	   NO_STR CS_STR CS_MAX_STR,
	   CMD_ATTR_IMMEDIATE)
{
	gprs_pcu_set_max_cs(the_pcu, 0, 0);
	return CMD_SUCCESS;
}

#define MCS_STR "Modulation and Coding Scheme configuration (EGPRS)\n"
DEFUN_ATTR(cfg_pcu_mcs,
	   cfg_pcu_mcs_cmd,
	   "mcs <1-9> [<1-9>]",
	   MCS_STR
	   "Initial MCS value to be used (default 1)\n"
	   "Use a different initial MCS value for the uplink",
	   CMD_ATTR_IMMEDIATE)
{
	uint8_t mcs_dl, mcs_ul;
	mcs_dl = atoi(argv[0]);
	if (argc > 1)
		mcs_ul = atoi(argv[1]);
	else
		mcs_ul = mcs_dl;
	the_pcu->vty.force_initial_mcs = true;
	gprs_pcu_set_initial_mcs(the_pcu, mcs_dl, mcs_ul);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_mcs,
	   cfg_pcu_no_mcs_cmd,
	   "no mcs",
	   NO_STR MCS_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.force_initial_mcs = false;
	gprs_pcu_set_initial_mcs(the_pcu, 0, 0);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_mcs_max,
	   cfg_pcu_mcs_max_cmd,
	   "mcs max <1-9> [<1-9>]",
	   MCS_STR
	   CS_MAX_STR
	   "Maximum MCS value to be used\n"
	   "Use a different maximum MCS value for the uplink",
	   CMD_ATTR_IMMEDIATE)
{
	uint8_t mcs_dl = atoi(argv[0]);
	uint8_t mcs_ul;

	if (argc > 1)
		mcs_ul = atoi(argv[1]);
	else
		mcs_ul = mcs_dl;

	gprs_pcu_set_max_mcs(the_pcu, mcs_dl, mcs_ul);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_mcs_max,
	   cfg_pcu_no_mcs_max_cmd,
	   "no mcs max",
	   NO_STR MCS_STR CS_MAX_STR,
	   CMD_ATTR_IMMEDIATE)
{
	gprs_pcu_set_max_mcs(the_pcu, 0, 0);
	return CMD_SUCCESS;
}

#define DL_STR "downlink specific configuration\n"

DEFUN_ATTR(cfg_pcu_dl_arq_type,
	   cfg_pcu_dl_arq_cmd,
	   "egprs dl arq-type (spb|arq2)",
	   EGPRS_STR DL_STR "ARQ options\n"
	   "enable SPB(ARQ1) support\n"
	   "enable ARQ2 support",
	   CMD_ATTR_IMMEDIATE)
{
	if (!strcmp(argv[0], "arq2"))
		the_pcu->vty.dl_arq_type = EGPRS_ARQ2;
	else
		the_pcu->vty.dl_arq_type = EGPRS_ARQ1;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_window_size,
	      cfg_pcu_window_size_cmd,
	      X(PCU_VTY_ATTR_NEW_TBF),
	      "window-size <0-1024> [<0-256>]",
	      "Window size configuration (b + N_PDCH * f)\n"
	      "Base value (b)\n"
	      "Factor for number of PDCH (f)")
{
	uint16_t b = atoi(argv[0]);

	the_pcu->vty.ws_base = b;
	if (argc > 1) {
		uint16_t f = atoi(argv[1]);
		the_pcu->vty.ws_pdch = f;
	}

	return CMD_SUCCESS;
}


#define QUEUE_STR "Packet queue options\n"
#define LIFETIME_STR "Set lifetime limit of LLC frame in centi-seconds " \
	"(overrides the value given by SGSN)\n"

DEFUN_USRATTR(cfg_pcu_queue_lifetime,
	      cfg_pcu_queue_lifetime_cmd,
	      X(PCU_VTY_ATTR_NEW_TBF),
	      "queue lifetime <1-65534>",
	      QUEUE_STR LIFETIME_STR "Lifetime in centi-seconds")
{
	uint16_t csec = atoi(argv[0]);
	the_pcu->vty.force_llc_lifetime = csec;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_queue_lifetime_inf,
	      cfg_pcu_queue_lifetime_inf_cmd,
	      X(PCU_VTY_ATTR_NEW_TBF),
	      "queue lifetime infinite",
	      QUEUE_STR LIFETIME_STR "Infinite lifetime")
{
	the_pcu->vty.force_llc_lifetime = 0xffff;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_no_queue_lifetime,
	      cfg_pcu_no_queue_lifetime_cmd,
	      X(PCU_VTY_ATTR_NEW_TBF),
	      "no queue lifetime",
	      NO_STR QUEUE_STR "Disable lifetime limit of LLC frame (use value given "
	      "by SGSN)\n")
{
	the_pcu->vty.force_llc_lifetime = 0;
	return CMD_SUCCESS;
}

#define QUEUE_HYSTERESIS_STR "Set lifetime hysteresis of LLC frame in centi-seconds " \
	"(continue discarding until lifetime-hysteresis is reached)\n"

DEFUN_USRATTR(cfg_pcu_queue_hysteresis,
	      cfg_pcu_queue_hysteresis_cmd,
	      X(PCU_VTY_ATTR_NEW_TBF),
	      "queue hysteresis <1-65535>",
	      QUEUE_STR QUEUE_HYSTERESIS_STR "Hysteresis in centi-seconds")
{
	uint16_t csec = atoi(argv[0]);
	the_pcu->vty.llc_discard_csec = csec;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_no_queue_hysteresis,
	      cfg_pcu_no_queue_hysteresis_cmd,
	      X(PCU_VTY_ATTR_NEW_TBF),
	      "no queue hysteresis",
	      NO_STR QUEUE_STR QUEUE_HYSTERESIS_STR)
{
	the_pcu->vty.llc_discard_csec = 0;
	return CMD_SUCCESS;
}

#define QUEUE_CODEL_STR "Set CoDel queue management\n"
DEFUN_USRATTR(cfg_pcu_queue_codel,
	      cfg_pcu_queue_codel_cmd,
	      X(PCU_VTY_ATTR_NEW_SUBSCR),
	      "queue codel",
	      QUEUE_STR QUEUE_CODEL_STR)
{
	the_pcu->vty.llc_codel_interval_msec = LLC_CODEL_USE_DEFAULT;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_queue_codel_interval,
	      cfg_pcu_queue_codel_interval_cmd,
	      X(PCU_VTY_ATTR_NEW_SUBSCR),
	      "queue codel interval <1-1000>",
	      QUEUE_STR QUEUE_CODEL_STR "Specify interval\n" "Interval in centi-seconds")
{
	uint16_t csec = atoi(argv[0]);
	the_pcu->vty.llc_codel_interval_msec = 10*csec;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_no_queue_codel,
	      cfg_pcu_no_queue_codel_cmd,
	      X(PCU_VTY_ATTR_NEW_SUBSCR),
	      "no queue codel",
	      NO_STR QUEUE_STR QUEUE_CODEL_STR)
{
	the_pcu->vty.llc_codel_interval_msec = LLC_CODEL_DISABLE;
	return CMD_SUCCESS;
}


#define QUEUE_IDLE_ACK_STR "Request an ACK after the last DL LLC frame in centi-seconds\n"

DEFUN_ATTR(cfg_pcu_queue_idle_ack_delay,
	   cfg_pcu_queue_idle_ack_delay_cmd,
	   "queue idle-ack-delay <1-65535>",
	   QUEUE_STR QUEUE_IDLE_ACK_STR "Idle ACK delay in centi-seconds",
	   CMD_ATTR_IMMEDIATE)
{
	uint16_t csec = atoi(argv[0]);
	the_pcu->vty.llc_idle_ack_csec = csec;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_queue_idle_ack_delay,
	   cfg_pcu_no_queue_idle_ack_delay_cmd,
	   "no queue idle-ack-delay",
	   NO_STR QUEUE_STR QUEUE_IDLE_ACK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.llc_idle_ack_csec = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_alloc,
	   cfg_pcu_alloc_cmd,
	   "alloc-algorithm (a|b|dynamic)",
	   "Select slot allocation algorithm to use when assigning timeslots on "
	   "PACCH\n"
	   "Single slot is assigned only\n"
	   "Multiple slots are assigned for semi-duplex operation\n"
	   "Dynamically select the algorithm based on the system state\n",
	   CMD_ATTR_IMMEDIATE)
{
	switch (argv[0][0]) {
	case 'a':
		the_pcu->alloc_algorithm = alloc_algorithm_a;
		break;
	case 'b':
		the_pcu->alloc_algorithm = alloc_algorithm_b;
		break;
	default:
		the_pcu->alloc_algorithm = alloc_algorithm_dynamic;
		break;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_two_phase,
	   cfg_pcu_two_phase_cmd,
	   "two-phase-access",
	   "Force two phase access when MS requests single phase access\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.force_two_phase = 1;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_two_phase,
	   cfg_pcu_no_two_phase_cmd,
	   "no two-phase-access",
	   NO_STR "Only use two phase access when requested my MS\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.force_two_phase = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_alpha,
	   cfg_pcu_alpha_cmd,
	   "alpha <0-10>",
	   "Alpha parameter for MS power control in units of 0.1 (see TS 05.08) "
	   "NOTE: Be sure to set Alpha value at System information 13 too.\n"
	   "Alpha in units of 0.1\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.alpha = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_gamma,
	   cfg_pcu_gamma_cmd,
	   "gamma <0-62>",
	   "Gamma parameter for MS power control in units of dB (see TS 05.08)\n"
	   "Gamma in even unit of dBs\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.gamma = atoi(argv[0]) / 2;
	return CMD_SUCCESS;
}

DEFUN(show_bts_stats,
      show_bts_stats_cmd,
      "show bts statistics",
      SHOW_STR "BTS related functionality\nStatistics\n")
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		vty_out(vty, "BTS%" PRIu8 ":%s", bts->nr, VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, " ", bts_rate_counters(bts));
	}
	return CMD_SUCCESS;
}

DEFUN(show_bts_pdch,
      show_bts_pdch_cmd,
      "show bts pdch",
      SHOW_STR "BTS related functionality\nPDCH timeslots\n")
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		pcu_vty_show_bts_pdch(vty, bts);
	}
	return CMD_SUCCESS;
}

#define IDLE_TIME_STR "keep an idle DL TBF alive for the time given\n"
DEFUN_DEPRECATED(cfg_pcu_dl_tbf_idle_time,
      cfg_pcu_dl_tbf_idle_time_cmd,
      "dl-tbf-idle-time <1-5000>",
      IDLE_TIME_STR "idle time in msec")
{
	vty_out(vty, "%% 'dl-tbf-idle-time' is now deprecated: use 'timer X2031 <val>' instead%s", VTY_NEWLINE);

	if (osmo_tdef_set(the_pcu->T_defs, -2031, atoi(argv[0]), OSMO_TDEF_MS) < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_pcu_no_dl_tbf_idle_time,
      cfg_pcu_no_dl_tbf_idle_time_cmd,
      "no dl-tbf-idle-time",
      NO_STR IDLE_TIME_STR)
{
	vty_out(vty, "%% 'no dl-tbf-idle-time' is now deprecated: use 'timer X2031 0' instead%s", VTY_NEWLINE);

	if (osmo_tdef_set(the_pcu->T_defs, -2031, 0, OSMO_TDEF_MS) < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

#define RETRANSMISSION_STR "retransmit blocks even before the MS had a chance to receive them (better throughput," \
			   " less readable traces)"
DEFUN_ATTR(cfg_pcu_dl_tbf_preemptive_retransmission,
	   cfg_pcu_dl_tbf_preemptive_retransmission_cmd,
	   "dl-tbf-preemptive-retransmission",
	   RETRANSMISSION_STR " (enabled by default)",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.dl_tbf_preemptive_retransmission = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_dl_tbf_preemptive_retransmission,
	   cfg_pcu_no_dl_tbf_preemptive_retransmission_cmd,
	   "no dl-tbf-preemptive-retransmission",
	   NO_STR RETRANSMISSION_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.dl_tbf_preemptive_retransmission = false;
	return CMD_SUCCESS;
}

#define MS_IDLE_TIME_STR "keep an idle MS object alive for the time given\n"
DEFUN_DEPRECATED(cfg_pcu_ms_idle_time,
      cfg_pcu_ms_idle_time_cmd,
      "ms-idle-time <1-7200>",
      MS_IDLE_TIME_STR "idle time in sec")
{
	vty_out(vty, "%% 'ms-idle-time' is now deprecated: use 'timer X2030 <val>' instead%s", VTY_NEWLINE);
	if (osmo_tdef_set(the_pcu->T_defs, -2030, atoi(argv[0]), OSMO_TDEF_S) < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_pcu_no_ms_idle_time,
      cfg_pcu_no_ms_idle_time_cmd,
      "no ms-idle-time",
      NO_STR MS_IDLE_TIME_STR)
{
	vty_out(vty, "%% 'no ms-idle-time' is now deprecated: use 'timer X2030 0' instead%s", VTY_NEWLINE);
	if (osmo_tdef_set(the_pcu->T_defs, -2030, 0, OSMO_TDEF_S) < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

#define CS_ERR_LIMITS_STR "set thresholds for error rate based downlink (M)CS adjustment\n"
DEFUN_ATTR(cfg_pcu_cs_err_limits,
	   cfg_pcu_cs_err_limits_cmd,
	   "cs threshold <0-100> <0-100>",
	   CS_STR CS_ERR_LIMITS_STR "lower limit in %\n" "upper limit in %\n",
	   CMD_ATTR_IMMEDIATE)
{
	uint8_t lower_limit = atoi(argv[0]);
	uint8_t upper_limit = atoi(argv[1]);

	if (lower_limit > upper_limit) {
		vty_out(vty,
			"The lower limit must be less than or equal to the "
			"upper limit.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	the_pcu->vty.cs_adj_enabled = true;
	the_pcu->vty.cs_adj_upper_limit = upper_limit;
	the_pcu->vty.cs_adj_lower_limit = lower_limit;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_cs_err_limits,
	   cfg_pcu_no_cs_err_limits_cmd,
	   "no cs threshold",
	   NO_STR CS_STR CS_ERR_LIMITS_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.cs_adj_enabled = false;
	the_pcu->vty.cs_adj_upper_limit = 100;
	the_pcu->vty.cs_adj_lower_limit = 0;

	return CMD_SUCCESS;
}

#define CS_DOWNGRADE_STR "set threshold for data size based downlink (M)CS downgrade\n"
DEFUN_ATTR(cfg_pcu_cs_downgrade_thrsh,
	   cfg_pcu_cs_downgrade_thrsh_cmd,
	   "cs downgrade-threshold <1-10000>",
	   CS_STR CS_DOWNGRADE_STR "downgrade if less octets left\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.cs_downgrade_threshold = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_no_cs_downgrade_thrsh,
	   cfg_pcu_no_cs_downgrade_thrsh_cmd,
	   "no cs downgrade-threshold",
	   NO_STR CS_STR CS_DOWNGRADE_STR,
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.cs_downgrade_threshold = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_cs_lqual_ranges,
	   cfg_pcu_cs_lqual_ranges_cmd,
	   "cs link-quality-ranges cs1 <0-35> cs2 <0-35> <0-35> cs3 <0-35> <0-35> cs4 <0-35>",
	   CS_STR "Set link quality ranges for each uplink CS\n"
	   "Set quality range for CS-1 (high value only)\n"
	   "CS-1 high (dB)\n"
	   "Set quality range for CS-2\n"
	   "CS-2 low (dB)\n"
	   "CS-2 high (dB)\n"
	   "Set quality range for CS-3\n"
	   "CS-3 low (dB)\n"
	   "CS-3 high (dB)\n"
	   "Set quality range for CS-4 (low value only)\n"
	   "CS-4 low (dB)\n",
	   CMD_ATTR_IMMEDIATE)
{
	uint8_t cs1_high = atoi(argv[0]);
	uint8_t cs2_low = atoi(argv[1]);
	uint8_t cs2_high = atoi(argv[2]);
	uint8_t cs3_low = atoi(argv[3]);
	uint8_t cs3_high = atoi(argv[4]);
	uint8_t cs4_low = atoi(argv[5]);

	the_pcu->vty.cs_lqual_ranges[0].high = cs1_high;
	the_pcu->vty.cs_lqual_ranges[1].low  = cs2_low;
	the_pcu->vty.cs_lqual_ranges[1].high = cs2_high;
	the_pcu->vty.cs_lqual_ranges[2].low  = cs3_low;
	the_pcu->vty.cs_lqual_ranges[2].high = cs3_high;
	the_pcu->vty.cs_lqual_ranges[3].low  = cs4_low;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_pcu_mcs_lqual_ranges,
	   cfg_pcu_mcs_lqual_ranges_cmd,
	   "mcs link-quality-ranges mcs1 <0-35> mcs2 <0-35> <0-35> mcs3 <0-35> <0-35> mcs4 <0-35> <0-35> mcs5 <0-35> <0-35> mcs6 <0-35> <0-35> mcs7 <0-35> <0-35> mcs8 <0-35> <0-35> mcs9 <0-35>",
	   CS_STR "Set link quality ranges for each uplink MCS\n"
	   "Set quality range for MCS-1 (high value only)\n"
	   "MCS-1 high (dB)\n"
	   "Set quality range for MCS-2\n"
	   "MCS-2 high (dB)\n"
	   "MCS-2 low (dB)\n"
	   "Set quality range for MCS-3\n"
	   "MCS-3 high (dB)\n"
	   "MCS-3 low (dB)\n"
	   "Set quality range for MCS-4\n"
	   "MCS-4 high (dB)\n"
	   "MCS-4 low (dB)\n"
	   "Set quality range for MCS-5\n"
	   "MCS-5 high (dB)\n"
	   "MCS-5 low (dB)\n"
	   "Set quality range for MCS-6\n"
	   "MCS-6 low (dB)\n"
	   "MCS-6 high (dB)\n"
	   "Set quality range for MCS-7\n"
	   "MCS-7 low (dB)\n"
	   "MCS-7 high (dB)\n"
	   "Set quality range for MCS-8\n"
	   "MCS-8 low (dB)\n"
	   "MCS-8 high (dB)\n"
	   "Set quality range for MCS-9 (low value only)\n"
	   "MCS-9 low (dB)\n",
	   CMD_ATTR_IMMEDIATE)
{
	the_pcu->vty.mcs_lqual_ranges[0].high = atoi(argv[0]);
	the_pcu->vty.mcs_lqual_ranges[1].low  = atoi(argv[1]);
	the_pcu->vty.mcs_lqual_ranges[1].high = atoi(argv[2]);
	the_pcu->vty.mcs_lqual_ranges[2].low  = atoi(argv[3]);
	the_pcu->vty.mcs_lqual_ranges[2].high = atoi(argv[4]);
	the_pcu->vty.mcs_lqual_ranges[3].low  = atoi(argv[5]);
	the_pcu->vty.mcs_lqual_ranges[3].high  = atoi(argv[6]);
	the_pcu->vty.mcs_lqual_ranges[4].low  = atoi(argv[7]);
	the_pcu->vty.mcs_lqual_ranges[4].high  = atoi(argv[8]);
	the_pcu->vty.mcs_lqual_ranges[5].low  = atoi(argv[9]);
	the_pcu->vty.mcs_lqual_ranges[5].high  = atoi(argv[10]);
	the_pcu->vty.mcs_lqual_ranges[6].low  = atoi(argv[11]);
	the_pcu->vty.mcs_lqual_ranges[6].high  = atoi(argv[12]);
	the_pcu->vty.mcs_lqual_ranges[7].low  = atoi(argv[13]);
	the_pcu->vty.mcs_lqual_ranges[7].high  = atoi(argv[14]);
	the_pcu->vty.mcs_lqual_ranges[8].low  = atoi(argv[15]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_sock,
      cfg_pcu_sock_cmd,
      "pcu-socket PATH",
      "Configure the osmo-bts PCU socket file/path name\n"
      "Path of the socket to connect to\n")
{
	if (vty->type != VTY_FILE)
		vty_out(vty, "Changing PCU socket path at run-time has no effect%s", VTY_NEWLINE);

	osmo_talloc_replace_string(tall_pcu_ctx, &the_pcu->pcu_sock_path, argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_pcu_gb_dialect,
	      cfg_pcu_gb_dialect_cmd,
	      X(PCU_VTY_ATTR_NS_RESET),
	      "gb-dialect (classic|ip-sns)",
	      "Select which Gb interface dialect to use\n"
	      "Classic Gb interface with NS-{RESET,BLOCK,UNBLOCK} and static configuration\n"
	      "Modern Gb interface with IP-SNS (Sub Network Service) and dynamic configuration\n")
{
	if (!strcmp(argv[0], "ip-sns")) {
		the_pcu->vty.ns_dialect = GPRS_NS2_DIALECT_SNS;
	} else {
		the_pcu->vty.ns_dialect = GPRS_NS2_DIALECT_IPACCESS;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_neighbor_resolution, cfg_neighbor_resolution_cmd,
       "neighbor resolution " VTY_IPV46_CMD " [<0-65535>]",
       "Manage local and remote-BSS neighbor cells\n"
       "Connect to Neighbor Resolution Service (CTRL interface) to given ip and port\n"
       "IPv4 address to connect to\n" "IPv6 address to connect to\n"
       "Port to connect to (default 4248)\n")
{
	osmo_talloc_replace_string(the_pcu, &the_pcu->vty.neigh_ctrl_addr, argv[0]);
	if (argc > 1)
		the_pcu->vty.neigh_ctrl_port = atoi(argv[1]);
	else
		the_pcu->vty.neigh_ctrl_port = OSMO_CTRL_PORT_BSC_NEIGH;
	return CMD_SUCCESS;
}


DEFUN(show_bts_timer, show_bts_timer_cmd,
      "show bts-timer " OSMO_TDEF_VTY_ARG_T_OPTIONAL,
      SHOW_STR "Show BTS controlled timers\n"
      OSMO_TDEF_VTY_DOC_T)
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		const char *T_arg = argc > 0 ? argv[0] : NULL;
		vty_out(vty, "BTS%" PRIu8 ":%s", bts->nr, VTY_NEWLINE);
		osmo_tdef_vty_show_cmd(vty, bts->T_defs_bts, T_arg, " ");
	}
	return CMD_SUCCESS;
}

DEFUN(show_timer, show_timer_cmd,
      "show timer " OSMO_TDEF_VTY_ARG_T_OPTIONAL,
      SHOW_STR "Show PCU timers\n"
      OSMO_TDEF_VTY_DOC_T)
{
	const char *T_arg = argc > 0 ? argv[0] : NULL;
	return osmo_tdef_vty_show_cmd(vty, the_pcu->T_defs, T_arg, NULL);
}

DEFUN_ATTR(cfg_pcu_timer, cfg_pcu_timer_cmd,
	   "timer " OSMO_TDEF_VTY_ARG_SET_OPTIONAL,
	   "Configure or show PCU timers\n"
	   OSMO_TDEF_VTY_DOC_SET,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	struct osmo_tdef *t;
	/* If any arguments are missing, redirect to 'show' */
	if (argc < 2)
		return show_timer(self, vty, argc, argv);
	if ((rc = osmo_tdef_vty_set_cmd(vty, the_pcu->T_defs, argv)) != CMD_SUCCESS)
		return rc;
	t = osmo_tdef_vty_parse_T_arg(vty, the_pcu->T_defs, argv[0]);
	switch (t->T) {
	case PCU_TDEF_NEIGH_CACHE_ALIVE:
		neigh_cache_set_keep_time_interval(the_pcu->neigh_cache, t->val);
		break;
	case PCU_TDEF_SI_CACHE_ALIVE:
		si_cache_set_keep_time_interval(the_pcu->si_cache, t->val);
		break;
	default:
		break;
	}
	return CMD_SUCCESS;
}

DEFUN(show_tbf,
      show_tbf_cmd,
      "show tbf (all|ccch|pacch)",
      SHOW_STR "information about TBFs\n"
      "All TBFs\n"
      "TBFs allocated via CCCH\n"
      "TBFs allocated via PACCH\n")
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		uint32_t flags = UINT32_MAX;

		if (argv[0][0] == 'c')
			flags = (1 << GPRS_RLCMAC_FLAG_CCCH);
		else if (argv[0][0] == 'p')
			flags = (1 << GPRS_RLCMAC_FLAG_PACCH);

		pcu_vty_show_tbf_all(vty, bts, flags);
	}
	return CMD_SUCCESS;
}

DEFUN(show_ms_all,
      show_ms_all_cmd,
      "show ms all",
      SHOW_STR "information about MSs\n" "All TBFs\n")
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		pcu_vty_show_ms_all(vty, bts);
	}
	return CMD_SUCCESS;
}

DEFUN(show_ms_tlli,
      show_ms_tlli_cmd,
      "show ms tlli TLLI",
      SHOW_STR "information about MSs\n" "Select MS by TLLI\n" "TLLI as hex\n")
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		char *endp = NULL;
		unsigned long long tlli = strtoll(argv[0], &endp, 16);
		if ((endp != NULL && *endp != 0) || tlli > 0xffffffffULL) {
			vty_out(vty, "Invalid TLLI.%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		pcu_vty_show_ms_by_tlli(vty, bts, (uint32_t)tlli);
	}
	return CMD_SUCCESS;
}

DEFUN(show_ms_imsi,
      show_ms_imsi_cmd,
      "show ms imsi IMSI",
      SHOW_STR "information about MSs\n" "Select MS by IMSI\n" "IMSI\n")
{
	struct gprs_rlcmac_bts *bts;
	llist_for_each_entry(bts, &the_pcu->bts_list, list) {
		pcu_vty_show_ms_by_imsi(vty, bts, argv[0]);
	}
	return CMD_SUCCESS;
}

static const char pcu_copyright[] =
	"Copyright (C) 2012 by Ivan Kluchnikov <kluchnikovi@gmail.com> and \r\n"
	"                      Andreas Eversberg <jolly@eversberg.eu>\r\n"
	"License GNU GPL version 2 or later\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

struct vty_app_info pcu_vty_info = {
	.name		= "OsmoPCU",
	.version	= PACKAGE_VERSION,
	.copyright	= pcu_copyright,
	.usr_attr_desc	= {
		[PCU_VTY_ATTR_NEW_TBF] = \
			"This command applies when a new TBF is begins",
		[PCU_VTY_ATTR_NEW_SUBSCR] = \
			"This command applies when a new subscriber attaches",
		[PCU_VTY_ATTR_NS_RESET] = \
			"This command applies when the NS is reset",
	},
	.usr_attr_letters = {
		[PCU_VTY_ATTR_NEW_TBF]		= 'n',
		[PCU_VTY_ATTR_NEW_SUBSCR]	= 's',
		[PCU_VTY_ATTR_NS_RESET]		= 'r',
	},
};

int pcu_vty_init(void)
{
//	install_element_ve(&show_pcu_cmd);

	cfg_pcu_gsmtap_categ_cmd.string = vty_cmd_string_from_valstr(tall_pcu_ctx, pcu_gsmtap_categ_names,
						"gsmtap-category (",
						"|",")", VTY_DO_LOWER);
	cfg_pcu_gsmtap_categ_cmd.doc = vty_cmd_string_from_valstr(tall_pcu_ctx, pcu_gsmtap_categ_help,
						"GSMTAP Category\n",
						"\n", "", 0);
	cfg_pcu_no_gsmtap_categ_cmd.string = vty_cmd_string_from_valstr(tall_pcu_ctx, pcu_gsmtap_categ_names,
						"no gsmtap-category (",
						"|",")", VTY_DO_LOWER);
	cfg_pcu_no_gsmtap_categ_cmd.doc = vty_cmd_string_from_valstr(tall_pcu_ctx, pcu_gsmtap_categ_help,
						NO_STR "GSMTAP Category\n",
						"\n", "", 0);

	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	install_node(&pcu_node, config_write_pcu);
	install_element(CONFIG_NODE, &cfg_pcu_cmd);
	install_element(PCU_NODE, &cfg_pcu_egprs_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_egprs_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_two_phase_cmd);
	install_element(PCU_NODE, &cfg_pcu_cs_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_cs_cmd);
	install_element(PCU_NODE, &cfg_pcu_cs_max_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_cs_max_cmd);
	install_element(PCU_NODE, &cfg_pcu_cs_err_limits_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_cs_err_limits_cmd);
	install_element(PCU_NODE, &cfg_pcu_cs_downgrade_thrsh_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_cs_downgrade_thrsh_cmd);
	install_element(PCU_NODE, &cfg_pcu_cs_lqual_ranges_cmd);
	install_element(PCU_NODE, &cfg_pcu_mcs_lqual_ranges_cmd);
	install_element(PCU_NODE, &cfg_pcu_mcs_cmd);
	install_element(PCU_NODE, &cfg_pcu_dl_arq_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_mcs_cmd);
	install_element(PCU_NODE, &cfg_pcu_mcs_max_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_mcs_max_cmd);
	install_element(PCU_NODE, &cfg_pcu_window_size_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_lifetime_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_lifetime_inf_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_queue_lifetime_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_hysteresis_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_queue_hysteresis_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_codel_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_codel_interval_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_queue_codel_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_idle_ack_delay_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_queue_idle_ack_delay_cmd);
	install_element(PCU_NODE, &cfg_pcu_alloc_cmd);
	install_element(PCU_NODE, &cfg_pcu_two_phase_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_interval_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_bucket_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_fc_bucket_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_bvc_bucket_size_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_fc_bvc_bucket_size_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_bvc_leak_rate_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_fc_bvc_leak_rate_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_ms_bucket_size_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_fc_ms_bucket_size_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_ms_leak_rate_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_fc_ms_leak_rate_cmd);
	install_element(PCU_NODE, &cfg_pcu_alpha_cmd);
	install_element(PCU_NODE, &cfg_pcu_gamma_cmd);
	install_element(PCU_NODE, &cfg_pcu_dl_tbf_idle_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_dl_tbf_idle_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_dl_tbf_preemptive_retransmission_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_dl_tbf_preemptive_retransmission_cmd);
	install_element(PCU_NODE, &cfg_pcu_ms_idle_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_ms_idle_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_gsmtap_categ_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_gsmtap_categ_cmd);
	install_element(PCU_NODE, &cfg_pcu_sock_cmd);
	install_element(PCU_NODE, &cfg_pcu_gb_dialect_cmd);
	install_element(PCU_NODE, &cfg_neighbor_resolution_cmd);
	install_element(PCU_NODE, &cfg_pcu_timer_cmd);

	install_element_ve(&show_bts_stats_cmd);
	install_element_ve(&show_bts_pdch_cmd);
	install_element_ve(&show_tbf_cmd);
	install_element_ve(&show_ms_all_cmd);
	install_element_ve(&show_ms_tlli_cmd);
	install_element_ve(&show_ms_imsi_cmd);
	install_element_ve(&show_bts_timer_cmd);
	install_element_ve(&show_timer_cmd);

	return 0;
}
