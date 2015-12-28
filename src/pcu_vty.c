/* OsmoBTS VTY interface */


#include <stdint.h>
#include <stdlib.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include "pcu_vty.h"
#include "gprs_rlcmac.h"
#include "bts.h"
#include "tbf.h"

#include "pcu_vty_functions.h"

int pcu_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
#if 0
	case TRX_NODE:
		vty->node = PCU_NODE;
		{
			struct gsm_bts_trx *trx = vty->index;
			vty->index = trx->bts;
		}
		break;
#endif
	default:
		vty->node = CONFIG_NODE;
	}
	return (enum node_type) vty->node;
}

int pcu_vty_is_config_node(struct vty *vty, int node)
{
	switch (node) {
	case PCU_NODE:
		return 1;
	default:
		return 0;
	}
}

static struct cmd_node pcu_node = {
	(enum node_type) PCU_NODE,
	"%s(config-pcu)# ",
	1,
};

static int config_write_pcu(struct vty *vty)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	vty_out(vty, "pcu%s", VTY_NEWLINE);
	if (bts->egprs_enabled)
		vty_out(vty, " egprs%s", VTY_NEWLINE);
	else
		vty_out(vty, " no egprs%s", VTY_NEWLINE);

	vty_out(vty, " flow-control-interval %d%s", bts->fc_interval,
		VTY_NEWLINE);
	if (bts->fc_bvc_bucket_size)
		vty_out(vty, " flow-control force-bvc-bucket-size %d%s",
			bts->fc_bvc_bucket_size, VTY_NEWLINE);
	if (bts->fc_bvc_leak_rate)
		vty_out(vty, " flow-control force-bvc-leak-rate %d%s",
			bts->fc_bvc_leak_rate, VTY_NEWLINE);
	if (bts->fc_ms_bucket_size)
		vty_out(vty, " flow-control force-ms-bucket-size %d%s",
			bts->fc_ms_bucket_size, VTY_NEWLINE);
	if (bts->fc_ms_leak_rate)
		vty_out(vty, " flow-control force-ms-leak-rate %d%s",
			bts->fc_ms_leak_rate, VTY_NEWLINE);
	if (bts->force_cs) {
		if (bts->initial_cs_ul == bts->initial_cs_dl)
			vty_out(vty, " cs %d%s", bts->initial_cs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " cs %d %d%s", bts->initial_cs_dl,
				bts->initial_cs_ul, VTY_NEWLINE);
	}
	if (bts->max_cs_dl && bts->max_cs_ul) {
		if (bts->max_cs_ul == bts->max_cs_dl)
			vty_out(vty, " cs max %d%s", bts->max_cs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " cs max %d %d%s", bts->max_cs_dl,
				bts->max_cs_ul, VTY_NEWLINE);
	}
	if (bts->cs_adj_enabled)
		vty_out(vty, " cs threshold %d %d%s",
			bts->cs_adj_lower_limit, bts->cs_adj_upper_limit,
			VTY_NEWLINE);
	else
		vty_out(vty, " no cs threshold%s", VTY_NEWLINE);

	if (bts->cs_downgrade_threshold)
		vty_out(vty, " cs downgrade-threshold %d%s",
			bts->cs_downgrade_threshold, VTY_NEWLINE);
	else
		vty_out(vty, " no cs downgrade-threshold%s", VTY_NEWLINE);

	vty_out(vty, " cs link-quality-ranges cs1 %d cs2 %d %d cs3 %d %d cs4 %d%s",
		bts->cs_lqual_ranges[0].high,
		bts->cs_lqual_ranges[1].low,
		bts->cs_lqual_ranges[1].high,
		bts->cs_lqual_ranges[2].low,
		bts->cs_lqual_ranges[2].high,
		bts->cs_lqual_ranges[3].low,
		VTY_NEWLINE);

	if (bts->force_llc_lifetime == 0xffff)
		vty_out(vty, " queue lifetime infinite%s", VTY_NEWLINE);
	else if (bts->force_llc_lifetime)
		vty_out(vty, " queue lifetime %d%s", bts->force_llc_lifetime,
			VTY_NEWLINE);
	if (bts->llc_discard_csec)
		vty_out(vty, " queue hysteresis %d%s", bts->llc_discard_csec,
			VTY_NEWLINE);
	if (bts->llc_idle_ack_csec)
		vty_out(vty, " queue idle-ack-delay %d%s", bts->llc_idle_ack_csec,
			VTY_NEWLINE);
	if (bts->llc_codel_interval_msec == LLC_CODEL_USE_DEFAULT)
		vty_out(vty, " queue codel%s", VTY_NEWLINE);
	else if (bts->llc_codel_interval_msec == LLC_CODEL_DISABLE)
		vty_out(vty, " no queue codel%s", VTY_NEWLINE);
	else
		vty_out(vty, " queue codel interval %d%s",
			bts->llc_codel_interval_msec/10, VTY_NEWLINE);

	if (bts->alloc_algorithm == alloc_algorithm_a)
		vty_out(vty, " alloc-algorithm a%s", VTY_NEWLINE);
	if (bts->alloc_algorithm == alloc_algorithm_b)
		vty_out(vty, " alloc-algorithm b%s", VTY_NEWLINE);
	if (bts->alloc_algorithm == alloc_algorithm_dynamic)
		vty_out(vty, " alloc-algorithm dynamic%s", VTY_NEWLINE);
	if (bts->force_two_phase)
		vty_out(vty, " two-phase-access%s", VTY_NEWLINE);
	vty_out(vty, " alpha %d%s", bts->alpha, VTY_NEWLINE);
	vty_out(vty, " gamma %d%s", bts->gamma * 2, VTY_NEWLINE);
	if (bts->dl_tbf_idle_msec)
		vty_out(vty, " dl-tbf-idle-time %d%s", bts->dl_tbf_idle_msec,
			VTY_NEWLINE);

	return pcu_vty_config_write_pcu_ext(vty);
}

/* per-BTS configuration */
DEFUN(cfg_pcu,
      cfg_pcu_cmd,
      "pcu",
      "BTS specific configure")
{
	vty->node = PCU_NODE;

	return CMD_SUCCESS;
}

#define EGPRS_STR "EGPRS configuration\n"

DEFUN(cfg_pcu_egprs,
      cfg_pcu_egprs_cmd,
      "egprs",
      EGPRS_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->egprs_enabled = 1;

	vty_out(vty, "%%Note that EGPRS support is in an experimental state "
		"and the PCU will currently fail to use a TBF if the MS is capable "
		"to do EGPRS. You may want to disable this feature by entering "
		"the \"no egprs\" command. "
		"Do not use this in production!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_egprs,
      cfg_pcu_no_egprs_cmd,
      "no egprs",
      NO_STR EGPRS_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->egprs_enabled = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_fc_interval,
      cfg_pcu_fc_interval_cmd,
      "flow-control-interval <1-10>",
      "Interval between sending subsequent Flow Control PDUs\n"
      "Interval time in seconds\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_interval = atoi(argv[0]);

	return CMD_SUCCESS;
}
#define FC_STR "BSSGP Flow Control configuration\n"
#define FC_BMAX_STR(who) "Force a fixed value for the " who " bucket size\n"
#define FC_LR_STR(who) "Force a fixed value for the " who " leak rate\n"

DEFUN(cfg_pcu_fc_bvc_bucket_size,
      cfg_pcu_fc_bvc_bucket_size_cmd,
      "flow-control force-bvc-bucket-size <1-6553500>",
      FC_STR FC_BMAX_STR("BVC") "Bucket size in octets\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_bvc_bucket_size = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_fc_bvc_bucket_size,
      cfg_pcu_no_fc_bvc_bucket_size_cmd,
      "no flow-control force-bvc-bucket-size",
      NO_STR FC_STR FC_BMAX_STR("BVC"))
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_bvc_bucket_size = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_fc_bvc_leak_rate,
      cfg_pcu_fc_bvc_leak_rate_cmd,
      "flow-control force-bvc-leak-rate <1-6553500>",
      FC_STR FC_LR_STR("BVC") "Leak rate in bit/s\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_bvc_leak_rate = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_fc_bvc_leak_rate,
      cfg_pcu_no_fc_bvc_leak_rate_cmd,
      "no flow-control force-bvc-leak-rate",
      NO_STR FC_STR FC_LR_STR("BVC"))
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_bvc_leak_rate = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_fc_ms_bucket_size,
      cfg_pcu_fc_ms_bucket_size_cmd,
      "flow-control force-ms-bucket-size <1-6553500>",
      FC_STR FC_BMAX_STR("default MS") "Bucket size in octets\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_ms_bucket_size = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_fc_ms_bucket_size,
      cfg_pcu_no_fc_ms_bucket_size_cmd,
      "no flow-control force-ms-bucket-size",
      NO_STR FC_STR FC_BMAX_STR("default MS"))
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_ms_bucket_size = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_fc_ms_leak_rate,
      cfg_pcu_fc_ms_leak_rate_cmd,
      "flow-control force-ms-leak-rate <1-6553500>",
      FC_STR FC_LR_STR("default MS") "Leak rate in bit/s\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_ms_leak_rate = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_fc_ms_leak_rate,
      cfg_pcu_no_fc_ms_leak_rate_cmd,
      "no flow-control force-ms-leak-rate",
      NO_STR FC_STR FC_LR_STR("default MS"))
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_ms_leak_rate = 0;

	return CMD_SUCCESS;
}

#define FC_BTIME_STR "Set target downlink maximum queueing time (only affects the advertised bucket size)\n"
DEFUN(cfg_pcu_fc_bucket_time,
      cfg_pcu_fc_bucket_time_cmd,
      "flow-control bucket-time <1-65534>",
      FC_STR FC_BTIME_STR "Time in centi-seconds\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_bucket_time = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_fc_bucket_time,
      cfg_pcu_no_fc_bucket_time_cmd,
      "no flow-control bucket-time",
      NO_STR FC_STR FC_BTIME_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->fc_bucket_time = 0;

	return CMD_SUCCESS;
}

#define CS_STR "Coding Scheme configuration\n"

DEFUN(cfg_pcu_cs,
      cfg_pcu_cs_cmd,
      "cs <1-4> [<1-4>]",
      CS_STR
      "Initial CS value to be used (overrides BTS config)\n"
      "Use a different initial CS value for the uplink")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint8_t cs = atoi(argv[0]);

	bts->force_cs = 1;
	bts->initial_cs_dl = cs;
	if (argc > 1)
		bts->initial_cs_ul = atoi(argv[1]);
	else
		bts->initial_cs_ul = cs;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_cs,
      cfg_pcu_no_cs_cmd,
      "no cs",
      NO_STR CS_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->force_cs = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_cs_max,
      cfg_pcu_cs_max_cmd,
      "cs max <1-4> [<1-4>]",
      CS_STR
      "Set maximum values for adaptive CS selection (overrides BTS config)\n"
      "Maximum CS value to be used\n"
      "Use a different maximum CS value for the uplink")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint8_t cs = atoi(argv[0]);

	bts->max_cs_dl = cs;
	if (argc > 1)
		bts->max_cs_ul = atoi(argv[1]);
	else
		bts->max_cs_ul = cs;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_cs_max,
      cfg_pcu_no_cs_max_cmd,
      "no cs max",
      NO_STR CS_STR
      "Set maximum values for adaptive CS selection (overrides BTS config)\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->max_cs_dl = 0;
	bts->max_cs_ul = 0;

	return CMD_SUCCESS;
}

#define QUEUE_STR "Packet queue options\n"
#define LIFETIME_STR "Set lifetime limit of LLC frame in centi-seconds " \
	"(overrides the value given by SGSN)\n"

DEFUN(cfg_pcu_queue_lifetime,
      cfg_pcu_queue_lifetime_cmd,
      "queue lifetime <1-65534>",
      QUEUE_STR LIFETIME_STR "Lifetime in centi-seconds")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint16_t csec = atoi(argv[0]);

	bts->force_llc_lifetime = csec;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_queue_lifetime_inf,
      cfg_pcu_queue_lifetime_inf_cmd,
      "queue lifetime infinite",
      QUEUE_STR LIFETIME_STR "Infinite lifetime")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->force_llc_lifetime = 0xffff;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_queue_lifetime,
      cfg_pcu_no_queue_lifetime_cmd,
      "no queue lifetime",
      NO_STR QUEUE_STR "Disable lifetime limit of LLC frame (use value given "
      "by SGSN)\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->force_llc_lifetime = 0;

	return CMD_SUCCESS;
}

#define QUEUE_HYSTERESIS_STR "Set lifetime hysteresis of LLC frame in centi-seconds " \
	"(continue discarding until lifetime-hysteresis is reached)\n"

DEFUN(cfg_pcu_queue_hysteresis,
      cfg_pcu_queue_hysteresis_cmd,
      "queue hysteresis <1-65535>",
      QUEUE_STR QUEUE_HYSTERESIS_STR "Hysteresis in centi-seconds")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint16_t csec = atoi(argv[0]);

	bts->llc_discard_csec = csec;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_queue_hysteresis,
      cfg_pcu_no_queue_hysteresis_cmd,
      "no queue hysteresis",
      NO_STR QUEUE_STR QUEUE_HYSTERESIS_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->llc_discard_csec = 0;

	return CMD_SUCCESS;
}

#define QUEUE_CODEL_STR "Set CoDel queue management\n"

DEFUN(cfg_pcu_queue_codel,
      cfg_pcu_queue_codel_cmd,
      "queue codel",
      QUEUE_STR QUEUE_CODEL_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->llc_codel_interval_msec = LLC_CODEL_USE_DEFAULT;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_queue_codel_interval,
      cfg_pcu_queue_codel_interval_cmd,
      "queue codel interval <1-1000>",
      QUEUE_STR QUEUE_CODEL_STR "Specify interval\n" "Interval in centi-seconds")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint16_t csec = atoi(argv[0]);

	bts->llc_codel_interval_msec = 10*csec;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_queue_codel,
      cfg_pcu_no_queue_codel_cmd,
      "no queue codel",
      NO_STR QUEUE_STR QUEUE_CODEL_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->llc_codel_interval_msec = LLC_CODEL_DISABLE;

	return CMD_SUCCESS;
}


#define QUEUE_IDLE_ACK_STR "Request an ACK after the last DL LLC frame in centi-seconds\n"

DEFUN(cfg_pcu_queue_idle_ack_delay,
      cfg_pcu_queue_idle_ack_delay_cmd,
      "queue idle-ack-delay <1-65535>",
      QUEUE_STR QUEUE_IDLE_ACK_STR "Idle ACK delay in centi-seconds")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint16_t csec = atoi(argv[0]);

	bts->llc_idle_ack_csec = csec;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_queue_idle_ack_delay,
      cfg_pcu_no_queue_idle_ack_delay_cmd,
      "no queue idle-ack-delay",
      NO_STR QUEUE_STR QUEUE_IDLE_ACK_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->llc_idle_ack_csec = 0;

	return CMD_SUCCESS;
}


DEFUN(cfg_pcu_alloc,
      cfg_pcu_alloc_cmd,
      "alloc-algorithm (a|b|dynamic)",
      "Select slot allocation algorithm to use when assigning timeslots on "
      "PACCH\n"
      "Single slot is assigned only\n"
      "Multiple slots are assigned for semi-duplex operation\n"
      "Dynamically select the algorithm based on the system state\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	switch (argv[0][0]) {
	case 'a':
		bts->alloc_algorithm = alloc_algorithm_a;
		break;
	case 'b':
		bts->alloc_algorithm = alloc_algorithm_b;
		break;
	default:
		bts->alloc_algorithm = alloc_algorithm_dynamic;
		break;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_two_phase,
      cfg_pcu_two_phase_cmd,
      "two-phase-access",
      "Force two phase access when MS requests single phase access\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->force_two_phase = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_two_phase,
      cfg_pcu_no_two_phase_cmd,
      "no two-phase-access",
      NO_STR "Only use two phase access when requested my MS\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->force_two_phase = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_alpha,
      cfg_pcu_alpha_cmd,
      "alpha <0-10>",
      "Alpha parameter for MS power control in units of 0.1 (see TS 05.08) "
      "NOTE: Be sure to set Alpha value at System information 13 too.\n"
      "Alpha in units of 0.1\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->alpha = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_gamma,
      cfg_pcu_gamma_cmd,
      "gamma <0-62>",
      "Gamma parameter for MS power control in units of dB (see TS 05.08)\n"
      "Gamma in even unit of dBs\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->gamma = atoi(argv[0]) / 2;

	return CMD_SUCCESS;
}

DEFUN(show_bts_stats,
      show_bts_stats_cmd,
      "show bts statistics",
      SHOW_STR "BTS related functionality\nStatistics\n")
{
	vty_out_rate_ctr_group(vty, "", bts_main_data_stats());
	return CMD_SUCCESS;
}

#define IDLE_TIME_STR "keep an idle DL TBF alive for the time given\n"
DEFUN(cfg_pcu_dl_tbf_idle_time,
      cfg_pcu_dl_tbf_idle_time_cmd,
      "dl-tbf-idle-time <1-5000>",
      IDLE_TIME_STR "idle time in msec")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->dl_tbf_idle_msec = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_dl_tbf_idle_time,
      cfg_pcu_no_dl_tbf_idle_time_cmd,
      "no dl-tbf-idle-time",
      NO_STR IDLE_TIME_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->dl_tbf_idle_msec = 0;

	return CMD_SUCCESS;
}

#define MS_IDLE_TIME_STR "keep an idle MS object alive for the time given\n"
DEFUN(cfg_pcu_ms_idle_time,
      cfg_pcu_ms_idle_time_cmd,
      "ms-idle-time <1-7200>",
      MS_IDLE_TIME_STR "idle time in sec")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->ms_idle_sec = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_ms_idle_time,
      cfg_pcu_no_ms_idle_time_cmd,
      "no ms-idle-time",
      NO_STR MS_IDLE_TIME_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->ms_idle_sec = 0;

	return CMD_SUCCESS;
}

#define CS_ERR_LIMITS_STR "set thresholds for error rate based CS adjustment\n"
DEFUN(cfg_pcu_cs_err_limits,
      cfg_pcu_cs_err_limits_cmd,
      "cs threshold <0-100> <0-100>",
      CS_STR CS_ERR_LIMITS_STR "lower limit in %\n" "upper limit in %\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	uint8_t lower_limit = atoi(argv[0]);
	uint8_t upper_limit = atoi(argv[1]);

	if (lower_limit > upper_limit) {
		vty_out(vty,
			"The lower limit must be less than or equal to the "
			"upper limit.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->cs_adj_enabled = 1;
	bts->cs_adj_upper_limit = upper_limit;
	bts->cs_adj_lower_limit = lower_limit;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_cs_err_limits,
      cfg_pcu_no_cs_err_limits_cmd,
      "no cs threshold",
      NO_STR CS_STR CS_ERR_LIMITS_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->cs_adj_enabled = 0;
	bts->cs_adj_upper_limit = 100;
	bts->cs_adj_lower_limit = 0;

	return CMD_SUCCESS;
}

#define CS_DOWNGRADE_STR "set threshold for data size based CS downgrade\n"
DEFUN(cfg_pcu_cs_downgrade_thrsh,
      cfg_pcu_cs_downgrade_thrsh_cmd,
      "cs downgrade-threshold <1-10000>",
      CS_STR CS_DOWNGRADE_STR "downgrade if less octets left\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->cs_downgrade_threshold = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_cs_downgrade_thrsh,
      cfg_pcu_no_cs_downgrade_thrsh_cmd,
      "no cs downgrade-threshold",
      NO_STR CS_STR CS_DOWNGRADE_STR)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->cs_downgrade_threshold = 0;

	return CMD_SUCCESS;
}


DEFUN(cfg_pcu_cs_lqual_ranges,
      cfg_pcu_cs_lqual_ranges_cmd,
      "cs link-quality-ranges cs1 <0-35> cs2 <0-35> <0-35> cs3 <0-35> <0-35> cs4 <0-35>",
      CS_STR "Set link quality ranges\n"
      "Set quality range for CS-1 (high value only)\n"
      "CS-1 high (dB)\n"
      "Set quality range for CS-2\n"
      "CS-2 low (dB)\n"
      "CS-2 high (dB)\n"
      "Set quality range for CS-3\n"
      "CS-3 low (dB)\n"
      "CS-3 high (dB)\n"
      "Set quality range for CS-4 (low value only)\n"
      "CS-4 low (dB)\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	uint8_t cs1_high = atoi(argv[0]);
	uint8_t cs2_low = atoi(argv[1]);
	uint8_t cs2_high = atoi(argv[2]);
	uint8_t cs3_low = atoi(argv[3]);
	uint8_t cs3_high = atoi(argv[4]);
	uint8_t cs4_low = atoi(argv[5]);

	bts->cs_lqual_ranges[0].high = cs1_high;
	bts->cs_lqual_ranges[1].low  = cs2_low;
	bts->cs_lqual_ranges[1].high = cs2_high;
	bts->cs_lqual_ranges[2].low  = cs3_low;
	bts->cs_lqual_ranges[2].high = cs3_high;
	bts->cs_lqual_ranges[3].low  = cs4_low;

	return CMD_SUCCESS;
}


DEFUN(show_tbf,
      show_tbf_cmd,
      "show tbf all",
      SHOW_STR "information about TBFs\n" "All TBFs\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	return pcu_vty_show_tbf_all(vty, bts);
}

DEFUN(show_ms_all,
      show_ms_all_cmd,
      "show ms all",
      SHOW_STR "information about MSs\n" "All TBFs\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	return pcu_vty_show_ms_all(vty, bts);
}

DEFUN(show_ms_tlli,
      show_ms_tlli_cmd,
      "show ms tlli TLLI",
      SHOW_STR "information about MSs\n" "Select MS by TLLI\n" "TLLI as hex\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	char *endp = NULL;
	unsigned long long tlli = strtoll(argv[0], &endp, 16);
	if ((endp != NULL && *endp != 0) || tlli > 0xffffffffULL) {
		vty_out(vty, "Invalid TLLI.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return pcu_vty_show_ms_by_tlli(vty, bts, (uint32_t)tlli);
}

DEFUN(show_ms_imsi,
      show_ms_imsi_cmd,
      "show ms imsi IMSI",
      SHOW_STR "information about MSs\n" "Select MS by IMSI\n" "IMSI\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	return pcu_vty_show_ms_by_imsi(vty, bts, argv[0]);
}

static const char pcu_copyright[] =
	"Copyright (C) 2012 by Ivan Kluchnikov <kluchnikovi@gmail.com> and \r\n"
	"                      Andreas Eversberg <jolly@eversberg.eu>\r\n"
	"License GNU GPL version 2 or later\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

struct vty_app_info pcu_vty_info = {
	.name		= "Osmo-PCU",
	.version	= PACKAGE_VERSION,
	.copyright	= pcu_copyright,
	.go_parent_cb	= pcu_vty_go_parent,
	.is_config_node	= pcu_vty_is_config_node,
};

int pcu_vty_init(const struct log_info *cat)
{
//	install_element_ve(&show_pcu_cmd);

	logging_vty_add_cmds(cat);
	osmo_stats_vty_add_cmds(cat);

	install_node(&pcu_node, config_write_pcu);
	install_element(CONFIG_NODE, &cfg_pcu_cmd);
	vty_install_default(PCU_NODE);
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
	install_element(PCU_NODE, &cfg_pcu_ms_idle_time_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_ms_idle_time_cmd);

	install_element_ve(&show_bts_stats_cmd);
	install_element_ve(&show_tbf_cmd);
	install_element_ve(&show_ms_all_cmd);
	install_element_ve(&show_ms_tlli_cmd);
	install_element_ve(&show_ms_imsi_cmd);

	return 0;
}
