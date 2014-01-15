/* OsmoBTS VTY interface */


#include <stdint.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/linuxlist.h>
#include "pcu_vty.h"
#include "gprs_rlcmac.h"
#include "bts.h"

enum node_type pcu_vty_go_parent(struct vty *vty)
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
	"%s(pcu)#",
	1,
};

gDEFUN(ournode_exit, ournode_exit_cmd, "exit",
	"Exit current node, go down to provious node")
{
	switch (vty->node) {
#if 0
	case TRXV_NODE:
		vty->node = PCU_NODE;
		{
			struct gsm_bts_trx *trx = vty->index;
			vty->index = trx->bts;
		}
		break;
#endif
	default:
		break;
	}
	return CMD_SUCCESS;
}

gDEFUN(ournode_end, ournode_end_cmd, "end",
	"End current mode and change to enable mode")
{
	switch (vty->node) {
	default:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	}
	return CMD_SUCCESS;
}

static int config_write_pcu(struct vty *vty)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	vty_out(vty, "pcu%s", VTY_NEWLINE);
	vty_out(vty, " flow-control-interval %d%s", bts->fc_interval,
		VTY_NEWLINE);
	if (bts->force_cs)
		if (bts->initial_cs_ul == bts->initial_cs_dl)
			vty_out(vty, " cs %d%s", bts->initial_cs_dl,
				VTY_NEWLINE);
		else
			vty_out(vty, " cs %d %d%s", bts->initial_cs_dl,
				bts->initial_cs_ul, VTY_NEWLINE);
	if (bts->force_llc_lifetime == 0xffff)
		vty_out(vty, " queue lifetime infinite%s", VTY_NEWLINE);
	else if (bts->force_llc_lifetime)
		vty_out(vty, " queue lifetime %d%s", bts->force_llc_lifetime,
			VTY_NEWLINE);
	if (bts->alloc_algorithm == alloc_algorithm_a)
		vty_out(vty, " alloc-algorithm a%s", VTY_NEWLINE);
	if (bts->alloc_algorithm == alloc_algorithm_b)
		vty_out(vty, " alloc-algorithm b%s", VTY_NEWLINE);
	if (bts->force_two_phase)
		vty_out(vty, " two-phase-access%s", VTY_NEWLINE);
	vty_out(vty, " alpha %d%s", bts->alpha, VTY_NEWLINE);
	vty_out(vty, " gamma %d%s", bts->gamma * 2, VTY_NEWLINE);

	return CMD_SUCCESS;
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

DEFUN(cfg_pcu_cs,
      cfg_pcu_cs_cmd,
      "cs <1-4> [<1-4>]",
      "Set the Coding Scheme to be used, (overrides BTS config)\n"
      "Initial CS used\nAlternative uplink CS")
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
      NO_STR "Don't force given Coding Scheme, (use BTS config)\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	bts->force_cs = 0;

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
	uint8_t csec = atoi(argv[0]);

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

DEFUN(cfg_pcu_alloc,
      cfg_pcu_alloc_cmd,
      "alloc-algorithm (a|b)",
      "Select slot allocation algorithm to use when assigning timeslots on "
      "PACCH\nSingle slot is assigned only\nMultiple slots are assigned for "
      "semi-duplex operation")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	switch (argv[0][0]) {
	case 'a':
		bts->alloc_algorithm = alloc_algorithm_a;
		break;
	case 'b':
		bts->alloc_algorithm = alloc_algorithm_b;
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

DEFUN(show_tbf,
      show_tbf_cmd,
      "show tbf all",
      SHOW_STR "information about all current TBFs\n")
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	struct llist_head *tbf;

	vty_out(vty, "UL TBFs%s", VTY_NEWLINE);
	llist_for_each(tbf, &bts->ul_tbfs) {
		tbf_print_vty_info(vty, tbf);
	}

	vty_out(vty, "%sDL TBFs%s", VTY_NEWLINE, VTY_NEWLINE);
	llist_for_each(tbf, &bts->dl_tbfs) {
		tbf_print_vty_info(vty, tbf);
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

	install_node(&pcu_node, config_write_pcu);
	install_element(CONFIG_NODE, &cfg_pcu_cmd);
	install_default(PCU_NODE);
	install_element(PCU_NODE, &cfg_pcu_no_two_phase_cmd);
	install_element(PCU_NODE, &cfg_pcu_cs_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_cs_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_lifetime_cmd);
	install_element(PCU_NODE, &cfg_pcu_queue_lifetime_inf_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_queue_lifetime_cmd);
	install_element(PCU_NODE, &cfg_pcu_alloc_cmd);
	install_element(PCU_NODE, &cfg_pcu_two_phase_cmd);
	install_element(PCU_NODE, &cfg_pcu_fc_interval_cmd);
	install_element(PCU_NODE, &cfg_pcu_alpha_cmd);
	install_element(PCU_NODE, &cfg_pcu_gamma_cmd);
	install_element(PCU_NODE, &ournode_end_cmd);

	install_element_ve(&show_bts_stats_cmd);
	install_element_ve(&show_tbf_cmd);

	return 0;
}
