/* OsmoBTS VTY interface */


#include <stdint.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/linuxlist.h>
#include "pcu_vty.h"
#include "gprs_rlcmac.h"

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
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

	vty_out(vty, "pcu%s", VTY_NEWLINE);
	if (bts->force_cs)
		vty_out(vty, " cs %d%s", bts->initial_cs, VTY_NEWLINE);
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

DEFUN(cfg_pcu_cs,
      cfg_pcu_cs_cmd,
      "cs <1-4>",
      "Set the Coding Scheme to be used, (overrides BTS config)\n")
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	uint8_t cs = atoi(argv[0]);

	bts->force_cs = 1;
	bts->initial_cs = cs;

	return CMD_SUCCESS;
}

DEFUN(cfg_pcu_no_cs,
      cfg_pcu_no_cs_cmd,
      "no cs",
      NO_STR "Don't force given Coding Scheme, (use BTS config)\n")
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

	bts->force_cs = 0;

	return CMD_SUCCESS;
}

static const char pcu_copyright[] =
	"Copyright (C) 2012 by ...\r\n"
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
	install_element(PCU_NODE, &cfg_pcu_cs_cmd);
	install_element(PCU_NODE, &cfg_pcu_no_cs_cmd);
	install_element(PCU_NODE, &ournode_end_cmd);

	return 0;
}
