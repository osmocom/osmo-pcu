#ifndef _PCU_VTY_H

#define _PCU_VTY_H

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

enum pcu_vty_node {
	PCU_NODE = _LAST_OSMOVTY_NODE + 1,
};

int pcu_vty_go_parent(struct vty *vty);
int pcu_vty_is_config_node(struct vty *vty, int node);

int pcu_vty_init();

extern struct vty_app_info pcu_vty_info;

#endif /* _PCU_VTY_H */

