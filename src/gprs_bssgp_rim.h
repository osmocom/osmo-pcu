#pragma once

#include <osmocom/gprs/gprs_bssgp.h>

int sgsn_rim_rx(struct osmo_bssgp_prim *bp, struct msgb *msg, struct gprs_rlcmac_bts *bts);
