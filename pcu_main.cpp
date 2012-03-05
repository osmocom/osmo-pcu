/* pcu_main.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <gprs_bssgp_pcu.h>
#include <Threads.h>
#include <Sockets.h>
#include <pcu_l1_if.h>

// TODO: We should move this parameters to config file.
#define SGSN_IP "127.0.0.1"
#define SGSN_PORT 23000
#define NSVCI 4


int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc, struct msgb *msg, uint16_t bvci)
{
	int rc = 0;
	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = gprs_bssgp_pcu_rcvmsg(msg);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "RLCMAC: Unknown event %u from NS\n", event);
		if (msg)
			talloc_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}

int main(int argc, char *argv[])
{
	uint16_t nsvci = NSVCI;
	struct gprs_ns_inst *sgsn_nsi;
	struct gprs_nsvc *nsvc;
	// Socket for reading BitVectors (RLC/MAC Frames) from OpenBTS application.
	Thread pcu_l1if;
	pcu_l1if.start(pcu_l1if_rx, NULL);

	osmo_init_logging(&log_info);
	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb);
	bssgp_nsi = sgsn_nsi;

	if (!bssgp_nsi)
	{
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	bctx = btsctx_alloc(BVCI, NSEI);
	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = MNC;
	bctx->ra_id.mcc = MCC;
	bctx->ra_id.lac = PCU_LAC;
	bctx->ra_id.rac = PCU_RAC;
	bctx->bvci = BVCI;
	uint8_t cause = 39;
	gprs_ns_nsip_listen(sgsn_nsi);

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(SGSN_PORT);
	inet_aton(SGSN_IP, &dest.sin_addr);

	nsvc = nsip_connect(sgsn_nsi, &dest, NSEI, nsvci);
	unsigned i = 0;
	while (1) 
	{
		osmo_select_main(0);
		if (i == 7)
		{
			bssgp_tx_bvc_reset(bctx, BVCI, cause);
		}
		i++;
	}
}
