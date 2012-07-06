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
#include <arpa/inet.h>
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <gsm_timer.h>
#include <gprs_debug.h>
#include <unistd.h>
#include <getopt.h>

struct gprs_rlcmac_bts *gprs_rlcmac_bts;
uint16_t spoof_mcc = 0, spoof_mnc = 0;

// TODO: We should move this parameters to config file.
#define SGSN_IP "127.0.0.1"
#define SGSN_PORT 23000
#define NSVCI 4

static void print_help()
{
	printf( "Some useful options:\n"
		"  -h	--help		this text\n"
		"  -m	--mcc MCC	use given MCC instead of value "
			"provided by BTS\n"
		"  -n	--mnc MNC	use given MNC instead of value "
			"provided by BTS\n"
		);
}

/* FIXME: finally get some option parsing code into libosmocore */
static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_idx = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "mcc", 0, 0, 'm' },
			{ "mnc", 0, 0, 'n' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hm:n:",
				long_options, &option_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'm':
			spoof_mcc = atoi(optarg);
			break;
		case 'n':
			spoof_mnc = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Unknown option '%c'\n", c);
			exit(0);
			break;
		}
	}
}

int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc, struct msgb *msg, uint16_t bvci)
{
	int rc = 0;
	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = gprs_bssgp_pcu_rcvmsg(msg);
		break;
	default:
		LOGP(DPCU, LOGL_ERROR, "RLCMAC: Unknown event %u from NS\n", event);
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
	struct gprs_rlcmac_bts *bts;

	bts = gprs_rlcmac_bts = talloc_zero(NULL, struct gprs_rlcmac_bts);
	if (!gprs_rlcmac_bts)
		return -ENOMEM;
	gprs_rlcmac_bts->initial_cs = 1;
	bts->initial_cs = 1;
	bts->cs1 = 1;
	bts->t3142 = 20;
	bts->t3169 = 5;
	bts->t3191 = 5;
	bts->t3193_msec = 100;
	bts->t3195 = 5;
	bts->n3101 = 10;
	bts->n3103 = 4;
	bts->n3105 = 8;

	osmo_init_logging(&gprs_log_info);

	handle_options(argc, argv);
	if ((!!spoof_mcc) + (!!spoof_mnc) == 1) {
		fprintf(stderr, "--mcc and --mnc must be specified "
			"together.\n");
		exit(0);
	}

	pcu_l1if_open();

	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb, NULL);
	bssgp_nsi = sgsn_nsi;

	if (!bssgp_nsi)
	{
		LOGP(DPCU, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	bctx = btsctx_alloc(BVCI, NSEI);
	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = spoof_mcc ? : MNC;
	bctx->ra_id.mcc = spoof_mnc ? : MCC;
	bctx->ra_id.lac = PCU_LAC;
	bctx->ra_id.rac = PCU_RAC;
	bctx->bvci = BVCI;
	uint8_t cause = 39;
	gprs_ns_nsip_listen(sgsn_nsi);

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(SGSN_PORT);
	inet_aton(SGSN_IP, &dest.sin_addr);

	nsvc = gprs_ns_nsip_connect(sgsn_nsi, &dest, NSEI, nsvci);
	unsigned i = 0;
	while (1) 
	{
		osmo_gsm_timers_check();
		osmo_gsm_timers_prepare();
		osmo_gsm_timers_update();

		osmo_select_main(0);
		if (i == 7)
		{
			bssgp_tx_bvc_reset(bctx, BVCI, cause);
		}
		i++;
	}

	talloc_free(gprs_rlcmac_bts);
}

