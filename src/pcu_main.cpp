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
extern struct gprs_nsvc *nsvc;
uint16_t spoof_mcc = 0, spoof_mnc = 0;

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

int main(int argc, char *argv[])
{
	struct gprs_rlcmac_bts *bts;
	int rc;

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

	rc = pcu_l1if_open();
	if (rc < 0)
		return rc;

	while (1) 
	{
		osmo_gsm_timers_check();
		osmo_gsm_timers_prepare();
		osmo_gsm_timers_update();

		osmo_select_main(0);
	}

	pcu_l1if_close();
	talloc_free(gprs_rlcmac_bts);

	return 0;
}

