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
#include <signal.h>
#include <sched.h>
#include <bts.h>
extern "C" {
#include "pcu_vty.h"
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
}

extern struct gprs_nsvc *nsvc;
uint16_t spoof_mcc = 0;
gsm_mnc_t spoof_mnc = { 0, false };
static int config_given = 0;
static char *config_file = strdup("osmo-pcu.cfg");
extern struct vty_app_info pcu_vty_info;
void *tall_pcu_ctx;
extern void *bv_tall_ctx;
static int quit = 0;
static int rt_prio = -1;

static void print_help()
{
	printf( "Some useful options:\n"
		"  -h	--help		this text\n"
		"  -c	--config-file 	Specify the filename of the config "
			"file\n"
		"  -m	--mcc MCC	use given MCC instead of value "
			"provided by BTS\n"
		"  -n	--mnc MNC	use given MNC instead of value "
			"provided by BTS\n"
		"  -r   --realtime PRIO Use SCHED_RR with the specified "
			"priority\n"
		);
}

/* FIXME: finally get some option parsing code into libosmocore */
static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_idx = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "config-file", 1, 0, 'c' },
			{ "mcc", 1, 0, 'm' },
			{ "mnc", 1, 0, 'n' },
			{ "version", 0, 0, 'V' },
			{ "realtime", 1, 0, 'r' },
			{ "exit", 0, 0, 'e' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hc:m:n:Vr:e",
				long_options, &option_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'c':
			free(config_file);
			config_file = strdup(optarg);
			config_given = 1;
			break;
		case 'm':
			spoof_mcc = atoi(optarg);
			break;
		case 'n':
			spoof_mnc = gsm48_str_to_mnc(optarg);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'r':
			rt_prio = atoi(optarg);
			break;
		case 'e':
			fprintf(stderr, "Warning: Option '-e' is deprecated!\n");
			break;
		default:
			fprintf(stderr, "Unknown option '%c'\n", c);
			exit(0);
			break;
		}
	}
}

void sighandler(int sigset)
{
	if (sigset == SIGHUP || sigset == SIGPIPE)
		return;

	fprintf(stderr, "Signal %d received.\n", sigset);

	switch (sigset) {
	case SIGINT:
	case SIGTERM:
		/* If another signal is received afterwards, the program
		 * is terminated without finishing shutdown process.
		 */
		signal(SIGINT, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		signal(SIGABRT, SIG_DFL);
		signal(SIGUSR1, SIG_DFL);
		signal(SIGUSR2, SIG_DFL);

		quit = 1;
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process
		 */
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(tall_pcu_ctx, stderr);
		break;
	}
}

int main(int argc, char *argv[])
{
	struct sched_param param;
	struct gprs_rlcmac_bts *bts;
	int rc;

	tall_pcu_ctx = talloc_named_const(NULL, 1, "Osmo-PCU context");
	if (!tall_pcu_ctx)
		return -ENOMEM;
	bv_tall_ctx = tall_pcu_ctx;

	bts = bts_main_data();
	bts->fc_interval = 1;
	bts->initial_cs_dl = bts->initial_cs_ul = 1;
	bts->cs1 = 1;
	bts->t3142 = 20;
	bts->t3169 = 5;
	bts->t3191 = 5;
	bts->t3193_msec = 100;
	bts->t3195 = 5;
	bts->n3101 = 10;
	bts->n3103 = 4;
	bts->n3105 = 8;
	bts->alpha = 0; /* a = 0.0 */

	msgb_set_talloc_ctx(tall_pcu_ctx);

	osmo_init_logging(&gprs_log_info);

	vty_init(&pcu_vty_info);
	pcu_vty_init(&gprs_log_info);

	handle_options(argc, argv);
	if ((!!spoof_mcc) + (!!spoof_mnc.network_code) == 1) {
		fprintf(stderr, "--mcc and --mnc must be specified "
			"together.\n");
		exit(0);
	}

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0 && config_given) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n",
			config_file);
		exit(1);
	}
	if (rc < 0)
		fprintf(stderr, "No config file: '%s' Using default config.\n",
			config_file);

	rc = telnet_init(tall_pcu_ctx, NULL, 4240);
	if (rc < 0) {
		fprintf(stderr, "Error initializing telnet\n");
		exit(1);
	}

	if (!bts->alloc_algorithm)
		bts->alloc_algorithm = alloc_algorithm_b;

	rc = pcu_l1if_open();

	if (rc < 0)
		return rc;

	signal(SIGINT, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);

	/* enable realtime priority for us */
	if (rt_prio != -1) {
		memset(&param, 0, sizeof(param));
		param.sched_priority = rt_prio;
		rc = sched_setscheduler(getpid(), SCHED_RR, &param);
		if (rc != 0) {
			fprintf(stderr, "Setting SCHED_RR priority(%d) failed: %s\n",
			param.sched_priority, strerror(errno));
			exit(1);
		}
	}

	while (!quit) {
		osmo_gsm_timers_check();
		osmo_gsm_timers_prepare();
		osmo_gsm_timers_update();

		osmo_select_main(0);
	}

	telnet_exit();

	pcu_l1if_close();

	bts->bts->timing_advance()->flush();

	talloc_report_full(tall_pcu_ctx, stderr);
	talloc_free(tall_pcu_ctx);

	return 0;
}
