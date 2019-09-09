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

#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <gsm_timer.h>
#include <gprs_debug.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sched.h>
#include <bts.h>
#include <gprs_coding_scheme.h>
#include <osmocom/pcu/pcuif_proto.h>
#include "gprs_bssgp_pcu.h"

extern "C" {
#include "pcu_vty.h"
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/ports.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>
}

extern struct gprs_nsvc *nsvc;
uint16_t spoof_mcc = 0, spoof_mnc = 0;
bool spoof_mnc_3_digits = false;
static int config_given = 0;
static char *config_file = strdup("osmo-pcu.cfg");
extern struct vty_app_info pcu_vty_info;
void *tall_pcu_ctx = NULL;
extern void *bv_tall_ctx;
static int quit = 0;
static int rt_prio = -1;
static bool daemonize = false;
static const char *gsmtap_addr = "localhost"; // FIXME: use gengetopt's default value instead

static void print_help()
{
	printf( "Options:\n"
		"  -h	--help		This text\n"
		"  -c	--config-file 	Specify the filename of the config "
			"file\n"
		"  -m	--mcc MCC	Use given MCC instead of value "
			"provided by BTS\n"
		"  -n	--mnc MNC	Use given MNC instead of value "
			"provided by BTS\n"
		"  -V	--version	Print version\n"
		"  -r	--realtime PRIO Use SCHED_RR with the specified "
			"priority\n"
		"  -D	--daemonize	Fork the process into a background "
			"daemon\n"
		"  -i	--gsmtap-ip	The destination IP used for GSMTAP\n"
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
			{ "daemonize", 0, 0, 'D' },
			{ "exit", 0, 0, 'e' },
			{ "gsmtap-ip", 1, 0, 'i' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hc:m:n:Vr:De:i:",
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
			if (osmo_mnc_from_str(optarg, &spoof_mnc, &spoof_mnc_3_digits)) {
				fprintf(stderr, "Error decoding MNC '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'i':
			gsmtap_addr = optarg;
			break;
		case 'r':
			rt_prio = atoi(optarg);
			break;
		case 'D':
			daemonize = true;
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
	if (sigset == SIGPIPE)
		return;

	fprintf(stderr, "Signal %d received.\n", sigset);

	switch (sigset) {
	case SIGINT:
	case SIGTERM:
		/* If another signal is received afterwards, the program
		 * is terminated without finishing shutdown process.
		 */
		signal(SIGINT, SIG_DFL);
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

	/* tall_pcu_ctx may already have been initialized in bts.cpp during early_init(). */
	if (!tall_pcu_ctx) {
		tall_pcu_ctx = talloc_named_const(NULL, 1, "Osmo-PCU context");
		if (!tall_pcu_ctx)
			return -ENOMEM;
		osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	}

	bts = bts_main_data();
	bts->fc_interval = 1;
	bts->initial_cs_dl = bts->initial_cs_ul = 1;
	bts->initial_mcs_dl = bts->initial_mcs_ul = 1;
	bts->cs1 = 1;
	bts->n3101 = 10;
	bts->n3103 = 4;
	bts->n3105 = 8;
	bts->alpha = 0; /* a = 0.0 */
	bts->si13_is_set = false;
	bts->cs_adj_enabled = 1;
	bts->cs_adj_upper_limit = 33; /* Decrease CS if the error rate is above */
	bts->cs_adj_lower_limit = 10; /* Increase CS if the error rate is below */
	bts->max_cs_ul = MAX_GPRS_CS;
	bts->max_cs_dl = MAX_GPRS_CS;
	bts->max_mcs_ul = MAX_EDGE_MCS;
	bts->max_mcs_dl = MAX_EDGE_MCS;
	/* CS-1 to CS-4 */
	bts->cs_lqual_ranges[0].low = -256;
	bts->cs_lqual_ranges[0].high = 6;
	bts->cs_lqual_ranges[1].low = 5;
	bts->cs_lqual_ranges[1].high = 8;
	bts->cs_lqual_ranges[2].low = 7;
	bts->cs_lqual_ranges[2].high = 13;
	bts->cs_lqual_ranges[3].low = 12;
	bts->cs_lqual_ranges[3].high = 256;

	/* MCS-1 to MCS-9 */
	/* Default thresholds are referenced from literature */
	/* Fig. 2.3, Chapter 2, Optimizing Wireless Communication Systems, Springer (2009) */
	bts->mcs_lqual_ranges[0].low = -256;
	bts->mcs_lqual_ranges[0].high = 6;
	bts->mcs_lqual_ranges[1].low = 5;
	bts->mcs_lqual_ranges[1].high = 8;
	bts->mcs_lqual_ranges[2].low = 7;
	bts->mcs_lqual_ranges[2].high = 13;
	bts->mcs_lqual_ranges[3].low = 12;
	bts->mcs_lqual_ranges[3].high = 15;
	bts->mcs_lqual_ranges[4].low = 14;
	bts->mcs_lqual_ranges[4].high = 17;
	bts->mcs_lqual_ranges[5].low = 16;
	bts->mcs_lqual_ranges[5].high = 18;
	bts->mcs_lqual_ranges[6].low = 17;
	bts->mcs_lqual_ranges[6].high = 20;
	bts->mcs_lqual_ranges[7].low = 19;
	bts->mcs_lqual_ranges[7].high = 24;
	bts->mcs_lqual_ranges[8].low = 23;
	bts->mcs_lqual_ranges[8].high = 256;
	bts->cs_downgrade_threshold = 200;

	/* TODO: increase them when CRBB decoding is implemented */
	bts->ws_base = 64;
	bts->ws_pdch = 0;

	bts->llc_codel_interval_msec = LLC_CODEL_USE_DEFAULT;
	bts->dl_tbf_idle_msec = 2000;
	bts->llc_idle_ack_csec = 10;

	/*
	 * By default resegmentation is supported in DL
	 * can also be configured through VTY
	 */
	bts->dl_arq_type = EGPRS_ARQ1;

	bts->pcu_sock_path = talloc_strdup(tall_pcu_ctx, PCU_SOCK_DEFAULT);

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);

	osmo_stats_init(tall_pcu_ctx);
	rate_ctr_init(tall_pcu_ctx);
	gprs_ns_set_log_ss(DNS);
	bssgp_set_log_ss(DBSSGP);

	vty_init(&pcu_vty_info);
	pcu_vty_init();

	handle_options(argc, argv);
	if ((!!spoof_mcc) + (!!spoof_mnc) == 1) {
		fprintf(stderr, "--mcc and --mnc must be specified "
			"together.\n");
		exit(0);
	}

	bts->gsmtap = gsmtap_source_init(gsmtap_addr, GSMTAP_UDP_PORT, 1);

	if (bts->gsmtap)
		gsmtap_source_add_sink(bts->gsmtap);
	else
		fprintf(stderr, "Failed to initialize GSMTAP for %s\n", gsmtap_addr);

	bssgp_nsi = gprs_ns_instantiate(&gprs_bssgp_ns_cb, tall_pcu_ctx);
	if (!bssgp_nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		exit(1);
	}
	gprs_ns_vty_init(bssgp_nsi);

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0 && config_given) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n",
			config_file);
		exit(1);
	}
	if (rc < 0)
		fprintf(stderr, "No config file: '%s' Using default config.\n",
			config_file);

	rc = telnet_init_dynif(tall_pcu_ctx, NULL, vty_get_bind_addr(),
			       OSMO_VTY_PORT_PCU);
	if (rc < 0) {
		fprintf(stderr, "Error initializing telnet\n");
		exit(1);
	}

	if (!bts->alloc_algorithm)
		bts->alloc_algorithm = alloc_algorithm_dynamic;

	rc = pcu_l1if_open();

	if (rc < 0)
		return rc;

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	osmo_init_ignore_signals();

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

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
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

	bts_cleanup();
	talloc_report_full(tall_pcu_ctx, stderr);
	talloc_free(tall_pcu_ctx);

	return 0;
}
