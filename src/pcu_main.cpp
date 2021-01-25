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
#include <osmocom/pcu/pcuif_proto.h>
#include "gprs_bssgp_pcu.h"

extern "C" {
#include "pcu_vty.h"
#include "coding_scheme.h"
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/cpu_sched_vty.h>
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
	printf( "Some useful options:\n"
		"  -h	--help			This text\n"
		"  -c	--config-file		Specify the filename of the config file\n"
		"  -m	--mcc MCC		Use given MCC instead of value provided by BTS\n"
		"  -n	--mnc MNC		Use given MNC instead of value provided by BTS\n"
		"  -V	--version		Print version\n"
		"  -r	--realtime PRIO		Use SCHED_RR with the specified priority\n"
		"  -D	--daemonize		Fork the process into a background daemon\n"
		"  -i	--gsmtap-ip		The destination IP used for GSMTAP\n"
		"\nVTY reference generation:\n"
		"    	--vty-ref-mode MODE	VTY reference generation mode (e.g. 'expert').\n"
		"    	--vty-ref-xml		Generate the VTY reference XML output and exit.\n"
		);
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

/* FIXME: finally get some option parsing code into libosmocore */
static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_idx = 0, c;
		static int long_option = 0;
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
			{ "vty-ref-mode", 1, &long_option, 1 },
			{ "vty-ref-xml", 0, &long_option, 2 },
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
		case 0:
			handle_long_options(argv[0], long_option);
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
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report_full(tall_pcu_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(tall_pcu_ctx, stderr);
		break;
	}
}

int main(int argc, char *argv[])
{
	struct sched_param param;
	struct gprs_pcu *pcu;
	int rc;

	/* tall_pcu_ctx may already have been initialized in bts.cpp during early_init(). */
	if (!tall_pcu_ctx) {
		tall_pcu_ctx = talloc_named_const(NULL, 1, "Osmo-PCU context");
		if (!tall_pcu_ctx)
			return -ENOMEM;
		osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	}

	pcu = gprs_pcu_alloc(tall_pcu_ctx);
	the_pcu = pcu; /* globally avaialable object */

	pcu->pcu_sock_path = talloc_strdup(tall_pcu_ctx, PCU_SOCK_DEFAULT);

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);

	osmo_stats_init(tall_pcu_ctx);
	rate_ctr_init(tall_pcu_ctx);

	pcu_vty_info.tall_ctx = tall_pcu_ctx;
	vty_init(&pcu_vty_info);
	pcu_vty_init();
	osmo_cpu_sched_vty_init(tall_pcu_ctx);
	logging_vty_add_deprecated_subsys(tall_pcu_ctx, "bssgp");

	handle_options(argc, argv);
	if ((!!spoof_mcc) + (!!spoof_mnc) == 1) {
		fprintf(stderr, "--mcc and --mnc must be specified "
			"together.\n");
		exit(0);
	}

	pcu->gsmtap = gsmtap_source_init(gsmtap_addr, GSMTAP_UDP_PORT, 1);

	if (pcu->gsmtap)
		gsmtap_source_add_sink(pcu->gsmtap);
	else
		fprintf(stderr, "Failed to initialize GSMTAP for %s\n", gsmtap_addr);

	pcu->nsi = gprs_ns2_instantiate(tall_pcu_ctx, gprs_ns_prim_cb, NULL);
	if (!pcu->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		exit(1);
	}
	bssgp_set_bssgp_callback(gprs_gp_send_cb, pcu->nsi);
	gprs_ns2_vty_init(pcu->nsi);

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

	if (!pcu->alloc_algorithm)
		pcu->alloc_algorithm = alloc_algorithm_dynamic;

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
		osmo_select_main(0);
	}

	telnet_exit();

	pcu_l1if_close();

	TALLOC_FREE(the_pcu);
	talloc_report_full(tall_pcu_ctx, stderr);
	talloc_free(tall_pcu_ctx);

	return 0;
}
