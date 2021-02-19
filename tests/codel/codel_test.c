/* Test routines for the CoDel implementation
 *
 * (C) 2015 by sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
 */

#undef _GNU_SOURCE
#define _GNU_SOURCE

#if 0
#include <osmocom/core/talloc.h>
#include <osmocom/core/prim.h>
#endif
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/logging.h>

#include "gprs_codel.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int do_codel_control(struct gprs_codel *state, const struct timespec *recv,
	struct timespec *now, const struct timespec *delta_now, int count)
{
	int drop;

	drop = gprs_codel_control(state, recv, now, -1);
	if (drop) {
		printf("Dropping packet %d, "
			"recv = %d.%03d, now = %d.%03d, "
			"codel.count = %d\n",
			count,
			(int)recv->tv_sec, (int)recv->tv_nsec/1000000,
			(int)now->tv_sec, (int)now->tv_nsec/1000000,
			state->count);
	} else {
		timespecadd(now, delta_now, now);
	}

	return drop == 0 ? 0 : 1;
}

static void test_codel(void)
{
	struct gprs_codel codel;
	struct timespec now;
	struct timespec recv;
	const struct timespec delta_now = {0, 10000000};
	const struct timespec init_delta_recv = {0, 5000000};
	struct timespec delta_recv;
	unsigned count;
	unsigned sum = 0;
	unsigned dropped = 0;
	int drop;

	printf("----- %s START\n", __func__);
	gprs_codel_init(&codel);
	gprs_codel_set_interval(&codel, 100);

	timespecclear(&now);
	timespecclear(&recv);
	delta_recv = init_delta_recv;

	for (count = 0; count < 20; count++, sum++) {
		drop = do_codel_control(&codel, &recv, &now, &delta_now, sum);
		timespecadd(&recv, &delta_recv, &recv);
		dropped += drop;
	}

	printf("Dropped %d packets\n", dropped);
	OSMO_ASSERT(dropped == 0);
	OSMO_ASSERT(!codel.dropping);

	for (count = 0; count < 20; count++, sum++) {
		drop = do_codel_control(&codel, &recv, &now, &delta_now, sum);
		timespecadd(&recv, &delta_recv, &recv);
		dropped += drop;
	}

	OSMO_ASSERT(dropped == 2);
	OSMO_ASSERT(codel.dropping);

	/* slow down recv rate */
	delta_recv.tv_nsec = delta_now.tv_nsec;

	for (count = 0; count < 75; count++, sum++) {
		drop = do_codel_control(&codel, &recv, &now, &delta_now, sum);
		timespecadd(&recv, &delta_recv, &recv);
		dropped += drop;
	}

	OSMO_ASSERT(dropped == 20);
	OSMO_ASSERT(codel.dropping);

	for (count = 0; count < 50; count++, sum++) {
		drop = do_codel_control(&codel, &recv, &now, &delta_now, sum);
		timespecadd(&recv, &delta_recv, &recv);
		dropped += drop;
	}

	OSMO_ASSERT(dropped == 20);
	OSMO_ASSERT(!codel.dropping);
	OSMO_ASSERT(codel.count >= 20);

	/* go back to old data rate */
	delta_recv = init_delta_recv;

	for (count = 0; count < 20; count++, sum++) {
		drop = do_codel_control(&codel, &recv, &now, &delta_now, sum);
		timespecadd(&recv, &delta_recv, &recv);
		dropped += drop;
	}

	OSMO_ASSERT(dropped == 20);
	OSMO_ASSERT(!codel.dropping);

	for (count = 0; count < 20; count++, sum++) {
		drop = do_codel_control(&codel, &recv, &now, &delta_now, sum);
		timespecadd(&recv, &delta_recv, &recv);
		dropped += drop;
	}

	OSMO_ASSERT(dropped == 22);
	OSMO_ASSERT(codel.count >= 2);

	printf("Dropped %d packets\n", dropped);

	printf("----- %s END\n", __func__);
}

static struct log_info info = {};

int main(int argc, char **argv)
{
	osmo_init_logging2(NULL, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	printf("===== CoDel test START\n");
	test_codel();
	printf("===== CoDel test END\n\n");

	exit(EXIT_SUCCESS);
}
