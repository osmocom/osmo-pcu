/*
 * LlcTest.cpp
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

extern "C" {
	#include <osmocom/core/linuxlist.h>
}

#include "gprs_debug.h"
#include "bts.h"

extern "C" {
#include "pcu_vty.h"
#include "gprs_pcu.h"
#include "llc.h"
#include "gprs_ms.h"

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/vty/vty.h>
}


void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;
static struct timespec *clk_mono_override_time;

static struct gprs_llc_queue *prepare_queue(void)
{
	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);
	the_pcu->vty.llc_codel_interval_msec = LLC_CODEL_DISABLE;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct GprsMs *ms = ms_alloc(bts, NULL);
	return ms_llc_queue(ms);
}

static void enqueue_data(gprs_llc_queue *queue, const uint8_t *data, size_t len,
			 const struct timespec *expire_time)
{
	struct timespec *tv;
	uint8_t *msg_data;
	struct msgb *llc_msg = msgb_alloc(len + sizeof(*tv) * 2,
		"llc_pdu_queue");

	msg_data = (uint8_t *)msgb_put(llc_msg, len);

	memcpy(msg_data, data, len);

	llc_queue_enqueue(queue, llc_msg, expire_time);
}

static void dequeue_and_check(gprs_llc_queue *queue, const uint8_t *exp_data,
	size_t len, const MetaInfo *exp_info)
{
	struct msgb *llc_msg;
	MetaInfo info_res;

	llc_msg = llc_queue_dequeue(queue, NULL, &info_res);
	OSMO_ASSERT(llc_msg != NULL);

	fprintf(stderr, "dequeued msg, length %u (expected %zu), data %s\n",
		msgb_length(llc_msg), len, msgb_hexdump(llc_msg));

	if (!msgb_eq_data_print(llc_msg, exp_data, len))
		fprintf(stderr, "check failed!\n");

	if (exp_info) {
		OSMO_ASSERT(memcmp(&exp_info->recv_time, &info_res.recv_time, sizeof(info_res.recv_time)) == 0);
		OSMO_ASSERT(memcmp(&exp_info->expire_time, &info_res.expire_time, sizeof(info_res.expire_time)) == 0);
	}
	msgb_free(llc_msg);
}

static void enqueue_data(gprs_llc_queue *queue, const char *message,
			 const struct timespec *expire_time)
{
	enqueue_data(queue, (uint8_t *)(message), strlen(message), expire_time);
}

static void dequeue_and_check(gprs_llc_queue *queue, const char *exp_message,
	const MetaInfo *exp_info = 0)
{
	dequeue_and_check(queue,
		(uint8_t *)(exp_message), strlen(exp_message), exp_info);
}

static void test_llc_queue()
{
	gprs_llc_queue *queue = prepare_queue();
	struct timespec expire_time = { };

	printf("=== start %s ===\n", __func__);

	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);

	enqueue_data(queue, "LLC message", &expire_time);
	OSMO_ASSERT(llc_queue_size(queue) == 1);
	OSMO_ASSERT(llc_queue_octets(queue) == 11);

	enqueue_data(queue, "other LLC message", &expire_time);
	OSMO_ASSERT(llc_queue_size(queue) == 2);
	OSMO_ASSERT(llc_queue_octets(queue) == 28);

	dequeue_and_check(queue, "LLC message");
	OSMO_ASSERT(llc_queue_size(queue) == 1);
	OSMO_ASSERT(llc_queue_octets(queue) == 17);

	dequeue_and_check(queue, "other LLC message");
	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);

	enqueue_data(queue, "LLC",  &expire_time);
	OSMO_ASSERT(llc_queue_size(queue) == 1);
	OSMO_ASSERT(llc_queue_octets(queue) == 3);

	llc_queue_clear(queue, NULL);
	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);

	printf("=== end %s ===\n", __func__);
	TALLOC_FREE(the_pcu);
}

static void test_llc_meta()
{
	gprs_llc_queue *queue = prepare_queue();
	MetaInfo info1 = { };
	MetaInfo info2 = { };

	printf("=== start %s ===\n", __func__);

	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);

	info1.recv_time.tv_sec = 123456777;
	info1.recv_time.tv_nsec = 123456000;
	info1.expire_time.tv_sec = 123456789;
	info1.expire_time.tv_nsec = 987654000;
	*clk_mono_override_time = info1.recv_time;
	enqueue_data(queue, "LLC message 1", &info1.expire_time);

	info2.recv_time.tv_sec = 123458000;
	info2.recv_time.tv_nsec = 547352000;
	info2.expire_time.tv_sec = 123458006;
	info2.expire_time.tv_nsec = 867252000;
	*clk_mono_override_time = info2.recv_time;
	enqueue_data(queue, "LLC message 2", &info2.expire_time);

	clk_mono_override_time->tv_sec = info1.expire_time.tv_sec - 1;
	clk_mono_override_time->tv_nsec = info1.expire_time.tv_nsec;

	dequeue_and_check(queue, "LLC message 1", &info1);
	dequeue_and_check(queue, "LLC message 2", &info2);

	llc_queue_clear(queue, NULL);
	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);

	printf("=== end %s ===\n", __func__);
	TALLOC_FREE(the_pcu);
}

/* Test PDU lifetime is taken into account and packet is dropped if dequeued too
 * late */
static void test_llc_meta_pdu_life_expire()
{
	gprs_llc_queue *queue = prepare_queue();
	MetaInfo info1 = { };
	MetaInfo info2 = { };

	printf("=== start %s ===\n", __func__);

	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);

	info1.recv_time.tv_sec = 123456777;
	info1.recv_time.tv_nsec = 123456000;
	info1.expire_time.tv_sec = 123456789;
	info1.expire_time.tv_nsec = 987654000;
	*clk_mono_override_time = info1.recv_time;
	enqueue_data(queue, "LLC message 1", &info1.expire_time);

	info2.recv_time.tv_sec = 123458000;
	info2.recv_time.tv_nsec = 547352000;
	info2.expire_time.tv_sec = 123458006;
	info2.expire_time.tv_nsec = 867252000;
	*clk_mono_override_time = info2.recv_time;
	enqueue_data(queue, "LLC message 2", &info2.expire_time);

	clk_mono_override_time->tv_sec = info1.expire_time.tv_sec + 1;
	clk_mono_override_time->tv_nsec = info1.expire_time.tv_nsec;

	dequeue_and_check(queue, "LLC message 2", &info2);

	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);
	llc_queue_clear(queue, NULL);

	printf("=== end %s ===\n", __func__);
	TALLOC_FREE(the_pcu);
}

/* Test codel entering in action */
static void test_llc_codel()
{
	clk_mono_override_time->tv_sec = 1000;
	clk_mono_override_time->tv_nsec = 0;

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);
	the_pcu->vty.llc_codel_interval_msec = LLC_CODEL_USE_DEFAULT;
	/* DEFAULT should be resolved to GPRS_CODEL_SLOW_INTERVAL_MS 4000 */
	#define GPRS_CODEL_SLOW_INTERVAL_MS 4000
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct GprsMs *ms = ms_alloc(bts, NULL);
	gprs_llc_queue *queue = ms_llc_queue(ms);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(queue->pq); i++) {
		gprs_codel_set_maxpacket(&queue->pq[i].codel_state, 8);
	}

	MetaInfo info1 = { };

	printf("=== start %s ===\n", __func__);

	for (i = 0; i < 10; i++) {
		char buf[256];

		snprintf(buf, sizeof(buf), "LLC message %u", i);
		info1.recv_time.tv_sec = clk_mono_override_time->tv_sec;
		info1.recv_time.tv_nsec = clk_mono_override_time->tv_nsec;
		info1.expire_time.tv_sec = clk_mono_override_time->tv_sec + 500;
		info1.expire_time.tv_nsec = clk_mono_override_time->tv_nsec;
		clk_mono_override_time->tv_sec += 1;
		enqueue_data(queue, buf, &info1.expire_time);
	}

	OSMO_ASSERT(llc_queue_size(queue) == 10);
	OSMO_ASSERT(llc_queue_octets(queue) != 0);

	dequeue_and_check(queue, "LLC message 0", NULL);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.first_above_time.tv_sec ==
				clk_mono_override_time->tv_sec + GPRS_CODEL_SLOW_INTERVAL_MS/1000);
	dequeue_and_check(queue, "LLC message 1", NULL);
	clk_mono_override_time->tv_sec += 7;
	dequeue_and_check(queue, "LLC message 2", NULL); /*recently == 0*/
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 0);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.count == 0);
	clk_mono_override_time->tv_sec += GPRS_CODEL_SLOW_INTERVAL_MS/1000 + 1;
	dequeue_and_check(queue, "LLC message 4", NULL); /* recently = 1, message 3 is dropped here */
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 1);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.count == 1);
	dequeue_and_check(queue, "LLC message 5", NULL);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 1);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.count == 1);
	dequeue_and_check(queue, "LLC message 6", NULL);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 1);
	dequeue_and_check(queue, "LLC message 7", NULL);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 1);
	dequeue_and_check(queue, "LLC message 8", NULL);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 1);
	dequeue_and_check(queue, "LLC message 9", NULL);
	OSMO_ASSERT(queue->pq[LLC_QUEUE_PRIO_OTHER].codel_state.dropping == 0);

	OSMO_ASSERT(llc_queue_size(queue) == 0);
	OSMO_ASSERT(llc_queue_octets(queue) == 0);
	llc_queue_clear(queue, NULL);

	printf("=== end %s ===\n", __func__);
	TALLOC_FREE(the_pcu);
}

static void test_llc_merge()
{
	gprs_llc_queue *queue1 = prepare_queue();
	struct GprsMs *ms = ms_alloc(queue1->ms->bts, NULL);
	gprs_llc_queue *queue2 = ms_llc_queue(ms);
	struct timespec expire_time = { };

	printf("=== start %s ===\n", __func__);

	clk_mono_override_time->tv_sec += 1;
	enqueue_data(queue1, "*A*", &expire_time);

	clk_mono_override_time->tv_sec += 1;
	enqueue_data(queue1, "*B*", &expire_time);

	clk_mono_override_time->tv_sec += 1;
	enqueue_data(queue2, "*C*", &expire_time);

	clk_mono_override_time->tv_sec += 1;
	enqueue_data(queue1, "*D*", &expire_time);

	clk_mono_override_time->tv_sec += 1;
	enqueue_data(queue2, "*E*", &expire_time);

	OSMO_ASSERT(llc_queue_size(queue1) == 3);
	OSMO_ASSERT(llc_queue_octets(queue1) == 9);
	OSMO_ASSERT(llc_queue_size(queue2) == 2);
	OSMO_ASSERT(llc_queue_octets(queue2) == 6);

	llc_queue_move_and_merge(queue2, queue1);

	OSMO_ASSERT(llc_queue_size(queue1) == 0);
	OSMO_ASSERT(llc_queue_octets(queue1) == 0);
	OSMO_ASSERT(llc_queue_size(queue2) == 5);
	OSMO_ASSERT(llc_queue_octets(queue2) == 15);

	dequeue_and_check(queue2, "*A*");
	dequeue_and_check(queue2, "*B*");
	dequeue_and_check(queue2, "*C*");
	dequeue_and_check(queue2, "*D*");
	dequeue_and_check(queue2, "*E*");

	OSMO_ASSERT(llc_queue_size(queue2) == 0);
	OSMO_ASSERT(llc_queue_octets(queue2) == 0);

	printf("=== end %s ===\n", __func__);
	TALLOC_FREE(the_pcu);
}

int main(int argc, char **argv)
{
	struct vty_app_info pcu_vty_info = { };

	tall_pcu_ctx = talloc_named_const(NULL, 1, "LlcTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
	log_parse_category_mask(osmo_stderr_target, "DPCU,3:DLGLOBAL,1:");

	vty_init(&pcu_vty_info);
	pcu_vty_init();

	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	clk_mono_override_time = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	clk_mono_override_time->tv_sec = 123456777;
	clk_mono_override_time->tv_nsec = 123456000;

	test_llc_queue();
	test_llc_meta();
	test_llc_meta_pdu_life_expire();
	test_llc_codel();
	test_llc_merge();

	if (getenv("TALLOC_REPORT_FULL"))
		talloc_report_full(tall_pcu_ctx, stderr);

	return EXIT_SUCCESS;
}

extern "C" {
void l1if_pdch_req() { abort(); }
void l1if_connect_pdch() { abort(); }
void l1if_disconnect_pdch() { abort(); }
void l1if_close_trx() { abort(); }
void l1if_open_trx() { abort(); }
}
