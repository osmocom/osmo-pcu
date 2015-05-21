/*
 * TbfTest.cpp
 *
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include "bts.h"
#include "tbf.h"
#include "gprs_debug.h"
#include "pcu_utils.h"
#include "gprs_bssgp_pcu.h"

extern "C" {
#include "pcu_vty.h"

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vty.h>
}

#include <errno.h>

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;

static void check_tbf(gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf);
	OSMO_ASSERT(tbf->m_new_tbf == NULL || tbf->m_new_tbf->m_old_tbf == tbf);
	OSMO_ASSERT(tbf->m_old_tbf == NULL || tbf->m_old_tbf->m_new_tbf == tbf);
}

static void test_tbf_tlli_update()
{
	BTS the_bts;
	GprsMs *ms, *ms_new;

	the_bts.bts_data()->alloc_algorithm = alloc_algorithm_a;
	the_bts.bts_data()->trx[0].pdch[2].enable();
	the_bts.bts_data()->trx[0].pdch[3].enable();

	/*
	 * Make a uplink and downlink allocation
	 */
	gprs_rlcmac_tbf *dl_tbf = tbf_alloc_dl_tbf(the_bts.bts_data(),
						NULL, 0,
						0, 0, 0);
	dl_tbf->update_tlli(0x2342);
	dl_tbf->update_ms(0x2342, GPRS_RLCMAC_DL_TBF);
	dl_tbf->ta = 4;
	the_bts.timing_advance()->remember(0x2342, dl_tbf->ta);

	gprs_rlcmac_tbf *ul_tbf = tbf_alloc_ul_tbf(the_bts.bts_data(),
						dl_tbf, 0,
						0, 0, 0);
	ul_tbf->update_tlli(0x2342);
	ul_tbf->update_ms(0x2342, GPRS_RLCMAC_UL_TBF);

	ms = the_bts.ms_by_tlli(0x2342);

	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->dl_tbf() == dl_tbf);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	/*
	 * Now check.. that DL changes and that the timing advance
	 * has changed.
	 */
	dl_tbf->update_tlli(0x4232);
	dl_tbf->update_ms(0x4232, GPRS_RLCMAC_DL_TBF);

	/* It is still there, since the new TLLI has not been used for UL yet */
	ms_new = the_bts.ms_by_tlli(0x2342);
	OSMO_ASSERT(ms == ms_new);

	ms_new = the_bts.ms_by_tlli(0x4232);
	OSMO_ASSERT(ms == ms_new);
	OSMO_ASSERT(ms->dl_tbf() == dl_tbf);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	/* Now use the new TLLI for UL */
	ul_tbf->update_ms(0x4232, GPRS_RLCMAC_UL_TBF);
	ms_new = the_bts.ms_by_tlli(0x2342);
	OSMO_ASSERT(ms_new == NULL);

	OSMO_ASSERT(the_bts.timing_advance()->recall(0x4232) == 4);
}

static uint8_t llc_data[200];

int pcu_sock_send(struct msgb *msg)
{
	return 0;
}

static void setup_bts(BTS *the_bts, uint8_t ts_no)
{
	gprs_rlcmac_bts *bts;
	gprs_rlcmac_trx *trx;

	bts = the_bts->bts_data();
	bts->alloc_algorithm = alloc_algorithm_a;
	trx = &bts->trx[0];

	trx->pdch[ts_no].enable();
}

static gprs_rlcmac_dl_tbf *create_dl_tbf(BTS *the_bts, uint8_t ms_class,
	uint8_t *trx_no_)
{
	gprs_rlcmac_bts *bts;
	int tfi;
	uint8_t trx_no;

	gprs_rlcmac_dl_tbf *dl_tbf;

	bts = the_bts->bts_data();

	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_DL_TBF, &trx_no, -1);
	OSMO_ASSERT(tfi >= 0);
	dl_tbf = tbf_alloc_dl_tbf(bts, NULL, tfi, trx_no, ms_class, 1);
	check_tbf(dl_tbf);

	/* "Establish" the DL TBF */
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_SEND_ASS;
	dl_tbf->set_state(GPRS_RLCMAC_FLOW);
	dl_tbf->m_wait_confirm = 0;
	dl_tbf->set_new_tbf(dl_tbf);
	check_tbf(dl_tbf);

	*trx_no_ = trx_no;

	return dl_tbf;
}

static void send_rlc_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx_no, uint8_t ts_no, uint16_t arfcn,
	uint32_t *fn, uint8_t *block_nr)
{
	gprs_rlcmac_rcv_rts_block(bts, trx_no, ts_no, 0, *fn, *block_nr);
	*fn += 4;
	if ((*fn % 13) == 12)
		*fn += 1;
	*block_nr += 1;
}

enum test_tbf_final_ack_mode {
	TEST_MODE_STANDARD,
	TEST_MODE_REVERSE_FREE
};

static void test_tbf_final_ack(enum test_tbf_final_ack_mode test_mode)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	unsigned i;
	uint8_t ms_class = 45;
	uint32_t fn;
	uint8_t block_nr;
	uint8_t trx_no;

	uint8_t rbb[64/8];

	gprs_rlcmac_dl_tbf *dl_tbf;
	gprs_rlcmac_tbf *new_tbf;

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	dl_tbf = create_dl_tbf(&the_bts, ms_class, &trx_no);

	for (i = 0; i < sizeof(llc_data); i++)
		llc_data[i] = i%256;

	/* Schedule two LLC frames */
	dl_tbf->append_data(ms_class, 1000, llc_data, sizeof(llc_data));
	dl_tbf->append_data(ms_class, 1000, llc_data, sizeof(llc_data));


	/* Send only a few RLC/MAC blocks */
	fn = 0;
	block_nr = 0;
	while (block_nr < 3) {
		/* Request to send one block */
		send_rlc_block(bts, trx_no, ts_no, 0, &fn, &block_nr);
	}
	OSMO_ASSERT(dl_tbf->have_data());
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Queue a final ACK */
	memset(rbb, 0, sizeof(rbb));
	/* Receive a final ACK */
	dl_tbf->rcvd_dl_ack(1, 1, rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	new_tbf = dl_tbf->new_tbf();
	check_tbf(new_tbf);
	OSMO_ASSERT(new_tbf != dl_tbf);
	OSMO_ASSERT(new_tbf->tfi() == 1);
	check_tbf(dl_tbf);
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
	if (test_mode == TEST_MODE_REVERSE_FREE) {
		tbf_free(new_tbf);
		OSMO_ASSERT(dl_tbf->m_new_tbf != new_tbf);
		check_tbf(dl_tbf);
		tbf_free(dl_tbf);
	} else {
		tbf_free(dl_tbf);
		OSMO_ASSERT(new_tbf->m_new_tbf != dl_tbf);
		check_tbf(new_tbf);
		tbf_free(new_tbf);
	}
}

static void test_tbf_delayed_release()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	unsigned i;
	uint8_t ms_class = 45;
	uint32_t fn = 0;
	uint8_t block_nr = 0;
	uint8_t trx_no;

	uint8_t rbb[64/8];

	gprs_rlcmac_dl_tbf *dl_tbf;

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	bts->dl_tbf_idle_msec = 200;

	dl_tbf = create_dl_tbf(&the_bts, ms_class, &trx_no);

	for (i = 0; i < sizeof(llc_data); i++)
		llc_data[i] = i%256;

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Schedule two LLC frames */
	dl_tbf->append_data(ms_class, 1000, llc_data, sizeof(llc_data));
	dl_tbf->append_data(ms_class, 1000, llc_data, sizeof(llc_data));

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Drain the queue */
	while (dl_tbf->have_data())
		/* Request to send one RLC/MAC block */
		send_rlc_block(bts, trx_no, ts_no, 0, &fn, &block_nr);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* ACK all blocks */
	memset(rbb, 0xff, sizeof(rbb));
	/* Receive an ACK */
	dl_tbf->rcvd_dl_ack(0, dl_tbf->m_window.v_s(), rbb);
	OSMO_ASSERT(dl_tbf->m_window.window_empty());

	/* Force sending of a single block containing an LLC dummy command */
	send_rlc_block(bts, trx_no, ts_no, 0, &fn, &block_nr);

	/* Receive an ACK */
	dl_tbf->rcvd_dl_ack(0, dl_tbf->m_window.v_s(), rbb);
	OSMO_ASSERT(dl_tbf->m_window.window_empty());

	/* Timeout (make sure fn % 52 remains valid) */
	fn += 52 * ((msecs_to_frames(bts->dl_tbf_idle_msec + 100) + 51)/ 52);
	send_rlc_block(bts, trx_no, ts_no, 0, &fn, &block_nr);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FINISHED));

	/* Receive a final ACK */
	dl_tbf->rcvd_dl_ack(1, dl_tbf->m_window.v_s(), rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	OSMO_ASSERT(dl_tbf->new_tbf() == dl_tbf);
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
	check_tbf(dl_tbf);
	tbf_free(dl_tbf);
	printf("=== end %s ===\n", __func__);
}

static void test_tbf_imsi()
{
	BTS the_bts;
	uint8_t ts_no = 4;
	uint8_t ms_class = 45;
	uint8_t trx_no;
	GprsMs *ms1, *ms2;

	gprs_rlcmac_dl_tbf *dl_tbf[2];

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no);

	dl_tbf[0] = create_dl_tbf(&the_bts, ms_class, &trx_no);
	dl_tbf[1] = create_dl_tbf(&the_bts, ms_class, &trx_no);

	dl_tbf[0]->update_ms(0xf1000001, GPRS_RLCMAC_DL_TBF);
	dl_tbf[1]->update_ms(0xf1000002, GPRS_RLCMAC_DL_TBF);

	dl_tbf[0]->assign_imsi("001001000000001");
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000001");
	OSMO_ASSERT(ms1 != NULL);
	ms2 = the_bts.ms_store().get_ms(0xf1000001);
	OSMO_ASSERT(ms2 != NULL);
	OSMO_ASSERT(strcmp(ms2->imsi(), "001001000000001") == 0);
	OSMO_ASSERT(ms1 == ms2);

	/* change the IMSI on TBF 0 */
	dl_tbf[0]->assign_imsi("001001000000002");
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000001");
	OSMO_ASSERT(ms1 == NULL);
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000002");
	OSMO_ASSERT(ms1 != NULL);
	OSMO_ASSERT(strcmp(ms2->imsi(), "001001000000002") == 0);
	OSMO_ASSERT(ms1 == ms2);

	/* use the same IMSI on TBF 2 */
	dl_tbf[1]->assign_imsi("001001000000002");
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000002");
	OSMO_ASSERT(ms1 != NULL);
	OSMO_ASSERT(ms1 != ms2);
	OSMO_ASSERT(strcmp(ms1->imsi(), "001001000000002") == 0);
	OSMO_ASSERT(strcmp(ms2->imsi(), "") == 0);

	tbf_free(dl_tbf[1]);
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000002");
	OSMO_ASSERT(ms1 == NULL);

	tbf_free(dl_tbf[0]);
	printf("=== end %s ===\n", __func__);
}

static void test_tbf_exhaustion()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	unsigned i;
	uint8_t ts_no = 4;
	uint8_t ms_class = 45;
	int rc = 0;

	uint8_t buf[256] = {0};

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	setup_bts(&the_bts, ts_no);
	gprs_bssgp_create_and_connect(bts, 33001, 0, 33001,
		1234, 1234, 1234, 1, 1, 0, 0, 0);

	for (i = 0; i < 1024; i++) {
		uint32_t tlli = 0xc0000000 + i;
		char imsi[16] = {0};
		unsigned delay_csec = 1000;

		snprintf(imsi, sizeof(imsi), "001001%09d", i);

		rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class,
			delay_csec, buf, sizeof(buf));

		if (rc < 0)
			break;
	}

	OSMO_ASSERT(rc == -EBUSY);
	printf("=== end %s ===\n", __func__);

	gprs_bssgp_destroy();
}

static const struct log_info_cat default_categories[] = {
        {"DCSN1", "\033[1;31m", "Concrete Syntax Notation One (CSN1)", LOGL_INFO, 0},
        {"DL1IF", "\033[1;32m", "GPRS PCU L1 interface (L1IF)", LOGL_DEBUG, 1},
        {"DRLCMAC", "\033[0;33m", "GPRS RLC/MAC layer (RLCMAC)", LOGL_DEBUG, 1},
        {"DRLCMACDATA", "\033[0;33m", "GPRS RLC/MAC layer Data (RLCMAC)", LOGL_DEBUG, 1},
        {"DRLCMACDL", "\033[1;33m", "GPRS RLC/MAC layer Downlink (RLCMAC)", LOGL_DEBUG, 1},
        {"DRLCMACUL", "\033[1;36m", "GPRS RLC/MAC layer Uplink (RLCMAC)", LOGL_DEBUG, 1},
        {"DRLCMACSCHED", "\033[0;36m", "GPRS RLC/MAC layer Scheduling (RLCMAC)", LOGL_DEBUG, 1},
        {"DRLCMACMEAS", "\033[1;31m", "GPRS RLC/MAC layer Measurements (RLCMAC)", LOGL_INFO, 1},
        {"DBSSGP","\033[1;34m", "GPRS BSS Gateway Protocol (BSSGP)", LOGL_INFO , 1},
        {"DPCU", "\033[1;35m", "GPRS Packet Control Unit (PCU)", LOGL_NOTICE, 1},
};

static int filter_fn(const struct log_context *ctx,
                     struct log_target *tar)
{
        return 1;
}

const struct log_info debug_log_info = {
	filter_fn,
	(struct log_info_cat*)default_categories,
	ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	struct vty_app_info pcu_vty_info = {0};

	tall_pcu_ctx = talloc_named_const(NULL, 1, "moiji-mobile TbfTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_set_talloc_ctx(tall_pcu_ctx);
	osmo_init_logging(&debug_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	bssgp_set_log_ss(DBSSGP);

	vty_init(&pcu_vty_info);
	pcu_vty_init(&debug_log_info);

	test_tbf_tlli_update();
	test_tbf_final_ack(TEST_MODE_STANDARD);
	test_tbf_final_ack(TEST_MODE_REVERSE_FREE);
	test_tbf_delayed_release();
	test_tbf_imsi();
	test_tbf_exhaustion();

	if (getenv("TALLOC_REPORT_FULL"))
		talloc_report_full(tall_pcu_ctx, stderr);
	return EXIT_SUCCESS;
}

/*
 * stubs that should not be reached
 */
extern "C" {
void l1if_pdch_req() { abort(); }
void l1if_connect_pdch() { abort(); }
void l1if_close_pdch() { abort(); }
void l1if_open_pdch() { abort(); }
}
