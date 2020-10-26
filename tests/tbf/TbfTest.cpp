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
#include "tbf_ul.h"
#include "gprs_debug.h"
#include "pcu_utils.h"
#include "gprs_bssgp_pcu.h"
#include "pcu_l1_if.h"
#include "decoding.h"
#include <gprs_rlcmac.h>

extern "C" {
#include "pcu_vty.h"
#include "coding_scheme.h"

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vty.h>
#include <osmocom/gprs/protocol/gsm_04_60.h>
#include <osmocom/gsm/l1sap.h>
}

#include <errno.h>

#define DUMMY_FN 2654167

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;

/* Measurements shared by all unit tests */
static struct pcu_l1_meas meas;

static int bts_handle_rach(BTS *bts, uint16_t ra, uint32_t Fn, int16_t qta)
{
	struct rach_ind_params rip = {
		.burst_type = GSM_L1_BURST_TYPE_ACCESS_0,
		.is_11bit = false,
		.ra = ra,
		.trx_nr = 0,
		.ts_nr = 0,
		.rfn = Fn,
		.qta = qta,
	};

	return bts->rcv_rach(&rip);
}

static void check_tbf(gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf);
	if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE))
		OSMO_ASSERT(tbf->timers_pending(T3191) || tbf->timers_pending(T3193));
	if (tbf->state_is(GPRS_RLCMAC_RELEASING))
		OSMO_ASSERT(tbf->timers_pending(T_MAX));
}

static void test_tbf_base()
{

	fprintf(stderr, "=== start %s ===\n", __func__);

	OSMO_ASSERT(GPRS_RLCMAC_DL_TBF == reverse(GPRS_RLCMAC_UL_TBF));
	OSMO_ASSERT(GPRS_RLCMAC_UL_TBF == reverse(GPRS_RLCMAC_DL_TBF));

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_tlli_update()
{
	BTS the_bts;
	GprsMs *ms, *ms_new;

	fprintf(stderr, "=== start %s ===\n", __func__);

	the_bts.bts_data()->alloc_algorithm = alloc_algorithm_a;
	the_bts.bts_data()->trx[0].pdch[2].enable();
	the_bts.bts_data()->trx[0].pdch[3].enable();

	/*
	 * Make a uplink and downlink allocation
	 */
	ms = the_bts.ms_alloc(0, 0);
	gprs_rlcmac_tbf *dl_tbf = tbf_alloc_dl_tbf(the_bts.bts_data(),
						ms, 0, false);
	OSMO_ASSERT(dl_tbf != NULL);
	dl_tbf->update_ms(0x2342, GPRS_RLCMAC_DL_TBF);
	dl_tbf->set_ta(4);
	OSMO_ASSERT(ms->dl_tbf() == dl_tbf);
	OSMO_ASSERT(dl_tbf->ms() == ms);

	gprs_rlcmac_tbf *ul_tbf = tbf_alloc_ul_tbf(the_bts.bts_data(),
						   ms, 0, false);
	OSMO_ASSERT(ul_tbf != NULL);
	ul_tbf->update_ms(0x2342, GPRS_RLCMAC_UL_TBF);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);
	OSMO_ASSERT(ul_tbf->ms() == ms);

	OSMO_ASSERT(the_bts.ms_by_tlli(0x2342) == ms);

	/*
	 * Now check.. that DL changes and that the timing advance
	 * has changed.
	 */
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

	ms_new = the_bts.ms_by_tlli(0x4232);
	OSMO_ASSERT(ms_new != NULL);
	OSMO_ASSERT(ms_new->ta() == 4);

	OSMO_ASSERT(ul_tbf->ta() == 4);
	OSMO_ASSERT(dl_tbf->ta() == 4);

	ul_tbf->set_ta(6);

	OSMO_ASSERT(ul_tbf->ta() == 6);
	OSMO_ASSERT(dl_tbf->ta() == 6);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static uint8_t llc_data[200];

/* override, requires '-Wl,--wrap=pcu_sock_send' */
int __real_pcu_sock_send(struct msgb *msg);
int __wrap_pcu_sock_send(struct msgb *msg)
{
	return 0;
}

static void setup_bts(BTS *the_bts, uint8_t ts_no, uint8_t cs = 1)
{
	gprs_rlcmac_bts *bts;
	gprs_rlcmac_trx *trx;

	bts = the_bts->bts_data();
	bts->alloc_algorithm = alloc_algorithm_a;
	bts->initial_cs_dl = cs;
	bts->initial_cs_ul = cs;
	osmo_tdef_set(bts->T_defs_pcu, -2030, 0, OSMO_TDEF_S);
	osmo_tdef_set(bts->T_defs_pcu, -2031, 0, OSMO_TDEF_S);
	trx = &bts->trx[0];

	trx->pdch[ts_no].enable();
	the_bts->set_current_frame_number(DUMMY_FN);
}

static gprs_rlcmac_dl_tbf *create_dl_tbf(BTS *the_bts, uint8_t ms_class,
	uint8_t egprs_ms_class, uint8_t *trx_no_)
{
	gprs_rlcmac_bts *bts;
	int tfi;
	uint8_t trx_no;
	GprsMs *ms;
	gprs_rlcmac_dl_tbf *dl_tbf;

	bts = the_bts->bts_data();
	ms = the_bts->ms_alloc(ms_class, egprs_ms_class);

	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_DL_TBF, &trx_no, -1);
	OSMO_ASSERT(tfi >= 0);
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, trx_no, true);
	OSMO_ASSERT(dl_tbf);
	dl_tbf->set_ta(0);
	check_tbf(dl_tbf);

	/* "Establish" the DL TBF */
	TBF_SET_ASS_STATE_DL(dl_tbf, GPRS_RLCMAC_DL_ASS_SEND_ASS);
	TBF_SET_STATE(dl_tbf, GPRS_RLCMAC_FLOW);
	dl_tbf->m_wait_confirm = 0;
	check_tbf(dl_tbf);

	*trx_no_ = trx_no;

	return dl_tbf;
}

static unsigned fn2bn(unsigned fn)
{
	return (fn % 52) / 4;
}

static unsigned fn_add_blocks(unsigned fn, unsigned blocks)
{
	unsigned bn = fn2bn(fn) + blocks;
	fn = fn - (fn % 52);
	fn += bn * 4 + bn / 3;
	return fn % GSM_MAX_FN;
}

static void request_dl_rlc_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx_no, uint8_t ts_no,
	uint32_t *fn, uint8_t *block_nr = NULL)
{
	uint8_t bn = fn2bn(*fn);
	gprs_rlcmac_rcv_rts_block(bts, trx_no, ts_no, *fn, bn);
	*fn = fn_add_blocks(*fn, 1);
	bn += 1;
	if (block_nr)
		*block_nr = bn;
}

static void request_dl_rlc_block(struct gprs_rlcmac_tbf *tbf,
	uint32_t *fn, uint8_t *block_nr = NULL)
{
	request_dl_rlc_block(tbf->bts->bts_data(), tbf->trx->trx_no,
		tbf->control_ts, fn, block_nr);
}

enum test_tbf_final_ack_mode {
	TEST_MODE_STANDARD,
	TEST_MODE_REVERSE_FREE
};

static void test_tbf_final_ack(enum test_tbf_final_ack_mode test_mode)
{
	BTS the_bts;
	uint8_t ts_no = 4;
	unsigned i;
	uint8_t ms_class = 45;
	uint32_t fn;
	uint8_t block_nr;
	uint8_t trx_no;
	GprsMs *ms;
	uint32_t tlli = 0xffeeddcc;

	uint8_t rbb[64/8];

	fprintf(stderr, "=== start %s ===\n", __func__);

	gprs_rlcmac_dl_tbf *dl_tbf;
	gprs_rlcmac_tbf *new_tbf;

	setup_bts(&the_bts, ts_no);
	dl_tbf = create_dl_tbf(&the_bts, ms_class, 0, &trx_no);
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);
	ms = dl_tbf->ms();

	for (i = 0; i < sizeof(llc_data); i++)
		llc_data[i] = i%256;

	/* Schedule two LLC frames */
	dl_tbf->append_data(ms_class, 1000, llc_data, sizeof(llc_data));
	dl_tbf->append_data(ms_class, 1000, llc_data, sizeof(llc_data));


	/* Send only a few RLC/MAC blocks */
	fn = 0;
	do {
		/* Request to send one block */
		request_dl_rlc_block(dl_tbf, &fn, &block_nr);
	} while (block_nr < 3);

	OSMO_ASSERT(dl_tbf->have_data());
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Queue a final ACK */
	memset(rbb, 0, sizeof(rbb));
	/* Receive a final ACK */
	dl_tbf->rcvd_dl_ack(true, 1, rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	new_tbf = ms->dl_tbf();
	check_tbf(new_tbf);
	OSMO_ASSERT(new_tbf != dl_tbf);
	OSMO_ASSERT(new_tbf->tfi() == 1);
	check_tbf(dl_tbf);
	TBF_SET_ASS_STATE_DL(dl_tbf, GPRS_RLCMAC_DL_ASS_NONE);
	if (test_mode == TEST_MODE_REVERSE_FREE) {
		GprsMs::Guard guard(ms);
		tbf_free(new_tbf);
		OSMO_ASSERT(ms->dl_tbf() == NULL);
		check_tbf(dl_tbf);
		tbf_free(dl_tbf);
	} else {
		GprsMs::Guard guard(ms);
		tbf_free(dl_tbf);
		OSMO_ASSERT(ms->dl_tbf() == new_tbf);
		check_tbf(new_tbf);
		tbf_free(new_tbf);
		OSMO_ASSERT(ms->dl_tbf() == NULL);
	}

	fprintf(stderr, "=== end %s ===\n", __func__);
}

/* Receive an ACK */
#define RCV_ACK(fin, tbf, rbb) do { \
		gprs_rlc_dl_window *w = static_cast<gprs_rlc_dl_window *>(tbf->window());	\
		tbf->rcvd_dl_ack(fin, w->v_s(), rbb);	\
		if (!fin)						\
			OSMO_ASSERT(w->window_empty());	\
	} while(0)

static void test_tbf_delayed_release()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	unsigned i;
	uint8_t ms_class = 45;
	uint32_t fn = 0;
	uint8_t trx_no;
	uint32_t tlli = 0xffeeddcc;
	unsigned long dl_tbf_idle_msec;

	uint8_t rbb[64/8];

	gprs_rlcmac_dl_tbf *dl_tbf;

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	OSMO_ASSERT(osmo_tdef_set(bts->T_defs_pcu, -2031, 200, OSMO_TDEF_MS) == 0);

	dl_tbf = create_dl_tbf(&the_bts, ms_class, 0, &trx_no);
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);

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
		request_dl_rlc_block(dl_tbf, &fn);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* ACK all blocks */
	memset(rbb, 0xff, sizeof(rbb));

	RCV_ACK(false, dl_tbf, rbb); /* Receive an ACK */

	/* Force sending of a single block containing an LLC dummy command */
	request_dl_rlc_block(dl_tbf, &fn);

	RCV_ACK(false, dl_tbf, rbb); /* Receive an ACK */

	/* Timeout (make sure fn % 52 remains valid) */
	dl_tbf_idle_msec = osmo_tdef_get(bts->T_defs_pcu, -2031, OSMO_TDEF_MS, -1);
	fn += 52 * ((msecs_to_frames(dl_tbf_idle_msec + 100) + 51)/ 52);
	request_dl_rlc_block(dl_tbf, &fn);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FINISHED));

	RCV_ACK(true, dl_tbf, rbb); /* Receive a final ACK */

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	TBF_SET_ASS_STATE_DL(dl_tbf, GPRS_RLCMAC_DL_ASS_NONE);
	check_tbf(dl_tbf);
	tbf_free(dl_tbf);
	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_imsi()
{
	BTS the_bts;
	uint8_t ts_no = 4;
	uint8_t ms_class = 45;
	uint8_t trx_no;
	GprsMs *ms1, *ms2;

	gprs_rlcmac_dl_tbf *dl_tbf[2];

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no);

	dl_tbf[0] = create_dl_tbf(&the_bts, ms_class, 0, &trx_no);
	dl_tbf[1] = create_dl_tbf(&the_bts, ms_class, 0, &trx_no);

	dl_tbf[0]->update_ms(0xf1000001, GPRS_RLCMAC_DL_TBF);
	dl_tbf[1]->update_ms(0xf1000002, GPRS_RLCMAC_DL_TBF);

	dl_tbf[0]->ms()->set_imsi("001001000000001");
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000001");
	OSMO_ASSERT(ms1 != NULL);
	ms2 = the_bts.ms_store().get_ms(0xf1000001);
	OSMO_ASSERT(ms2 != NULL);
	OSMO_ASSERT(strcmp(ms2->imsi(), "001001000000001") == 0);
	OSMO_ASSERT(ms1 == ms2);

	/* change the IMSI on TBF 0 */
	dl_tbf[0]->ms()->set_imsi("001001000000002");
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000001");
	OSMO_ASSERT(ms1 == NULL);
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000002");
	OSMO_ASSERT(ms1 != NULL);
	OSMO_ASSERT(strcmp(ms2->imsi(), "001001000000002") == 0);
	OSMO_ASSERT(ms1 == ms2);

	/* use the same IMSI on TBF 1 */
	{
		GprsMs::Guard guard(ms2);
		dl_tbf[1]->ms()->set_imsi("001001000000002");
		ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000002");
		OSMO_ASSERT(ms1 != NULL);
		OSMO_ASSERT(ms1 != ms2);
		OSMO_ASSERT(strcmp(ms1->imsi(), "001001000000002") == 0);
		OSMO_ASSERT(strcmp(ms2->imsi(), "") == 0);
	}

	ms2 = the_bts.ms_store().get_ms(0xf1000001);
	OSMO_ASSERT(ms2 == NULL);

	tbf_free(dl_tbf[1]);
	ms1 = the_bts.ms_store().get_ms(0, 0, "001001000000002");
	OSMO_ASSERT(ms1 == NULL);

	fprintf(stderr, "=== end %s ===\n", __func__);
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

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->nsi = gprs_ns2_instantiate(tall_pcu_ctx, gprs_ns_prim_cb, NULL);
	if (!bts->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		abort();
	}

	setup_bts(&the_bts, ts_no);
	gprs_bssgp_init(bts, 1234, 1234, 1, 1, false, 0, 0, 0);

	for (i = 0; i < 1024; i++) {
		uint32_t tlli = 0xc0000000 + i;
		char imsi[16] = {0};
		unsigned delay_csec = 1000;

		snprintf(imsi, sizeof(imsi), "001001%09d", i);

		rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
			delay_csec, buf, sizeof(buf));

		if (rc < 0)
			break;
	}

	OSMO_ASSERT(rc == -EBUSY);
	fprintf(stderr, "=== end %s ===\n", __func__);

	gprs_bssgp_destroy(bts);
}

static void test_tbf_dl_llc_loss()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	uint8_t ms_class = 45;
	int rc = 0;
	uint32_t tlli = 0xc0123456;
	const char *imsi = "001001000123456";
	unsigned delay_csec = 1000;
	GprsMs *ms;

	uint8_t buf[19];

	bts = the_bts.bts_data();
	bts->nsi = gprs_ns2_instantiate(tall_pcu_ctx, gprs_ns_prim_cb, NULL);
	if (!bts->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		abort();
	}

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no);
	/* keep the MS object 10 seconds */
	OSMO_ASSERT(osmo_tdef_set(bts->T_defs_pcu, -2030, 10, OSMO_TDEF_S) == 0);

	gprs_bssgp_init(bts, 2234, 2234, 1, 1, false, 0, 0, 0);

	/* Handle LLC frame 1 */
	memset(buf, 1, sizeof(buf));
	rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
		delay_csec, buf, sizeof(buf));
	OSMO_ASSERT(rc >= 0);

	ms = the_bts.ms_store().get_ms(0, 0, imsi);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->dl_tbf() != NULL);
	ms->dl_tbf()->set_ta(0);

	/* Handle LLC frame 2 */
	memset(buf, 2, sizeof(buf));
	rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
		delay_csec, buf, sizeof(buf));
	OSMO_ASSERT(rc >= 0);

	/* TBF establishment fails (timeout) */
	tbf_free(ms->dl_tbf());

	/* Handle LLC frame 3 */
	memset(buf, 3, sizeof(buf));
	rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
		delay_csec, buf, sizeof(buf));
	OSMO_ASSERT(rc >= 0);

	OSMO_ASSERT(ms->dl_tbf() != NULL);

	/* Get first BSN */
	struct msgb *msg;
	int fn = 0;
	uint8_t expected_data = 1;
	static uint8_t exp[][GSM_MACBLOCK_LEN] = {
		{ 0x07, 0x00, 0x00, 0x4d, 0x01, 0x01, 0x01,
		  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
		{ 0x07, 0x00, 0x02, 0x4d, 0x02, 0x02, 0x02,
		  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 },
		{ 0x07, 0x01, 0x04, 0x4d, 0x03, 0x03, 0x03,
		  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 },
	};

	while (ms->dl_tbf()->have_data()) {
		msg = ms->dl_tbf()->create_dl_acked_block(fn += 4, 7);
		fprintf(stderr, "MSG = %s\n", msgb_hexdump(msg));
		if (!msgb_eq_data_print(msg, exp[expected_data - 1], GSM_MACBLOCK_LEN))
			fprintf(stderr, "%s failed at %u\n", __func__, expected_data);

		expected_data += 1;
	}
	OSMO_ASSERT(expected_data-1 == 3);

	fprintf(stderr, "=== end %s ===\n", __func__);

	gprs_bssgp_destroy(bts);
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf_single_phase(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta)
{
	GprsMs *ms;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t trx_no = 0;
	struct gprs_rlcmac_pdch *pdch;

	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	bts_handle_rach(the_bts, 0x03, *fn, qta);

	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	OSMO_ASSERT(ul_tbf != NULL);

	OSMO_ASSERT(ul_tbf->ta() == qta / 4);

	uint8_t data_msg[23] = {
		0x00, /* GPRS_RLCMAC_DATA_BLOCK << 6 */
		uint8_t(1 | (tfi << 2)),
		uint8_t(1), /* BSN:7, E:1 */
		uint8_t(tlli >> 24), uint8_t(tlli >> 16),
		uint8_t(tlli >> 8), uint8_t(tlli), /* TLLI */
	};

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data_msg[0], sizeof(data_msg), *fn, &meas);

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);

	return ul_tbf;
}

static void send_ul_mac_block(BTS *the_bts, unsigned trx_no, unsigned ts_no,
	RlcMacUplink_t *ulreq, unsigned fn)
{
	bitvec *rlc_block;
	uint8_t buf[64];
	int num_bytes;
	struct gprs_rlcmac_pdch *pdch;

	rlc_block = bitvec_alloc(23, tall_pcu_ctx);

	OSMO_ASSERT(encode_gsm_rlcmac_uplink(rlc_block, ulreq) == 0);
	num_bytes = bitvec_pack(rlc_block, &buf[0]);
	OSMO_ASSERT(size_t(num_bytes) < sizeof(buf));
	bitvec_free(rlc_block);

	the_bts->set_current_block_frame_number(fn, 0);

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&buf[0], num_bytes, fn, &meas);
}

static void send_control_ack(gprs_rlcmac_tbf *tbf)
{
	RlcMacUplink_t ulreq = {0};

	OSMO_ASSERT(tbf->poll_fn != 0);
	OSMO_ASSERT(tbf->is_control_ts(tbf->poll_ts));

	ulreq.u.MESSAGE_TYPE = MT_PACKET_CONTROL_ACK;
	Packet_Control_Acknowledgement_t *ctrl_ack =
		&ulreq.u.Packet_Control_Acknowledgement;

	ctrl_ack->PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ctrl_ack->TLLI = tbf->tlli();
	send_ul_mac_block(tbf->bts, tbf->trx->trx_no, tbf->poll_ts,
		&ulreq, tbf->poll_fn);
}

static gprs_rlcmac_ul_tbf *puan_urbb_len_issue(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	uint32_t rach_fn = *fn - 51;
	uint32_t sba_fn = *fn + 52;
	uint8_t trx_no = 0;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch *pdch;
	gprs_rlcmac_bts *bts;
	RlcMacUplink_t ulreq = {0};
	struct gprs_rlc_ul_header_egprs_3 *egprs3  = NULL;

	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/*
	 * simulate RACH, this sends an Immediate
	 * Assignment Uplink on the AGCH
	 */
	bts_handle_rach(the_bts, 0x73, rach_fn, qta);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability2 = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.
		Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.EGPRS_multislot_class = ms_class;
	}

	send_ul_mac_block(the_bts, trx_no, ts_no, &ulreq, sba_fn);

	/* check the TBF */
	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	OSMO_ASSERT(ul_tbf);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);

	/* send packet uplink assignment */
	*fn = sba_fn;
	request_dl_rlc_block(ul_tbf, fn);

	/* send real acknowledgement */
	send_control_ack(ul_tbf);

	check_tbf(ul_tbf);
	/* send fake data */
	uint8_t data_msg[42] = {
		0xf << 2, /* GPRS_RLCMAC_DATA_BLOCK << 6, CV = 15 */
		(uint8_t)(tfi << 1),
		1, /* BSN:7, E:1 */
	};

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data_msg[0], 23, *fn, &meas);

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	/*
	 * TS 44.060, B.8.1
	 * first seg received first, later second seg
	 */
	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 0;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 1;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 0;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	struct msgb *msg1 = ul_tbf->create_ul_ack(*fn, ts_no);

	static uint8_t exp1[] = { 0x40, 0x24, 0x01, 0x03, 0x3e, 0x24, 0x46, 0x68, 0x90, 0x87, 0xb0, 0x06,
				  0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
	};

	if (!msgb_eq_data_print(msg1, exp1, GSM_MACBLOCK_LEN)) {
		fprintf(stderr, "%s test failed on 1st segment!\n", __func__);
		return NULL;
	}

	egprs3->si = 0;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 4;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	msg1 = ul_tbf->create_ul_ack(*fn, ts_no);

	static uint8_t exp2[] = { 0x40, 0x24, 0x01, 0x03, 0x3e, 0x24, 0x46, 0x68, 0x90, 0x88, 0xb0, 0x06, 0x8b,
				  0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
	};

	if (!msgb_eq_data_print(msg1, exp2, GSM_MACBLOCK_LEN)) {
		fprintf(stderr, "%s test failed on 2nd segment!\n", __func__);
		return NULL;
	}
	return ul_tbf;
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf_two_phase_spb(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	uint32_t rach_fn = *fn - 51;
	uint32_t sba_fn = *fn + 52;
	uint8_t trx_no = 0;
	int tfi = 0, i = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch *pdch;
	gprs_rlcmac_bts *bts;
	RlcMacUplink_t ulreq = {0};
	struct gprs_rlc_ul_header_egprs_3 *egprs3  = NULL;

	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/*
	 * simulate RACH, this sends an Immediate
	 * Assignment Uplink on the AGCH
	 */
	bts_handle_rach(the_bts, 0x73, rach_fn, qta);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability2 = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.
			Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.EGPRS_multislot_class = ms_class;
	}

	send_ul_mac_block(the_bts, trx_no, ts_no, &ulreq, sba_fn);

	/* check the TBF */
	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	OSMO_ASSERT(ul_tbf != NULL);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);

	/* send packet uplink assignment */
	*fn = sba_fn;
	request_dl_rlc_block(ul_tbf, fn);

	/* send real acknowledgement */
	send_control_ack(ul_tbf);

	check_tbf(ul_tbf);

	/* send fake data */
	uint8_t data_msg[42] = {
		0x00 | 0xf << 2, /* GPRS_RLCMAC_DATA_BLOCK << 6, CV = 15 */
		uint8_t(0 | (tfi << 1)),
		uint8_t(1), /* BSN:7, E:1 */
	};

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data_msg[0], 23, *fn, &meas);

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	/*
	 * TS 44.060, B.8.1
	 * first seg received first, later second seg
	 */
	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 1;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 2;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	struct gprs_rlc_data *block =  ul_tbf->m_rlc.block(1);

	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_FIRST_SEG_RXD);

	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 1;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 3;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_DEFAULT);
	OSMO_ASSERT(block->cs_last ==
			MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	/*
	 * TS 44.060, B.8.1
	 * second seg first, later first seg
	 */
	memset(data_msg, 0, sizeof(data_msg));

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 2;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 3;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(2);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_SECOND_SEG_RXD);

	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 2;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 2;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_DEFAULT);
	OSMO_ASSERT(block->cs_last ==
			MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	/*
	 * TS 44.060, B.8.1
	 * Error scenario with spb as 1
	 */
	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 3;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 1;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(3);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_DEFAULT);
	/*
	 * TS 44.060, B.8.1
	 * comparison of rlc_data for multiple scenarios
	 * Receive First, the second(BSN 3)
	 * Receive First, First then Second(BSN 4)
	 * Receive Second then First(BSN 5)
	 * after above 3 scenarios are triggered,
	 * rlc_data of all 3 BSN are compared
	 */

	/* Initialize the data_msg */
	for (i = 0; i < 42; i++)
		data_msg[i] = i;

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 3;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 2;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(3);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_FIRST_SEG_RXD);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 3;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 3;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(3);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_DEFAULT);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);
	OSMO_ASSERT(block->cs_last ==
			MCS6);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 4;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 2;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(4);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_FIRST_SEG_RXD);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 4;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 2;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(4);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_FIRST_SEG_RXD);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 4;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 3;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(4);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_DEFAULT);
	OSMO_ASSERT(block->cs_last ==
			MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 5;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 3;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(5);
	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_SECOND_SEG_RXD);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 1;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 5;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 2;
	egprs3->pi = 0;

	pdch->rcv_block(data_msg, 42, *fn, &meas);

	block =  ul_tbf->m_rlc.block(5);

	/* check the status of the block */
	OSMO_ASSERT(block->spb_status.block_status_ul ==
				EGPRS_RESEG_DEFAULT);
	OSMO_ASSERT(block->cs_last ==
			MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	OSMO_ASSERT(ul_tbf->m_rlc.block(5)->len ==
				ul_tbf->m_rlc.block(4)->len);
	OSMO_ASSERT(ul_tbf->m_rlc.block(5)->len ==
				ul_tbf->m_rlc.block(3)->len);

	/* Compare the spb status of each BSNs(3,4,5). should be same */
	OSMO_ASSERT(
		ul_tbf->m_rlc.block(5)->spb_status.block_status_ul ==
		ul_tbf->m_rlc.block(4)->spb_status.block_status_ul);
	OSMO_ASSERT(
		ul_tbf->m_rlc.block(5)->spb_status.block_status_ul ==
		ul_tbf->m_rlc.block(3)->spb_status.block_status_ul);

	/* Compare the Assembled MCS of each BSNs(3,4,5). should be same */
	OSMO_ASSERT(ul_tbf->m_rlc.block(5)->cs_last ==
				ul_tbf->m_rlc.block(4)->cs_last);
	OSMO_ASSERT(ul_tbf->m_rlc.block(5)->cs_last ==
				ul_tbf->m_rlc.block(3)->cs_last);

	/* Compare the data of each BSNs(3,4,5). should be same */
	OSMO_ASSERT(
		!memcmp(ul_tbf->m_rlc.block(5)->block,
		ul_tbf->m_rlc.block(4)->block, ul_tbf->m_rlc.block(5)->len
		));
	OSMO_ASSERT(
		!memcmp(ul_tbf->m_rlc.block(5)->block,
		ul_tbf->m_rlc.block(3)->block, ul_tbf->m_rlc.block(5)->len
		));

	return ul_tbf;
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class)
{
	uint32_t rach_fn = *fn - 51;
	uint32_t sba_fn = *fn + 52;
	uint8_t trx_no = 0;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_bts *bts;
	RlcMacUplink_t ulreq = {0};

	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/*
	 * simulate RACH, this sends an Immediate
	 * Assignment Uplink on the AGCH
	 */
	bts_handle_rach(the_bts, 0x73, rach_fn, qta);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability2 = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.
		Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.EGPRS_multislot_class = ms_class;
	}
	send_ul_mac_block(the_bts, trx_no, ts_no, &ulreq, sba_fn);

	/* check the TBF */
	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	/* send packet uplink assignment */
	*fn = sba_fn;
	request_dl_rlc_block(ul_tbf, fn);

	/* send real acknowledgement */
	send_control_ack(ul_tbf);

	check_tbf(ul_tbf);

	return ul_tbf;
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf_two_phase_puan_URBB_no_length(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class, gprs_rlcmac_ul_tbf *ul_tbf)
{
	OSMO_ASSERT(ul_tbf);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);
	GprsMs *ms;
	uint8_t trx_no = 0;
	int tfi = 0;
	struct gprs_rlcmac_pdch *pdch;

	/* send fake data with cv=0*/
	struct gprs_rlc_ul_header_egprs_3 *hdr3 = NULL;
	uint8_t data[49] = {0};

	hdr3 = (struct gprs_rlc_ul_header_egprs_3 *)data;

	/*header_construction */
	memset(data, 0x2b, sizeof(data));
	/* Message with CRBB */
	for (int i = 0 ; i < 80; i++) {
		hdr3->r = 0;
		hdr3->si = 0;
		hdr3->cv = 10;
		hdr3->tfi_hi = (tfi >> 3) & 0x3;
		hdr3->tfi_lo = tfi & 0x7;
		hdr3->bsn1_hi = ((i * 2)&0x1f);
		hdr3->bsn1_lo = ((i * 2)/32);
		hdr3->cps_hi = 0;
		hdr3->cps_lo = 0;
		hdr3->spb = 0;
		hdr3->rsb = 0;
		hdr3->pi = 0;
		hdr3->spare = 0;
		hdr3->dummy = 1;
		data[4] = 0x0;
		data[5] = 0x0;
		data[6] = 0x2b;
		data[7] = 0x2b;
		pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
		pdch->rcv_block(&data[0], sizeof(data), *fn, &meas);
	}
	ul_tbf->create_ul_ack(*fn, ts_no);
	memset(data, 0x2b, sizeof(data));
	hdr3 = (struct gprs_rlc_ul_header_egprs_3 *)data;
	hdr3->r = 0;
	hdr3->si = 0;
	hdr3->cv = 0;
	hdr3->tfi_hi = (tfi >> 3) & 0x3;
	hdr3->tfi_lo = tfi & 0x7;
	hdr3->bsn1_hi = 0;
	hdr3->bsn1_lo = 2;
	hdr3->cps_hi = 0;
	hdr3->cps_lo = 0;
	hdr3->spb = 0;
	hdr3->rsb = 0;
	hdr3->pi = 0;
	hdr3->spare = 0;
	hdr3->dummy = 1;
	data[4] = 0x0;
	data[5] = 0x2b;
	data[6] = 0x2b;
	data[7] = 0x2b;

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data[0], sizeof(data), *fn, &meas);

	request_dl_rlc_block(ul_tbf, fn);

	check_tbf(ul_tbf);
	OSMO_ASSERT(ul_tbf->ul_ack_state_is(GPRS_RLCMAC_UL_ACK_NONE));

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	return ul_tbf;
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf_two_phase_puan_URBB_with_length(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class, gprs_rlcmac_ul_tbf *ul_tbf)
{
	OSMO_ASSERT(ul_tbf);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);
	GprsMs *ms;
	uint8_t trx_no = 0;
	int tfi = 0;
	struct gprs_rlcmac_pdch *pdch;

	check_tbf(ul_tbf);
	/* send fake data with cv=0*/
	struct gprs_rlc_ul_header_egprs_3 *hdr3 = NULL;
	uint8_t data[49] = {0};

	hdr3 = (struct gprs_rlc_ul_header_egprs_3 *)data;

	/*header_construction */
	memset(data, 0x2b, sizeof(data));

	/* Message with URBB & URBB length */
	for (int i = 0 ; i < 20; i++) {
		hdr3->r = 0;
		hdr3->si = 0;
		hdr3->cv = 10;
		hdr3->tfi_hi = (tfi >> 3) & 0x3;
		hdr3->tfi_lo = tfi & 0x7;
		hdr3->bsn1_hi = ((i * 2)&0x1f);
		hdr3->bsn1_lo = ((i * 2)/32);
		hdr3->cps_hi = 0;
		hdr3->cps_lo = 0;
		hdr3->spb = 0;
		hdr3->rsb = 0;
		hdr3->pi = 0;
		hdr3->spare = 0;
		hdr3->dummy = 1;
		data[4] = 0x0;
		data[5] = 0x0;
		data[6] = 0x2b;
		data[7] = 0x2b;
		pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
		pdch->rcv_block(&data[0], sizeof(data), *fn, &meas);
	}
	ul_tbf->create_ul_ack(*fn, ts_no);
	memset(data, 0x2b, sizeof(data));
	hdr3 = (struct gprs_rlc_ul_header_egprs_3 *)data;
	hdr3->r = 0;
	hdr3->si = 0;
	hdr3->cv = 0;
	hdr3->tfi_hi = (tfi >> 3) & 0x3;
	hdr3->tfi_lo = tfi & 0x7;
	hdr3->bsn1_hi = 0;
	hdr3->bsn1_lo = 2;
	hdr3->cps_hi = 0;
	hdr3->cps_lo = 0;
	hdr3->spb = 0;
	hdr3->rsb = 0;
	hdr3->pi = 0;
	hdr3->spare = 0;
	hdr3->dummy = 1;
	data[4] = 0x0;
	data[5] = 0x2b;
	data[6] = 0x2b;
	data[7] = 0x2b;

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data[0], sizeof(data), *fn, &meas);
	ul_tbf->create_ul_ack(*fn, ts_no);

	request_dl_rlc_block(ul_tbf, fn);

	check_tbf(ul_tbf);
	OSMO_ASSERT(ul_tbf->ul_ack_state_is(GPRS_RLCMAC_UL_ACK_NONE));

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	return ul_tbf;
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf_two_phase_puan_CRBB(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	uint8_t trx_no = 0;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch *pdch;

	/* check the TBF */
	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	OSMO_ASSERT(ul_tbf);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);

	/* send fake data with cv=0*/
	struct gprs_rlc_ul_header_egprs_3 *hdr3 = NULL;
	uint8_t data[49] = {0};

	hdr3 = (struct gprs_rlc_ul_header_egprs_3 *)data;

	/*header_construction */
	memset(data, 0x2b, sizeof(data));

	/* Message with CRBB */
	for (int i = 80 ; i < 160; i++) {
		hdr3->r = 0;
		hdr3->si = 0;
		hdr3->cv = 10;
		hdr3->tfi_hi = (tfi >> 3) & 0x3;
		hdr3->tfi_lo = tfi & 0x7;
		hdr3->bsn1_hi = ((i)&0x1f);
		hdr3->bsn1_lo = ((i)/32);
		hdr3->cps_hi = 0;
		hdr3->cps_lo = 0;
		hdr3->spb = 0;
		hdr3->rsb = 0;
		hdr3->pi = 0;
		hdr3->spare = 0;
		hdr3->dummy = 1;
		data[4] = 0x0;
		data[5] = 0x0;
		data[6] = 0x2b;
		data[7] = 0x2b;
		pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
		pdch->rcv_block(&data[0], sizeof(data), *fn, &meas);
	}
	ul_tbf->create_ul_ack(*fn, ts_no);
	memset(data, 0x2b, sizeof(data));
	hdr3 = (struct gprs_rlc_ul_header_egprs_3 *)data;
	hdr3->r = 0;
	hdr3->si = 0;
	hdr3->cv = 0;
	hdr3->tfi_hi = (tfi >> 3) & 0x3;
	hdr3->tfi_lo = tfi & 0x7;
	hdr3->bsn1_hi = 0;
	hdr3->bsn1_lo = 2;
	hdr3->cps_hi = 0;
	hdr3->cps_lo = 0;
	hdr3->spb = 0;
	hdr3->rsb = 0;
	hdr3->pi = 0;
	hdr3->spare = 0;
	hdr3->dummy = 1;
	data[4] = 0x0;
	data[5] = 0x2b;
	data[6] = 0x2b;
	data[7] = 0x2b;

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data[0], sizeof(data), *fn, &meas);

	request_dl_rlc_block(ul_tbf, fn);

	check_tbf(ul_tbf);
	OSMO_ASSERT(ul_tbf->ul_ack_state_is(GPRS_RLCMAC_UL_ACK_NONE));

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	return ul_tbf;
}
static gprs_rlcmac_ul_tbf *establish_ul_tbf_two_phase(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	uint32_t rach_fn = *fn - 51;
	uint32_t sba_fn = *fn + 52;
	uint8_t trx_no = 0;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch *pdch;
	gprs_rlcmac_bts *bts;
	RlcMacUplink_t ulreq = {0};

	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/* simulate RACH, sends an Immediate Assignment Uplink on the AGCH */
	bts_handle_rach(the_bts, 0x73, rach_fn, qta);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability2 = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.Multislot_capability.
			Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability2.
			MS_RA_capability_value[0].u.Content.Multislot_capability.
			EGPRS_multislot_class = ms_class;
	}

	send_ul_mac_block(the_bts, trx_no, ts_no, &ulreq, sba_fn);

	/* check the TBF */
	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	OSMO_ASSERT(ul_tbf != NULL);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);

	/* send packet uplink assignment */
	*fn = sba_fn;
	request_dl_rlc_block(ul_tbf, fn);

	/* send real acknowledgement */
	send_control_ack(ul_tbf);

	check_tbf(ul_tbf);

	/* send fake data */
	uint8_t data_msg[23] = {
		0x00 | 0xf << 2, /* GPRS_RLCMAC_DATA_BLOCK << 6, CV = 15 */
		uint8_t(0 | (tfi << 1)),
		uint8_t(1), /* BSN:7, E:1 */
	};

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];
	pdch->rcv_block(&data_msg[0], sizeof(data_msg), *fn, &meas);

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	return ul_tbf;
}

static void send_dl_data(BTS *the_bts, uint32_t tlli, const char *imsi,
	const uint8_t *data, unsigned data_size)
{
	GprsMs *ms, *ms2;

	ms = the_bts->ms_store().get_ms(tlli, 0, imsi);

	gprs_rlcmac_dl_tbf::handle(the_bts->bts_data(), tlli, 0, imsi, 0, 0,
		1000, data, data_size);

	ms = the_bts->ms_by_imsi(imsi);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->dl_tbf() != NULL);

	if (imsi[0] && strcmp(imsi, "000") != 0) {
		ms2 = the_bts->ms_by_tlli(tlli);
		OSMO_ASSERT(ms == ms2);
	}
}

static void transmit_dl_data(BTS *the_bts, uint32_t tlli, uint32_t *fn,
	uint8_t slots = 0xff)
{
	gprs_rlcmac_dl_tbf *dl_tbf;
	GprsMs *ms;
	unsigned ts_no;

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms);
	dl_tbf = ms->dl_tbf();
	OSMO_ASSERT(dl_tbf);

	while (dl_tbf->have_data()) {
		uint8_t bn = fn2bn(*fn);
		for (ts_no = 0 ; ts_no < 8; ts_no += 1) {
			if (!(slots & (1 << ts_no)))
				continue;
			gprs_rlcmac_rcv_rts_block(the_bts->bts_data(),
				dl_tbf->trx->trx_no, ts_no,
				*fn, bn);
		}
		*fn = fn_add_blocks(*fn, 1);
	}
}

static inline void print_ta_tlli(const gprs_rlcmac_ul_tbf *ul_tbf, bool print_ms)
{
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());
	if (print_ms)
		fprintf(stderr, "Got MS: TLLI = 0x%08x, TA = %d\n", ul_tbf->ms()->tlli(), ul_tbf->ms()->ta());
}

static void test_tbf_single_phase()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = DUMMY_FN; /* 17,25,9 */
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint16_t qta = 31;
	gprs_rlcmac_ul_tbf *ul_tbf;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no);

	ul_tbf = establish_ul_tbf_single_phase(&the_bts, ts_no, tlli, &fn, qta);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, (const uint8_t *)"TEST", 4);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_egprs_two_phase_puan(void)
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	gprs_rlcmac_bts *bts;
	uint8_t egprs_ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t test_data[256];

	fprintf(stderr, "=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;
	bts = the_bts.bts_data();
	bts->ws_base = 128;
	bts->ws_pdch = 64;

	ul_tbf = establish_ul_tbf(&the_bts, ts_no, tlli, &fn, qta, ms_class, egprs_ms_class);
	/* Function to generate URBB with no length */
	ul_tbf = establish_ul_tbf_two_phase_puan_URBB_no_length(&the_bts, ts_no, tlli, &fn,
		qta, ms_class, egprs_ms_class, ul_tbf);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	static_cast<gprs_rlc_ul_window *>(ul_tbf->window())->reset_state();
	/* Function to generate URBB with length */
	ul_tbf = establish_ul_tbf_two_phase_puan_URBB_with_length(&the_bts, ts_no, tlli, &fn,
		qta, ms_class, egprs_ms_class, ul_tbf);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	static_cast<gprs_rlc_ul_window *>(ul_tbf->window())->reset_state();
	/* Function to generate CRBB */
	bts->ws_base = 128;
	bts->ws_pdch = 64;
	ul_tbf = establish_ul_tbf_two_phase_puan_CRBB(&the_bts, ts_no, tlli, &fn,
		qta, ms_class, egprs_ms_class);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	fprintf(stderr, "=== end %s ===\n", __func__);
}
/*
 * Trigger rach for single block
 */
static void test_immediate_assign_rej_single_block()
{
	BTS the_bts;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	int ts_no = 7;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	the_bts.bts_data()->trx[0].pdch[ts_no].disable();

	uint32_t rach_fn = fn - 51;

	int rc = 0;

	/*
	 * simulate RACH, sends an Immediate Assignment
	 * Uplink reject on the AGCH
	 */
	rc = bts_handle_rach(&the_bts, 0x70, rach_fn, qta);

	OSMO_ASSERT(rc == -EINVAL);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

/*
 * Trigger rach till resources(USF) exhaust
 */
static void test_immediate_assign_rej_multi_block()
{
	BTS the_bts;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	int ts_no = 7;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	uint32_t rach_fn = fn - 51;

	int rc = 0;

	/*
	 * simulate RACH, sends an Immediate Assignment Uplink
	 * reject on the AGCH
	 */
	rc = bts_handle_rach(&the_bts, 0x78, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x79, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7a, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7b, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7c, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7d, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7e, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7f, rach_fn, qta);

	OSMO_ASSERT(rc == -EBUSY);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_immediate_assign_rej()
{
	test_immediate_assign_rej_multi_block();
	test_immediate_assign_rej_single_block();
}

static void test_tbf_two_phase()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, 0);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, (const uint8_t *)"TEST", 4);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static inline void print_ms(const GprsMs *ms, bool old)
{
	fprintf(stderr, "%s MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %zu\n",
		old ? "Old" : "New", ms->tlli(), ms->ta(), ms->imsi(), ms->llc_queue()->size());
}

static void test_tbf_ra_update_rach()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli1 = 0xf1223344;
	uint32_t tlli2 = 0xf5667788;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	GprsMs *ms, *ms1, *ms2;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	print_ta_tlli(ul_tbf, false);

	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"RAU_ACCEPT", 10);
	print_ms(ms1, true);

	/* Send Packet Downlink Assignment to MS */
	request_dl_rlc_block(ul_tbf, &fn);

	/* Ack it */
	send_control_ack(ul_tbf);

	/* Make sure the RAU Accept gets sent to the MS */
	OSMO_ASSERT(ms1->llc_queue()->size() == 1);
	transmit_dl_data(&the_bts, tlli1, &fn);
	OSMO_ASSERT(ms1->llc_queue()->size() == 0);

	/* Now establish a new TBF for the RA UPDATE COMPLETE (new TLLI) */
	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli2, &fn, qta,
		ms_class, 0);

	ms2 = ul_tbf->ms();

	/* The PCU cannot know yet, that both TBF belong to the same MS */
	OSMO_ASSERT(ms1 != ms2);
	print_ms(ms1, true);

	/* Send some downlink data along with the new TLLI and the IMSI so that
	 * the PCU can see, that both MS objects belong to same MS */
	send_dl_data(&the_bts, tlli2, imsi, (const uint8_t *)"DATA", 4);

	ms = the_bts.ms_by_imsi(imsi);
	OSMO_ASSERT(ms == ms2);

	print_ms(ms2, false);

	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms == NULL);
	ms = the_bts.ms_by_tlli(tlli2);
	OSMO_ASSERT(ms == ms2);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_dl_flow_and_rach_two_phase()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli1 = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_dl_tbf *dl_tbf;
	GprsMs *ms, *ms1, *ms2;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 1);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	print_ta_tlli(ul_tbf, false);

	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 1 *************", 20);
	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 2 *************", 20);
	print_ms(ms1, true);

	OSMO_ASSERT(ms1->llc_queue()->size() == 2);
	dl_tbf = ms1->dl_tbf();
	OSMO_ASSERT(dl_tbf != NULL);

	/* Get rid of old UL TBF */
	tbf_free(ul_tbf);
	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms1 == ms);

	/* Now establish a new UL TBF, this will consume one LLC packet */
	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms2 = ul_tbf->ms();
	print_ms(ms2, false);

	/* This should be the same MS object */
	OSMO_ASSERT(ms2 == ms1);

	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms2 == ms);

	/* A DL TBF should still exist */
	OSMO_ASSERT(ms->dl_tbf());

	/* No queued packets should be lost */
	OSMO_ASSERT(ms->llc_queue()->size() == 2);

	fprintf(stderr, "=== end %s ===\n", __func__);
}


static void test_tbf_dl_flow_and_rach_single_phase()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli1 = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_dl_tbf *dl_tbf;
	GprsMs *ms, *ms1, *ms2;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 1);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	print_ta_tlli(ul_tbf, false);

	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 1 *************", 20);
	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 2 *************", 20);
	print_ms(ms1, true);

	OSMO_ASSERT(ms1->llc_queue()->size() == 2);
	dl_tbf = ms1->dl_tbf();
	OSMO_ASSERT(dl_tbf != NULL);

	/* Get rid of old UL TBF */
	tbf_free(ul_tbf);
	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms1 == ms);

	/* Now establish a new UL TBF */
	ul_tbf = establish_ul_tbf_single_phase(&the_bts, ts_no, tlli1, &fn, qta);

	ms2 = ul_tbf->ms();
	print_ms(ms2, false);

	/* There should be a different MS object */
	OSMO_ASSERT(ms2 != ms1);

	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms2 == ms);
	OSMO_ASSERT(ms1 != ms);

	/* DL TBF should be removed */
	OSMO_ASSERT(!ms->dl_tbf());

	/* No queued packets should be lost */
	OSMO_ASSERT(ms->llc_queue()->size() == 2);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_dl_reuse()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli1 = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_dl_tbf *dl_tbf1, *dl_tbf2;
	GprsMs *ms1, *ms2;
	unsigned i;
	RlcMacUplink_t ulreq = {0};

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 1);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	print_ta_tlli(ul_tbf, false);

	/* Send some LLC frames */
	for (i = 0; i < 40; i++) {
		char buf[32];
		int rc;

		rc = snprintf(buf, sizeof(buf), "LLC PACKET %02i", i);
		OSMO_ASSERT(rc > 0);

		send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)buf, rc);
	}

	print_ms(ms1, true);

	/* Send Packet Downlink Assignment to MS */
	request_dl_rlc_block(ul_tbf, &fn);

	/* Ack it */
	send_control_ack(ul_tbf);

	/* Transmit all data */
	transmit_dl_data(&the_bts, tlli1, &fn);
	OSMO_ASSERT(ms1->llc_queue()->size() == 0);
	OSMO_ASSERT(ms1->dl_tbf());
	OSMO_ASSERT(ms1->dl_tbf()->state_is(GPRS_RLCMAC_FINISHED));

	dl_tbf1 = ms1->dl_tbf();

	/* Send some LLC frames */
	for (i = 0; i < 10; i++) {
		char buf[32];
		int rc;

		rc = snprintf(buf, sizeof(buf), "LLC PACKET %02i (TBF 2)", i);
		OSMO_ASSERT(rc > 0);

		send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)buf, rc);
	}

	/* Fake Final DL Ack/Nack */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_DOWNLINK_ACK_NACK;
	Packet_Downlink_Ack_Nack_t *ack = &ulreq.u.Packet_Downlink_Ack_Nack;

	ack->PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ack->DOWNLINK_TFI = dl_tbf1->tfi();
	ack->Ack_Nack_Description.FINAL_ACK_INDICATION = 1;

	send_ul_mac_block(&the_bts, 0, dl_tbf1->poll_ts, &ulreq, dl_tbf1->poll_fn);

	OSMO_ASSERT(dl_tbf1->state_is(GPRS_RLCMAC_WAIT_RELEASE));

	request_dl_rlc_block(dl_tbf1, &fn);

	ms2 = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms2 == ms1);
	OSMO_ASSERT(ms2->dl_tbf());
	OSMO_ASSERT(ms2->dl_tbf()->state_is(GPRS_RLCMAC_ASSIGN));

	dl_tbf2 = ms2->dl_tbf();

	OSMO_ASSERT(dl_tbf1 != dl_tbf2);

	send_control_ack(dl_tbf1);
	OSMO_ASSERT(dl_tbf2->state_is(GPRS_RLCMAC_FLOW));

	/* Transmit all data */
	transmit_dl_data(&the_bts, tlli1, &fn);
	OSMO_ASSERT(ms2->llc_queue()->size() == 0);
	OSMO_ASSERT(ms2->dl_tbf());
	OSMO_ASSERT(ms2->dl_tbf()->state_is(GPRS_RLCMAC_FINISHED));

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_gprs_egprs()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	uint8_t ms_class = 45;
	int rc = 0;
	uint32_t tlli = 0xc0006789;
	const char *imsi = "001001123456789";
	unsigned delay_csec = 1000;

	uint8_t buf[256] = {0};

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->nsi = gprs_ns2_instantiate(tall_pcu_ctx, gprs_ns_prim_cb, NULL);
	if (!bts->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		abort();
	}

	setup_bts(&the_bts, ts_no);

	/* EGPRS-only */
	bts->egprs_enabled = 1;

	gprs_bssgp_init(bts, 3234, 3234, 1, 1, false, 0, 0, 0);

	/* Does not support EGPRS */
	rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
		delay_csec, buf, sizeof(buf));

	OSMO_ASSERT(rc == -EBUSY);
	fprintf(stderr, "=== end %s ===\n", __func__);

	gprs_bssgp_destroy(bts);
}

static inline void ws_check(gprs_rlcmac_dl_tbf *dl_tbf, const char *test, uint8_t exp_slots, uint16_t exp_ws,
			    bool free, bool end)
{
	gprs_rlcmac_bts *bts = dl_tbf->bts->bts_data();
	if (!dl_tbf) {
		fprintf(stderr, "%s(): FAILED (NULL TBF)\n", test);
		return;
	}

	fprintf(stderr, "DL TBF slots: 0x%02x, N: %d, WS: %d",
		dl_tbf->dl_slots(),
		pcu_bitcount(dl_tbf->dl_slots()),
		dl_tbf->window_size());

	if (pcu_bitcount(dl_tbf->dl_slots()) != exp_slots || dl_tbf->window_size() != exp_ws)
		fprintf(stderr, "%s(): DL TBF FAILED: dl_slots = %u (exp. %u), WS = %u (exp. %u)",
			test, pcu_bitcount(dl_tbf->dl_slots()), 4, dl_tbf->window_size(), 128 + 4 * 64);

	fprintf(stderr, "\n");

	if (free)
		tbf_free(dl_tbf);

	if (end) {
		fprintf(stderr, "=== end %s ===\n", test);
		gprs_bssgp_destroy(bts);
	}
}

static void test_tbf_ws()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	GprsMs *ms;
	uint8_t ts_no = 4;
	uint8_t ms_class = 12;
	gprs_rlcmac_dl_tbf *dl_tbf;

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->nsi = gprs_ns2_instantiate(tall_pcu_ctx, gprs_ns_prim_cb, NULL);
	if (!bts->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		abort();
	}

	setup_bts(&the_bts, ts_no);

	bts->ws_base = 128;
	bts->ws_pdch = 64;
	bts->alloc_algorithm = alloc_algorithm_b;
	bts->trx[0].pdch[2].enable();
	bts->trx[0].pdch[3].enable();
	bts->trx[0].pdch[4].enable();
	bts->trx[0].pdch[5].enable();

	gprs_bssgp_init(bts, 4234, 4234, 1, 1, false, 0, 0, 0);

	/* Does no support EGPRS */
	ms = the_bts.ms_alloc(ms_class, 0);
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, 0, false);

	ws_check(dl_tbf, __func__, 4, 64, true, false);

	/* EGPRS-only */
	bts->egprs_enabled = 1;

	/* Does support EGPRS */
	ms = the_bts.ms_alloc(ms_class, ms_class);
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, 0, false);

	ws_check(dl_tbf, __func__, 4, 128 + 4 * 64, true, true);
}

static void test_tbf_update_ws(void)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	GprsMs *ms;
	uint8_t ts_no = 4;
	uint8_t ms_class = 11;
	gprs_rlcmac_dl_tbf *dl_tbf;

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->nsi = gprs_ns2_instantiate(tall_pcu_ctx, gprs_ns_prim_cb, NULL);
	if (!bts->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		abort();
	}

	setup_bts(&the_bts, ts_no);

	bts->ws_base = 128;
	bts->ws_pdch = 64;
	bts->alloc_algorithm = alloc_algorithm_b;
	bts->trx[0].pdch[2].enable();
	bts->trx[0].pdch[3].enable();
	bts->trx[0].pdch[4].enable();
	bts->trx[0].pdch[5].enable();

	gprs_bssgp_init(bts, 5234, 5234, 1, 1, false, 0, 0, 0);

	/* EGPRS-only */
	bts->egprs_enabled = 1;

	/* Does support EGPRS */
	ms = the_bts.ms_alloc(ms_class, ms_class);
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, 0, true);

	ws_check(dl_tbf, __func__, 1, 128 + 1 * 64, false, false);

	dl_tbf->update();

	/* window size should be 384 */
	ws_check(dl_tbf, __func__, 4, 128 + 4 * 64, true, true);
}

static void test_tbf_puan_urbb_len(void)
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	uint8_t egprs_ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t test_data[256];

	fprintf(stderr, "=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = puan_urbb_len_issue(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static gprs_rlcmac_ul_tbf *tbf_li_decoding(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta,
	uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	uint32_t rach_fn = *fn - 51;
	uint32_t sba_fn = *fn + 52;
	uint8_t trx_no = 0;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch *pdch;
	gprs_rlcmac_bts *bts;
	RlcMacUplink_t ulreq = {0};
	struct gprs_rlc_ul_header_egprs_3 *egprs3  = NULL;
	Packet_Resource_Request_t *presreq = NULL;
	MS_Radio_Access_capability_t *pmsradiocap = NULL;
	Multislot_capability_t *pmultislotcap = NULL;

	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/*
	 * simulate RACH, this sends an Immediate
	 * Assignment Uplink on the AGCH
	 */
	bts_handle_rach(the_bts, 0x73, rach_fn, qta);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	presreq = &ulreq.u.Packet_Resource_Request;
	presreq->PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	presreq->ID.UnionType = 1; /* != 0 */
	presreq->ID.u.TLLI = tlli;
	presreq->Exist_MS_Radio_Access_capability2 = 1;
	pmsradiocap = &presreq->MS_Radio_Access_capability2;
	pmsradiocap->Count_MS_RA_capability_value = 1;
	pmsradiocap->MS_RA_capability_value[0].u.Content.
		Exist_Multislot_capability = 1;
	pmultislotcap = &pmsradiocap->MS_RA_capability_value[0].
		u.Content.Multislot_capability;

	pmultislotcap->Exist_GPRS_multislot_class = 1;
	pmultislotcap->GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		pmultislotcap->Exist_EGPRS_multislot_class = 1;
		pmultislotcap->EGPRS_multislot_class = ms_class;
	}

	send_ul_mac_block(the_bts, trx_no, ts_no, &ulreq, sba_fn);

	/* check the TBF */
	ul_tbf = the_bts->ul_tbf_by_tfi(tfi, trx_no, ts_no);
	OSMO_ASSERT(ul_tbf);
	OSMO_ASSERT(ul_tbf->ta() == qta / 4);

	/* send packet uplink assignment */
	*fn = sba_fn;
	request_dl_rlc_block(ul_tbf, fn);

	/* send real acknowledgement */
	send_control_ack(ul_tbf);

	check_tbf(ul_tbf);

	uint8_t data_msg[49] = {0};

	pdch = &the_bts->bts_data()->trx[trx_no].pdch[ts_no];

	ms = the_bts->ms_by_tlli(tlli);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->ta() == qta/4);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

	egprs3 = (struct gprs_rlc_ul_header_egprs_3 *) data_msg;
	egprs3->si = 0;
	egprs3->r = 1;
	egprs3->cv = 7;
	egprs3->tfi_hi = tfi & 0x03;
	egprs3->tfi_lo = (tfi & 0x1c) >> 2;
	egprs3->bsn1_hi = 0;
	egprs3->bsn1_lo = 0;
	egprs3->cps_hi = 1;
	data_msg[3] = 0xff;
	egprs3->pi = 0;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 0;
	egprs3->pi = 0;
	pdch->rcv_block(data_msg, 49, *fn, &meas);

	egprs3->bsn1_hi = 1;
	egprs3->bsn1_lo = 0;
	data_msg[3] = 0x7f;
	egprs3->cps_lo = 1;
	egprs3->rsb = 0;
	egprs3->spb = 0;
	egprs3->pi = 0;
	data_msg[4] = 0x2;
	data_msg[5] = 0x0;
	pdch->rcv_block(data_msg, 49, *fn, &meas);

	OSMO_ASSERT(ul_tbf->m_llc.m_index == 43);

	return ul_tbf;
}

static void test_tbf_li_decoding(void)
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	uint8_t egprs_ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t test_data[256];

	fprintf(stderr, "=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = tbf_li_decoding(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	fprintf(stderr, "=== end %s ===\n", __func__);
}

/*
 * Test that a bit within the uncompressed bitmap whose BSN is not within
 * the transmit window shall be ignored. See section 9.1.8.2.4 of 44.060
 * version 7.27.0 Release 7.
 */
static void test_tbf_epdan_out_of_rx_window(void)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ms_class = 11;
	uint8_t egprs_ms_class = 11;
	uint8_t trx_no;
	uint32_t tlli = 0xffeeddcc;
	gprs_rlcmac_dl_tbf *dl_tbf;
	int ts_no = 4;
	bitvec *block;
	uint8_t bits_data[RLC_EGPRS_MAX_WS/8];
	bitvec bits;
	int bsn_begin, bsn_end;
	EGPRS_PD_AckNack_t *ack_nack;
	RlcMacUplink_t ul_control_block;
	gprs_rlc_v_b *prlcmvb;
	gprs_rlc_dl_window *prlcdlwindow;
	int rc;

	memset(&ul_control_block, 0, sizeof(RlcMacUplink_t));

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	OSMO_ASSERT(osmo_tdef_set(bts->T_defs_pcu, -2031, 200, OSMO_TDEF_MS) == 0);
	bts->egprs_enabled = 1;
	/* ARQ II */
	bts->dl_arq_type = EGPRS_ARQ2;

	/*
	 * Simulate a message captured during over-the-air testing,
	 * where the following values were observed:
	 * v_a = 1176, vs = 1288, max sns = 2048, window size = 480.
	 */
	uint8_t data_msg[23] = {0x40, 0x20, 0x0b, 0xff, 0xd1,
				0x61, 0x00, 0x3e, 0x0e, 0x51, 0x9f,
				0xff, 0xff, 0xfb, 0x80, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	dl_tbf = create_dl_tbf(&the_bts, ms_class, egprs_ms_class, &trx_no);
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);
	prlcdlwindow = static_cast<gprs_rlc_dl_window *>(dl_tbf->window());
	prlcmvb = &prlcdlwindow->m_v_b;
	prlcdlwindow->m_v_s = 1288;
	prlcdlwindow->m_v_a = 1176;
	prlcdlwindow->set_sns(2048);
	prlcdlwindow->set_ws(480);
	prlcmvb->mark_unacked(1176);
	prlcmvb->mark_unacked(1177);
	prlcmvb->mark_unacked(1286);
	prlcmvb->mark_unacked(1287);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	block = bitvec_alloc(23, tall_pcu_ctx);

	bitvec_unpack(block, data_msg);

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	rc = decode_gsm_rlcmac_uplink(block, &ul_control_block);
	OSMO_ASSERT(rc == 0);

	ack_nack = &ul_control_block.u.Egprs_Packet_Downlink_Ack_Nack;

	OSMO_ASSERT(prlcmvb->is_unacked(1176));
	OSMO_ASSERT(prlcmvb->is_unacked(1177));
	OSMO_ASSERT(prlcmvb->is_unacked(1286));
	OSMO_ASSERT(prlcmvb->is_unacked(1287));

	Decoding::decode_egprs_acknack_bits(
		&ack_nack->EGPRS_AckNack.Desc, &bits,
		&bsn_begin, &bsn_end, prlcdlwindow);

	dl_tbf->rcvd_dl_ack(
		ack_nack->EGPRS_AckNack.Desc.FINAL_ACK_INDICATION,
		bsn_begin, &bits);

	OSMO_ASSERT(prlcmvb->is_invalid(1176));
	OSMO_ASSERT(prlcmvb->is_invalid(1177));
	OSMO_ASSERT(prlcmvb->is_acked(1286));
	OSMO_ASSERT(prlcmvb->is_acked(1287));

	bitvec_free(block);
	tbf_free(dl_tbf);
	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_egprs_two_phase_spb(void)
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	uint8_t egprs_ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t test_data[256];

	fprintf(stderr, "=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = establish_ul_tbf_two_phase_spb(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_egprs_two_phase()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint8_t ms_class = 1;
	uint8_t egprs_ms_class = 1;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t test_data[256];

	fprintf(stderr, "=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	print_ta_tlli(ul_tbf, true);
	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void establish_and_use_egprs_dl_tbf(BTS *the_bts, int mcs)
{
	unsigned i;
	uint8_t ms_class = 11;
	uint8_t egprs_ms_class = 11;
	uint32_t fn = 0;
	uint8_t trx_no;
	uint32_t tlli = 0xffeeddcc;
	uint8_t test_data[512];

	uint8_t rbb[64/8];

	gprs_rlcmac_dl_tbf *dl_tbf;

	fprintf(stderr, "Testing MCS-%d\n", mcs);

	memset(test_data, 1, sizeof(test_data));
	the_bts->bts_data()->initial_mcs_dl = mcs;

	dl_tbf = create_dl_tbf(the_bts, ms_class, egprs_ms_class, &trx_no);
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);

	for (i = 0; i < sizeof(llc_data); i++)
		llc_data[i] = i%256;

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Schedule a small LLC frame */
	dl_tbf->append_data(ms_class, 1000, test_data, 10);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Drain the queue */
	while (dl_tbf->have_data())
		/* Request to send one RLC/MAC block */
		request_dl_rlc_block(dl_tbf, &fn);

	/* Schedule a large LLC frame */
	dl_tbf->append_data(ms_class, 1000, test_data, sizeof(test_data));

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Drain the queue */
	while (dl_tbf->have_data())
		/* Request to send one RLC/MAC block */
		request_dl_rlc_block(dl_tbf, &fn);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	RCV_ACK(true, dl_tbf, rbb); /* Receive a final ACK */

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	TBF_SET_ASS_STATE_DL(dl_tbf, GPRS_RLCMAC_DL_ASS_NONE);
	check_tbf(dl_tbf);
	tbf_free(dl_tbf);
}

static gprs_rlcmac_dl_tbf *tbf_init(BTS *the_bts,
		int mcs)
{
	unsigned i;
	uint8_t ms_class = 11;
	uint8_t egprs_ms_class = 11;
	uint8_t trx_no;
	uint32_t tlli = 0xffeeddcc;
	uint8_t test_data[512];

	gprs_rlcmac_dl_tbf *dl_tbf;

	memset(test_data, 1, sizeof(test_data));
	the_bts->bts_data()->initial_mcs_dl = mcs;

	dl_tbf = create_dl_tbf(the_bts, ms_class, egprs_ms_class, &trx_no);
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);

	for (i = 0; i < sizeof(test_data); i++)
		test_data[i] = i%256;

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	/* Schedule a LLC frame
	 * passing only 100 bytes, since it is enough to construct
	 * 2 RLC data blocks. Which are enough to test Header Type 1
	 * cases
	 */
	dl_tbf->append_data(ms_class, 1000, test_data, 100);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FLOW));

	return dl_tbf;

}

static void tbf_cleanup(gprs_rlcmac_dl_tbf *dl_tbf)
{
	uint8_t rbb[64/8];

	RCV_ACK(true, dl_tbf, rbb); /* Receive a final ACK */

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	TBF_SET_ASS_STATE_DL(dl_tbf, GPRS_RLCMAC_DL_ASS_NONE);
	check_tbf(dl_tbf);
	tbf_free(dl_tbf);

}

#define NACK(tbf, x) do {					\
		gprs_rlc_dl_window *w = static_cast<gprs_rlc_dl_window *>(tbf->window());	\
		w->m_v_b.mark_nacked(x);		\
		OSMO_ASSERT(w->m_v_b.is_nacked(x));	\
	} while(0)

#define CHECK_UNACKED(tbf, cs, bsn) do {				             \
		gprs_rlc_dl_window *w = static_cast<gprs_rlc_dl_window *>(tbf->window());	\
		OSMO_ASSERT(w->m_v_b.is_unacked(bsn));	             \
		OSMO_ASSERT(mcs_chan_code(tbf->m_rlc.block(bsn)->cs_current_trans) == cs - 1); \
	} while(0)

#define CHECK_NACKED(tbf, cs, bsn) do {					             \
		gprs_rlc_dl_window *w = static_cast<gprs_rlc_dl_window *>(tbf->window());	\
		OSMO_ASSERT(w->m_v_b.is_nacked(bsn));	             \
		OSMO_ASSERT(mcs_chan_code(tbf->m_rlc.block(bsn)->cs_current_trans) == cs - 1); \
	} while(0)

#define MAKE_ACKED(m, tbf, fn, cs, check_unacked) do {			\
		m = tbf->create_dl_acked_block(fn, tbf->control_ts);	\
		OSMO_ASSERT(m);						\
		if (check_unacked)					\
			CHECK_UNACKED(tbf, cs, 0);			\
		else							\
			CHECK_NACKED(tbf, cs, 0);			\
	} while(0)

static void egprs_spb_to_normal_validation(BTS *the_bts,
		unsigned int mcs, unsigned int demanded_mcs)
{
	uint32_t fn = 0;
	gprs_rlcmac_dl_tbf *dl_tbf;
	uint16_t bsn1, bsn2, bsn3;
	struct msgb *msg;
	struct gprs_rlc_dl_header_egprs_3 *egprs3;
	struct gprs_rlc_dl_header_egprs_2 *egprs2;

	fprintf(stderr, "Testing retx for MCS %u to reseg_mcs %u\n", mcs, demanded_mcs);

	dl_tbf = tbf_init(the_bts, mcs);

	/*
	 * Table 10.4.8a.3.1 of 44.060.
	 * (MCS7, MCS9) to (MCS2, MCS3) is not handled since it is same as
	 * (MCS5, MCS6) to (MCS2, MCS3) transition
	 */
	if (!(mcs == 6 && demanded_mcs == 3))
		return;

	fn = fn_add_blocks(fn, 1);
	/* Send first RLC data block BSN 0 */
	MAKE_ACKED(msg, dl_tbf, fn, mcs, true);

	egprs2 = (struct gprs_rlc_dl_header_egprs_2 *) msg->data;
	bsn1 = (egprs2->bsn1_hi << 9) | (egprs2->bsn1_mid << 1) | (egprs2->bsn1_lo);

	NACK(dl_tbf, 0);

	OSMO_ASSERT(bsn1 == 0);

	dl_tbf->ms()->set_current_cs_dl
		(static_cast < enum CodingScheme >
			(CS4 + demanded_mcs));

	fn = fn_add_blocks(fn, 1);

	/* Send first segment with demanded_mcs */
	MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, false);
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->spb_status.block_status_dl
			== EGPRS_RESEG_FIRST_SEG_SENT);

	egprs3 = (struct gprs_rlc_dl_header_egprs_3 *) msg->data;
	OSMO_ASSERT(egprs3->spb == 2);

	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->cps == 3);

	/* Send second segment with demanded_mcs */
	MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, true);
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->spb_status.block_status_dl
			== EGPRS_RESEG_SECOND_SEG_SENT);

	egprs3 = (struct gprs_rlc_dl_header_egprs_3 *) msg->data;
	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->spb == 3);
	bsn2 = (egprs3->bsn1_hi << 9) | (egprs3->bsn1_mid << 1) | (egprs3->bsn1_lo);
	OSMO_ASSERT(bsn2 == bsn1);

	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->cps == 3);

	/* Handle (MCS3, MCS3) -> MCS6 case */
	dl_tbf->ms()->set_current_cs_dl
		(static_cast < enum CodingScheme >
			(CS4 + mcs));

	NACK(dl_tbf, 0);

	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	egprs2 = (struct gprs_rlc_dl_header_egprs_2 *) msg->data;

	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs2->cps == 0);
	bsn3 = (egprs2->bsn1_hi << 9) | (egprs2->bsn1_mid << 1) | (egprs2->bsn1_lo);
	OSMO_ASSERT(bsn3 == bsn2);

	tbf_cleanup(dl_tbf);
}

static void establish_and_use_egprs_dl_tbf_for_spb(BTS *the_bts,
		unsigned int mcs, unsigned int demanded_mcs)
{
	uint32_t fn = 0;
	gprs_rlcmac_dl_tbf *dl_tbf;
	struct msgb *msg;
	struct gprs_rlc_dl_header_egprs_3 *egprs3;

	fprintf(stderr, "Testing retx for MCS %u to reseg_mcs %u\n", mcs, demanded_mcs);

	dl_tbf = tbf_init(the_bts, mcs);

	/*
	 * Table 10.4.8a.3.1 of 44.060.
	 * (MCS7, MCS9) to (MCS2, MCS3) is not handled since it is same as
	 * (MCS5, MCS6) to (MCS2, MCS3) transition
	 */
	/* TODO: Need to support of MCS8 -> MCS6 ->MCS3 transistion
	 * Refer commit be881c028fc4da00c4046ecd9296727975c206a3
	 * dated 2016-02-07 23:45:40 (UTC)
	 */
	if (!(((mcs == 5) && (demanded_mcs == 2)) ||
		((mcs == 6) && (demanded_mcs == 3)) ||
		((mcs == 4) && (demanded_mcs == 1))))
		return;

	fn = fn_add_blocks(fn, 1);
	/* Send first RLC data block BSN 0 */
	MAKE_ACKED(msg, dl_tbf, fn, mcs, true);

	NACK(dl_tbf, 0);

	dl_tbf->ms()->set_current_cs_dl
		(static_cast < enum CodingScheme >
			(CS4 + demanded_mcs));

	fn = fn_add_blocks(fn, 1);

	/* Send first segment with demanded_mcs */
	MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, false);
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->spb_status.block_status_dl
			== EGPRS_RESEG_FIRST_SEG_SENT);

	egprs3 = (struct gprs_rlc_dl_header_egprs_3 *) msg->data;
	OSMO_ASSERT(egprs3->spb == 2);

	/* Table 10.4.8a.3.1 of 44.060 */
	switch (demanded_mcs) {
	case 3:
		OSMO_ASSERT(egprs3->cps == 3);
		break;
	case 2:
		OSMO_ASSERT(egprs3->cps == 9);
		break;
	case 1:
		OSMO_ASSERT(egprs3->cps == 11);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}

	/* Send second segment with demanded_mcs */
	MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, true);
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->spb_status.block_status_dl
			== EGPRS_RESEG_SECOND_SEG_SENT);

	egprs3 = (struct gprs_rlc_dl_header_egprs_3 *) msg->data;
	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->spb == 3);

	/* Table 10.4.8a.3.1 of 44.060 */
	switch (demanded_mcs) {
	case 3:
		OSMO_ASSERT(egprs3->cps == 3);
		break;
	case 2:
		OSMO_ASSERT(egprs3->cps == 9);
		break;
	case 1:
		OSMO_ASSERT(egprs3->cps == 11);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
	tbf_cleanup(dl_tbf);
}

static void establish_and_use_egprs_dl_tbf_for_retx(BTS *the_bts,
		unsigned int mcs, unsigned int demanded_mcs)
{
	uint32_t fn = 0;
	gprs_rlcmac_dl_tbf *dl_tbf;
	struct msgb *msg;

	fprintf(stderr, "Testing retx for MCS %u - %u\n", mcs, demanded_mcs);

	dl_tbf = tbf_init(the_bts, mcs);

	/* For MCS reduction cases like MCS9->MCS6, MCS7->MCS5
	 * The MCS transition are referred from table Table 8.1.1.2
	 * of TS 44.060
	 */
	/* TODO: Need to support of MCS8 -> MCS6 transistion
	 * Refer commit be881c028fc4da00c4046ecd9296727975c206a3
	 * dated 2016-02-07 23:45:40 (UTC)
	 */
	if (((mcs == 9) && (demanded_mcs < 9)) ||
		((mcs == 7) && (demanded_mcs < 7))) {
		fn = fn_add_blocks(fn, 1);
		/* Send 2 RLC data block */
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);
		CHECK_UNACKED(dl_tbf, mcs, 1);

		NACK(dl_tbf, 0);
		NACK(dl_tbf, 1);

		/* Set the demanded MCS to demanded_mcs */
		dl_tbf->ms()->set_current_cs_dl
			(static_cast < enum CodingScheme >
				(CS4 + demanded_mcs));

		fn = fn_add_blocks(fn, 1);
		/* Retransmit the first RLC data block with demanded_mcs */
		MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, true);
		CHECK_NACKED(dl_tbf, mcs, 1);

		fn = fn_add_blocks(fn, 1);
		/* Retransmit the second RLC data block with demanded_mcs */
		MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, true);
		CHECK_UNACKED(dl_tbf, demanded_mcs, 1);
	} else if (((mcs == 5) && (demanded_mcs > 6)) ||
		((mcs == 6) && (demanded_mcs > 8))) {
		fn = fn_add_blocks(fn, 1);
		/* Send first RLC data block BSN 0 */
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);

		fn = fn_add_blocks(fn, 1);
		/* Send second RLC data block BSN 1 */
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);
		CHECK_UNACKED(dl_tbf, mcs, 1);

		NACK(dl_tbf, 0);
		NACK(dl_tbf, 1);

		dl_tbf->ms()->set_current_cs_dl
			(static_cast < enum CodingScheme >
				(CS4 + demanded_mcs));

		fn = fn_add_blocks(fn, 1);
		/* Send first, second RLC data blocks with demanded_mcs */
		MAKE_ACKED(msg, dl_tbf, fn, demanded_mcs, true);
		CHECK_UNACKED(dl_tbf, demanded_mcs, 1);
	} else if (mcs > 6) {
		/* No Mcs change cases are handled here for mcs > MCS6*/
		fn = fn_add_blocks(fn, 1);
		/* Send first,second RLC data blocks */
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);
		CHECK_UNACKED(dl_tbf, mcs, 1);

		NACK(dl_tbf, 0);
		NACK(dl_tbf, 1);

		fn = fn_add_blocks(fn, 1);
		/* Send first,second RLC data blocks with demanded_mcs*/
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);
		CHECK_UNACKED(dl_tbf, mcs, 1);
	} else {

		/* No MCS change cases are handled here for mcs <= MCS6*/
		fn = fn_add_blocks(fn, 1);
		/* Send first RLC data block */
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);

		NACK(dl_tbf, 0);

		fn = fn_add_blocks(fn, 1);
		/* Send first RLC data block with demanded_mcs */
		MAKE_ACKED(msg, dl_tbf, fn, mcs, true);
	}

	tbf_cleanup(dl_tbf);
}

static void test_tbf_egprs_retx_dl(void)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->cs_downgrade_threshold = 0;
	setup_bts(&the_bts, ts_no);
	OSMO_ASSERT(osmo_tdef_set(bts->T_defs_pcu, -2031, 200, OSMO_TDEF_MS) == 0);
	bts->egprs_enabled = 1;
	/* ARQ II */
	bts->dl_arq_type = EGPRS_ARQ2;


	/* First parameter is current MCS, second one is demanded_mcs */
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 6, 6);
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 1, 9);
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 2, 8);
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 5, 7);
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 6, 9);
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 7, 5);
	establish_and_use_egprs_dl_tbf_for_retx(&the_bts, 9, 6);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_egprs_spb_dl(void)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->cs_downgrade_threshold = 0;
	setup_bts(&the_bts, ts_no);
	OSMO_ASSERT(osmo_tdef_set(bts->T_defs_pcu, -2031, 200, OSMO_TDEF_MS) == 0);
	bts->egprs_enabled = 1;

	/* ARQ I resegmentation support */
	bts->dl_arq_type = EGPRS_ARQ1;

	/*
	 * First parameter is current MCS, second one is demanded_mcs
	 * currently only MCS5->MCS2, MCS6->3, MCS4->MCS1 is tested in UT
	 * rest scenarios has been integration tested
	 */
	establish_and_use_egprs_dl_tbf_for_spb(&the_bts, 6, 3);
	establish_and_use_egprs_dl_tbf_for_spb(&the_bts, 5, 2);
	establish_and_use_egprs_dl_tbf_for_spb(&the_bts, 4, 1);
	/* check MCS6->(MCS3+MCS3)->MCS6 case */
	egprs_spb_to_normal_validation(&the_bts, 6, 3);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_tbf_egprs_dl()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	int i;

	fprintf(stderr, "=== start %s ===\n", __func__);

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	OSMO_ASSERT(osmo_tdef_set(bts->T_defs_pcu, -2031, 200, OSMO_TDEF_MS) == 0);
	bts->egprs_enabled = 1;
	/* ARQ II */
	bts->dl_arq_type = EGPRS_ARQ2;

	for (i = 1; i <= 9; i++)
		establish_and_use_egprs_dl_tbf(&the_bts, i);

	fprintf(stderr, "=== end %s ===\n", __func__);
}



static void test_packet_access_rej_prr_no_other_tbfs()
{
	BTS the_bts;
	uint32_t fn = 2654218;
	int ts_no = 7;
	uint8_t trx_no = 0;
	uint32_t tlli = 0xffeeddcc;
	struct gprs_rlcmac_ul_tbf *ul_tbf = NULL;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	int rc = 0;

	ul_tbf = handle_tbf_reject(the_bts.bts_data(), NULL, tlli,
				trx_no, ts_no);

	OSMO_ASSERT(ul_tbf != 0);

	/* trigger packet access reject */
	uint8_t bn = fn2bn(fn);

	rc = gprs_rlcmac_rcv_rts_block(the_bts.bts_data(),
		trx_no, ts_no, fn, bn);

	OSMO_ASSERT(rc == 0);

	ul_tbf->handle_timeout();

	fprintf(stderr, "=== end %s ===\n", __func__);
}

static void test_packet_access_rej_prr()
{
	BTS the_bts;
	uint32_t fn = 2654218;
	uint16_t qta = 31;
	int ts_no = 7;
	uint8_t trx_no = 0;
	RlcMacUplink_t ulreq = {0};
	Packet_Resource_Request_t *presreq = NULL;
	uint8_t ms_class = 11;
	uint8_t egprs_ms_class = 11;
	uint32_t rach_fn = fn - 51;
	uint32_t sba_fn = fn + 52;
	uint32_t tlli = 0xffeeddcc;
	MS_Radio_Access_capability_t *pmsradiocap = NULL;
	Multislot_capability_t *pmultislotcap = NULL;

	fprintf(stderr, "=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	int rc = 0;

	/*
	 * Trigger rach till resources(USF) exhaust
	 */
	rc = bts_handle_rach(&the_bts, 0x78, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x79, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7a, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7b, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7c, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7d, rach_fn, qta);
	rc = bts_handle_rach(&the_bts, 0x7e, rach_fn, qta);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	presreq = &ulreq.u.Packet_Resource_Request;
	presreq->PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	presreq->ID.UnionType = 1; /* != 0 */
	presreq->ID.u.TLLI = tlli;
	presreq->Exist_MS_Radio_Access_capability2 = 1;
	pmsradiocap = &presreq->MS_Radio_Access_capability2;
	pmsradiocap->Count_MS_RA_capability_value = 1;
	pmsradiocap->MS_RA_capability_value[0].u.Content.
		Exist_Multislot_capability = 1;
	pmultislotcap = &pmsradiocap->MS_RA_capability_value[0].
		u.Content.Multislot_capability;

	pmultislotcap->Exist_GPRS_multislot_class = 1;
	pmultislotcap->GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		pmultislotcap->Exist_EGPRS_multislot_class = 1;
		pmultislotcap->EGPRS_multislot_class = egprs_ms_class;
	}

	send_ul_mac_block(&the_bts, trx_no, ts_no, &ulreq, sba_fn);

	/* trigger packet access reject */
	uint8_t bn = fn2bn(fn);

	rc = gprs_rlcmac_rcv_rts_block(the_bts.bts_data(),
		trx_no, ts_no, fn, bn);

	OSMO_ASSERT(rc == 0);

	fprintf(stderr, "=== end %s ===\n", __func__);
}

void test_packet_access_rej_epdan()
{
	BTS the_bts;
	uint32_t tlli = 0xffeeddcc;
	static uint8_t exp[] = { 0x40, 0x84, 0x7f, 0xf7, 0x6e, 0xe6, 0x41, 0x4b,
				 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
				 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
	};

	fprintf(stderr, "=== start %s ===\n", __func__);
	setup_bts(&the_bts, 4);
	static gprs_rlcmac_dl_tbf *dl_tbf = tbf_init(&the_bts, 1);

	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);

	struct msgb *msg = dl_tbf->create_packet_access_reject();

	fprintf(stderr, "packet reject: %s\n",
			osmo_hexdump(msg->data, 23));

	if (!msgb_eq_data_print(msg, exp, GSM_MACBLOCK_LEN))
		fprintf(stderr, "%s test failed!\n", __func__);

	fprintf(stderr, "=== end %s ===\n", __func__);

}


int main(int argc, char **argv)
{
	struct vty_app_info pcu_vty_info = {0};

	tall_pcu_ctx = talloc_named_const(NULL, 1, "moiji-mobile TbfTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	bssgp_set_log_ss(DBSSGP);
	log_parse_category_mask(osmo_stderr_target, "DRLCMAC,1:DRLCMACDATA,3:DRLCMACDL,3:DRLCMACUL,3:"
				"DRLCMACSCHED,1:DRLCMACMEAS,3:DNS,3:DBSSGP,3:DPCU,5:"
				"DL1IF,6:DTBF,1:DTBFUL,1:DTBFDL,1:DLGLOBAL,2:");

	vty_init(&pcu_vty_info);
	pcu_vty_init();

	/* Initialize shared UL measurements */
	meas.set_link_qual(12);
	meas.set_rssi(31);

	test_tbf_base();
	test_tbf_tlli_update();
	test_tbf_final_ack(TEST_MODE_STANDARD);
	test_tbf_final_ack(TEST_MODE_REVERSE_FREE);
	test_tbf_delayed_release();
	test_tbf_imsi();
	test_tbf_exhaustion();
	test_tbf_dl_llc_loss();
	test_tbf_single_phase();
	test_tbf_two_phase();
	test_tbf_ra_update_rach();
	test_tbf_dl_flow_and_rach_two_phase();
	test_tbf_dl_flow_and_rach_single_phase();
	test_tbf_dl_reuse();
	test_tbf_gprs_egprs();
	test_tbf_ws();
	test_tbf_egprs_two_phase();
	test_tbf_egprs_two_phase_spb();
	test_tbf_egprs_dl();
	test_tbf_egprs_retx_dl();
	test_tbf_egprs_spb_dl();
	test_tbf_puan_urbb_len();
	test_tbf_update_ws();
	test_tbf_li_decoding();
	test_tbf_epdan_out_of_rx_window();
	test_immediate_assign_rej();
	test_tbf_egprs_two_phase_puan();
	test_packet_access_rej_epdan();
	test_packet_access_rej_prr();
	test_packet_access_rej_prr_no_other_tbfs();

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
