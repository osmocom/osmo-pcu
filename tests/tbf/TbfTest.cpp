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
#include "pcu_l1_if.h"

extern "C" {
#include "pcu_vty.h"

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vty.h>
#include <osmocom/gprs/protocol/gsm_04_60.h>
#include <osmocom/gsm/l1sap.h>
}

#include <errno.h>

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;

static void check_tbf(gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf);
	if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE))
		OSMO_ASSERT(tbf->T == 3191 || tbf->T == 3193);
	if (tbf->state_is(GPRS_RLCMAC_RELEASING))
		OSMO_ASSERT(tbf->T != 0);
}

/*
static unsigned inc_fn(fn)
{
	unsigned next_fn;

	next_fn = fn + 4;
	if ((block_nr % 3) == 2)
		next_fn ++;
	next_fn = next_fn % 2715648;

	return next_fn;
}
*/

static void test_tbf_base()
{

	printf("=== start %s ===\n", __func__);

	OSMO_ASSERT(GPRS_RLCMAC_DL_TBF == reverse(GPRS_RLCMAC_UL_TBF));
	OSMO_ASSERT(GPRS_RLCMAC_UL_TBF == reverse(GPRS_RLCMAC_DL_TBF));

	printf("=== end %s ===\n", __func__);
}

static void test_tbf_tlli_update()
{
	BTS the_bts;
	GprsMs *ms, *ms_new;

	printf("=== start %s ===\n", __func__);

	the_bts.bts_data()->alloc_algorithm = alloc_algorithm_a;
	the_bts.bts_data()->trx[0].pdch[2].enable();
	the_bts.bts_data()->trx[0].pdch[3].enable();

	/*
	 * Make a uplink and downlink allocation
	 */
	gprs_rlcmac_tbf *dl_tbf = tbf_alloc_dl_tbf(the_bts.bts_data(),
						NULL,
						0, 0, 0, 0);
	OSMO_ASSERT(dl_tbf != NULL);
	dl_tbf->update_ms(0x2342, GPRS_RLCMAC_DL_TBF);
	dl_tbf->set_ta(4);

	gprs_rlcmac_tbf *ul_tbf = tbf_alloc_ul_tbf(the_bts.bts_data(),
						dl_tbf->ms(),
						0, 0, 0, 0);
	OSMO_ASSERT(ul_tbf != NULL);
	ul_tbf->update_ms(0x2342, GPRS_RLCMAC_UL_TBF);

	ms = the_bts.ms_by_tlli(0x2342);

	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->dl_tbf() == dl_tbf);
	OSMO_ASSERT(ms->ul_tbf() == ul_tbf);

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

	printf("=== end %s ===\n", __func__);
}

static uint8_t llc_data[200];

int pcu_sock_send(struct msgb *msg)
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
	trx = &bts->trx[0];

	trx->pdch[ts_no].enable();
}

static gprs_rlcmac_dl_tbf *create_dl_tbf(BTS *the_bts, uint8_t ms_class,
	uint8_t egprs_ms_class, uint8_t *trx_no_)
{
	gprs_rlcmac_bts *bts;
	int tfi;
	uint8_t trx_no;

	gprs_rlcmac_dl_tbf *dl_tbf;

	bts = the_bts->bts_data();

	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_DL_TBF, &trx_no, -1);
	OSMO_ASSERT(tfi >= 0);
	dl_tbf = tbf_alloc_dl_tbf(bts, NULL, trx_no, ms_class, egprs_ms_class, 1);
	check_tbf(dl_tbf);

	/* "Establish" the DL TBF */
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_SEND_ASS;
	dl_tbf->set_state(GPRS_RLCMAC_FLOW);
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
	return fn % 2715648;
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

	printf("=== start %s ===\n", __func__);

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
	dl_tbf->rcvd_dl_ack(1, 1, rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	new_tbf = ms->dl_tbf();
	check_tbf(new_tbf);
	OSMO_ASSERT(new_tbf != dl_tbf);
	OSMO_ASSERT(new_tbf->tfi() == 1);
	check_tbf(dl_tbf);
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
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

	printf("=== end %s ===\n", __func__);
}

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

	uint8_t rbb[64/8];

	gprs_rlcmac_dl_tbf *dl_tbf;

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	bts->dl_tbf_idle_msec = 200;

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
	/* Receive an ACK */
	dl_tbf->rcvd_dl_ack(0, dl_tbf->m_window.v_s(), rbb);
	OSMO_ASSERT(dl_tbf->m_window.window_empty());

	/* Force sending of a single block containing an LLC dummy command */
	request_dl_rlc_block(dl_tbf, &fn);

	/* Receive an ACK */
	dl_tbf->rcvd_dl_ack(0, dl_tbf->m_window.v_s(), rbb);
	OSMO_ASSERT(dl_tbf->m_window.window_empty());

	/* Timeout (make sure fn % 52 remains valid) */
	fn += 52 * ((msecs_to_frames(bts->dl_tbf_idle_msec + 100) + 51)/ 52);
	request_dl_rlc_block(dl_tbf, &fn);

	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_FINISHED));

	/* Receive a final ACK */
	dl_tbf->rcvd_dl_ack(1, dl_tbf->m_window.v_s(), rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
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

	dl_tbf[0] = create_dl_tbf(&the_bts, ms_class, 0, &trx_no);
	dl_tbf[1] = create_dl_tbf(&the_bts, ms_class, 0, &trx_no);

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
	{
		GprsMs::Guard guard(ms2);
		dl_tbf[1]->assign_imsi("001001000000002");
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

		rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
			delay_csec, buf, sizeof(buf));

		if (rc < 0)
			break;
	}

	OSMO_ASSERT(rc == -EBUSY);
	printf("=== end %s ===\n", __func__);

	gprs_bssgp_destroy();
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

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	setup_bts(&the_bts, ts_no);
	bts->ms_idle_sec = 10; /* keep the MS object */

	gprs_bssgp_create_and_connect(bts, 33001, 0, 33001,
		1234, 1234, 1234, 1, 1, 0, 0, 0);

	/* Handle LLC frame 1 */
	memset(buf, 1, sizeof(buf));
	rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
		delay_csec, buf, sizeof(buf));
	OSMO_ASSERT(rc >= 0);

	ms = the_bts.ms_store().get_ms(0, 0, imsi);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms->dl_tbf() != NULL);

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

	while (ms->dl_tbf()->have_data()) {
		msg = ms->dl_tbf()->create_dl_acked_block(fn += 4, 7);
		fprintf(stderr, "MSG = %s\n", msgb_hexdump(msg));
		OSMO_ASSERT(msgb_length(msg) == 23);
		OSMO_ASSERT(msgb_data(msg)[10] == expected_data);
		expected_data += 1;
	}
	OSMO_ASSERT(expected_data-1 == 3);

	printf("=== end %s ===\n", __func__);

	gprs_bssgp_destroy();
}

static gprs_rlcmac_ul_tbf *establish_ul_tbf_single_phase(BTS *the_bts,
	uint8_t ts_no, uint32_t tlli, uint32_t *fn, uint16_t qta)
{
	GprsMs *ms;
	int tfi = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	uint8_t trx_no = 0;
	struct gprs_rlcmac_pdch *pdch;
	struct pcu_l1_meas meas;

	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	the_bts->rcv_rach(0x03, *fn, qta, 0, GSM_L1_BURST_TYPE_ACCESS_0);

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
	struct pcu_l1_meas meas;

	meas.set_rssi(31);

	rlc_block = bitvec_alloc(23);

	encode_gsm_rlcmac_uplink(rlc_block, ulreq);
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
	int tfi = 0, i = 0;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch *pdch;
	gprs_rlcmac_bts *bts;
	RlcMacUplink_t ulreq = {0};
	struct pcu_l1_meas meas;
	struct gprs_rlc_ul_header_egprs_3 *egprs3  = NULL;
	GprsCodingScheme cs;

	meas.set_rssi(31);
	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/*
	 * simulate RACH, this sends an Immediate
	 * Assignment Uplink on the AGCH
	 */
	the_bts->rcv_rach(0x73, rach_fn, qta);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.
		Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
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
		tfi << 1,
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
	cs = GprsCodingScheme::MCS3;
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

	OSMO_ASSERT(!strcmp(osmo_hexdump(msg1->data, msg1->data_len),
	"40 24 01 3f 3e 24 46 68 90 87 b0 06 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b "
	));

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

	OSMO_ASSERT(!strcmp(osmo_hexdump(msg1->data, msg1->data_len),
	"40 24 01 3f 3e 24 46 68 90 88 b0 06 8b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b "
	));

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
	struct pcu_l1_meas meas;
	struct gprs_rlc_ul_header_egprs_3 *egprs3  = NULL;
	GprsCodingScheme cs;

	meas.set_rssi(31);
	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/*
	 * simulate RACH, this sends an Immediate
	 * Assignment Uplink on the AGCH
	 */
	the_bts->rcv_rach(0x73, rach_fn, qta, 0, GSM_L1_BURST_TYPE_ACCESS_0);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.
			Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
			MS_RA_capability_value[0].u.Content.
			Multislot_capability.Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
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
	cs = GprsCodingScheme::MCS3;
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
			GprsCodingScheme::MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	/*
	 * TS 44.060, B.8.1
	 * second seg first, later first seg
	 */
	memset(data_msg, 0, sizeof(data_msg));

	cs = GprsCodingScheme::MCS3;
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
			GprsCodingScheme::MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	/*
	 * TS 44.060, B.8.1
	 * Error scenario with spb as 1
	 */
	cs = GprsCodingScheme::MCS3;
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

	cs = GprsCodingScheme::MCS3;
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

	cs = GprsCodingScheme::MCS3;
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
			GprsCodingScheme::MCS6);

	cs = GprsCodingScheme::MCS3;
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

	cs = GprsCodingScheme::MCS3;
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

	cs = GprsCodingScheme::MCS3;
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
			GprsCodingScheme::MCS6);
	/* Assembled MCS is MCS6. so the size is 74 */
	OSMO_ASSERT(block->len == 74);

	cs = GprsCodingScheme::MCS3;
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

	cs = GprsCodingScheme::MCS3;
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
			GprsCodingScheme::MCS6);
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
	struct pcu_l1_meas meas;
	meas.set_rssi(31);

	bts = the_bts->bts_data();

	/* needed to set last_rts_fn in the PDCH object */
	request_dl_rlc_block(bts, trx_no, ts_no, fn);

	/* simulate RACH, sends an Immediate Assignment Uplink on the AGCH */
	the_bts->rcv_rach(0x73, rach_fn, qta, 0, GSM_L1_BURST_TYPE_ACCESS_0);

	/* get next free TFI */
	tfi = the_bts->tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

	/* fake a resource request */
	ulreq.u.MESSAGE_TYPE = MT_PACKET_RESOURCE_REQUEST;
	ulreq.u.Packet_Resource_Request.PayloadType = GPRS_RLCMAC_CONTROL_BLOCK;
	ulreq.u.Packet_Resource_Request.ID.UnionType = 1; /* != 0 */
	ulreq.u.Packet_Resource_Request.ID.u.TLLI = tlli;
	ulreq.u.Packet_Resource_Request.Exist_MS_Radio_Access_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		Count_MS_RA_capability_value = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Exist_Multislot_capability = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		Exist_GPRS_multislot_class = 1;
	ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
		MS_RA_capability_value[0].u.Content.Multislot_capability.
		GPRS_multislot_class = ms_class;
	if (egprs_ms_class) {
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
			MS_RA_capability_value[0].u.Content.Multislot_capability.
			Exist_EGPRS_multislot_class = 1;
		ulreq.u.Packet_Resource_Request.MS_Radio_Access_capability.
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

static void test_tbf_single_phase()
{
	BTS the_bts;
	int ts_no = 7;
	uint32_t fn = 2654167; /* 17,25,9 */
	uint32_t tlli = 0xf1223344;
	const char *imsi = "0011223344";
	uint16_t qta = 31;
	gprs_rlcmac_ul_tbf *ul_tbf;
	GprsMs *ms;

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no);

	ul_tbf = establish_ul_tbf_single_phase(&the_bts, ts_no, tlli, &fn, qta);

	ms = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());
	fprintf(stderr, "Got MS: TLLI = 0x%08x, TA = %d\n", ms->tlli(), ms->ta());

	send_dl_data(&the_bts, tlli, imsi, (const uint8_t *)"TEST", 4);

	printf("=== end %s ===\n", __func__);
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
	GprsMs *ms;

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, 0);

	ms = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());
	fprintf(stderr, "Got MS: TLLI = 0x%08x, TA = %d\n", ms->tlli(), ms->ta());

	send_dl_data(&the_bts, tlli, imsi, (const uint8_t *)"TEST", 4);

	printf("=== end %s ===\n", __func__);
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

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 4);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());

	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"RAU_ACCEPT", 10);
	fprintf(stderr, "Old MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms1->tlli(), ms1->ta(), ms1->imsi(), ms1->llc_queue()->size());

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

	fprintf(stderr, "Old MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms1->tlli(), ms1->ta(), ms1->imsi(), ms1->llc_queue()->size());

	/* Send some downlink data along with the new TLLI and the IMSI so that
	 * the PCU can see, that both MS objects belong to same MS */
	send_dl_data(&the_bts, tlli2, imsi, (const uint8_t *)"DATA", 4);

	ms = the_bts.ms_by_imsi(imsi);
	OSMO_ASSERT(ms == ms2);

	fprintf(stderr, "New MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms2->tlli(), ms2->ta(), ms2->imsi(), ms2->llc_queue()->size());

	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms == NULL);
	ms = the_bts.ms_by_tlli(tlli2);
	OSMO_ASSERT(ms == ms2);

	printf("=== end %s ===\n", __func__);
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

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 1);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());

	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 1 *************", 20);
	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 2 *************", 20);
	fprintf(stderr, "Old MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms1->tlli(), ms1->ta(), ms1->imsi(), ms1->llc_queue()->size());

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
	fprintf(stderr, "New MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms2->tlli(), ms2->ta(), ms2->imsi(), ms2->llc_queue()->size());

	/* This should be the same MS object */
	OSMO_ASSERT(ms2 == ms1);

	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms2 == ms);

	/* A DL TBF should still exist */
	OSMO_ASSERT(ms->dl_tbf());

	/* No queued packets should be lost */
	OSMO_ASSERT(ms->llc_queue()->size() == 2);

	printf("=== end %s ===\n", __func__);
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

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 1);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());

	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 1 *************", 20);
	send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)"DATA 2 *************", 20);
	fprintf(stderr, "Old MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms1->tlli(), ms1->ta(), ms1->imsi(), ms1->llc_queue()->size());

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
	fprintf(stderr, "New MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms2->tlli(), ms2->ta(), ms2->imsi(), ms2->llc_queue()->size());

	/* There should be a different MS object */
	OSMO_ASSERT(ms2 != ms1);

	ms = the_bts.ms_by_tlli(tlli1);
	OSMO_ASSERT(ms2 == ms);
	OSMO_ASSERT(ms1 != ms);

	/* DL TBF should be removed */
	OSMO_ASSERT(!ms->dl_tbf());

	/* No queued packets should be lost */
	OSMO_ASSERT(ms->llc_queue()->size() == 2);

	printf("=== end %s ===\n", __func__);
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

	printf("=== start %s ===\n", __func__);

	setup_bts(&the_bts, ts_no, 1);

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli1, &fn, qta,
		ms_class, 0);

	ms1 = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());

	/* Send some LLC frames */
	for (i = 0; i < 40; i++) {
		char buf[32];
		int rc;

		rc = snprintf(buf, sizeof(buf), "LLC PACKET %02i", i);
		OSMO_ASSERT(rc > 0);

		send_dl_data(&the_bts, tlli1, imsi, (const uint8_t *)buf, rc);
	}

	fprintf(stderr, "Old MS: TLLI = 0x%08x, TA = %d, IMSI = %s, LLC = %d\n",
		ms1->tlli(), ms1->ta(), ms1->imsi(), ms1->llc_queue()->size());

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
	OSMO_ASSERT(ms2->dl_tbf()->state_is(GPRS_RLCMAC_WAIT_ASSIGN));

	dl_tbf2 = ms2->dl_tbf();

	OSMO_ASSERT(dl_tbf1 != dl_tbf2);

	send_control_ack(dl_tbf1);
	OSMO_ASSERT(dl_tbf2->state_is(GPRS_RLCMAC_FLOW));

	/* Transmit all data */
	transmit_dl_data(&the_bts, tlli1, &fn);
	OSMO_ASSERT(ms2->llc_queue()->size() == 0);
	OSMO_ASSERT(ms2->dl_tbf());
	OSMO_ASSERT(ms2->dl_tbf()->state_is(GPRS_RLCMAC_FINISHED));

	printf("=== end %s ===\n", __func__);
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

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	setup_bts(&the_bts, ts_no);

	/* EGPRS-only */
	bts->egprs_enabled = 1;

	gprs_bssgp_create_and_connect(bts, 33001, 0, 33001,
		1234, 1234, 1234, 1, 1, 0, 0, 0);

	/* Does not support EGPRS */
	rc = gprs_rlcmac_dl_tbf::handle(bts, tlli, 0, imsi, ms_class, 0,
		delay_csec, buf, sizeof(buf));

	OSMO_ASSERT(rc == -EBUSY);
	printf("=== end %s ===\n", __func__);

	gprs_bssgp_destroy();
}

static void test_tbf_ws()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	uint8_t ms_class = 12;
	gprs_rlcmac_dl_tbf *dl_tbf;

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	setup_bts(&the_bts, ts_no);

	bts->ws_base = 128;
	bts->ws_pdch = 64;
	bts->alloc_algorithm = alloc_algorithm_b;
	bts->trx[0].pdch[2].enable();
	bts->trx[0].pdch[3].enable();
	bts->trx[0].pdch[4].enable();
	bts->trx[0].pdch[5].enable();

	gprs_bssgp_create_and_connect(bts, 33001, 0, 33001,
		1234, 1234, 1234, 1, 1, 0, 0, 0);

	/* Does no support EGPRS */
	dl_tbf = tbf_alloc_dl_tbf(bts, NULL, 0, ms_class, 0, 0);
	OSMO_ASSERT(dl_tbf != NULL);
	fprintf(stderr, "DL TBF slots: 0x%02x, N: %d, WS: %d\n",
		dl_tbf->dl_slots(),
		pcu_bitcount(dl_tbf->dl_slots()),
		dl_tbf->window()->ws());
	OSMO_ASSERT(pcu_bitcount(dl_tbf->dl_slots()) == 4);
	OSMO_ASSERT(dl_tbf->window()->ws() == 64);
	tbf_free(dl_tbf);

	/* EGPRS-only */
	bts->egprs_enabled = 1;

	/* Does support EGPRS */
	dl_tbf = tbf_alloc_dl_tbf(bts, NULL, 0, ms_class, ms_class, 0);

	OSMO_ASSERT(dl_tbf != NULL);
	fprintf(stderr, "DL TBF slots: 0x%02x, N: %d, WS: %d\n",
		dl_tbf->dl_slots(),
		pcu_bitcount(dl_tbf->dl_slots()),
		dl_tbf->window()->ws());
	OSMO_ASSERT(pcu_bitcount(dl_tbf->dl_slots()) == 4);
	OSMO_ASSERT(dl_tbf->window()->ws() == 128 + 4 * 64);
	tbf_free(dl_tbf);

	printf("=== end %s ===\n", __func__);

	gprs_bssgp_destroy();
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
	GprsMs *ms;
	uint8_t test_data[256];

	printf("=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = puan_urbb_len_issue(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	ms = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());
	fprintf(stderr,
		"Got MS: TLLI = 0x%08x, TA = %d\n", ms->tlli(), ms->ta());

	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	printf("=== end %s ===\n", __func__);
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
	GprsMs *ms;
	uint8_t test_data[256];

	printf("=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = establish_ul_tbf_two_phase_spb(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	ms = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());
	fprintf(stderr,
		"Got MS: TLLI = 0x%08x, TA = %d\n", ms->tlli(), ms->ta());

	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	printf("=== end %s ===\n", __func__);
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
	GprsMs *ms;
	uint8_t test_data[256];

	printf("=== start %s ===\n", __func__);

	memset(test_data, 1, sizeof(test_data));

	setup_bts(&the_bts, ts_no, 4);
	the_bts.bts_data()->initial_mcs_dl = 9;
	the_bts.bts_data()->egprs_enabled = 1;

	ul_tbf = establish_ul_tbf_two_phase(&the_bts, ts_no, tlli, &fn, qta,
		ms_class, egprs_ms_class);

	ms = ul_tbf->ms();
	fprintf(stderr, "Got '%s', TA=%d\n", ul_tbf->name(), ul_tbf->ta());
	fprintf(stderr, "Got MS: TLLI = 0x%08x, TA = %d\n", ms->tlli(), ms->ta());

	send_dl_data(&the_bts, tlli, imsi, test_data, sizeof(test_data));

	printf("=== end %s ===\n", __func__);
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

	printf("Testing MCS-%d\n", mcs);

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

	/* Receive a final ACK */
	dl_tbf->rcvd_dl_ack(1, dl_tbf->m_window.v_s(), rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
	check_tbf(dl_tbf);
	tbf_free(dl_tbf);
}

static gprs_rlcmac_dl_tbf *tbf_init(BTS *the_bts,
		int mcs)
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
	uint32_t fn = 0;
	uint8_t rbb[64/8];

	/* Receive a final ACK */
	dl_tbf->rcvd_dl_ack(1, dl_tbf->m_window.v_s(), rbb);

	/* Clean up and ensure tbfs are in the correct state */
	OSMO_ASSERT(dl_tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE));
	dl_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
	check_tbf(dl_tbf);
	tbf_free(dl_tbf);

}

static void egprs_spb_to_normal_validation(BTS *the_bts,
		int mcs, int demanded_mcs)
{
	uint32_t fn = 0;
	gprs_rlcmac_dl_tbf *dl_tbf;
	uint8_t block_nr = 0;
	int index1 = 0;
	uint8_t bn;
	uint16_t bsn1, bsn2, bsn3;
	struct msgb *msg;
	struct gprs_rlc_dl_header_egprs_3 *egprs3;
	struct gprs_rlc_dl_header_egprs_2 *egprs2;

	printf("Testing retx for MCS %d to reseg_mcs %d\n", mcs, demanded_mcs);

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
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
			== mcs);

	egprs2 = (struct gprs_rlc_dl_header_egprs_2 *) msg->data;
	bsn1 = (egprs2->bsn1_hi << 9) || (egprs2->bsn1_mid << 1)
			|| (egprs2->bsn1_lo);
	dl_tbf->m_window.m_v_b.mark_nacked(0);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
	OSMO_ASSERT(bsn1 == 0);

	dl_tbf->ms()->set_current_cs_dl
		(static_cast < GprsCodingScheme::Scheme >
			(GprsCodingScheme::CS4 + demanded_mcs));

	fn = fn_add_blocks(fn, 1);

	/* Send first segment with demanded_mcs */
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
			== demanded_mcs);
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->spb_status.block_status_dl
			== EGPRS_RESEG_FIRST_SEG_SENT);

	egprs3 = (struct gprs_rlc_dl_header_egprs_3 *) msg->data;
	OSMO_ASSERT(egprs3->spb == 2);

	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->cps == 3);

	/* Send second segment with demanded_mcs */
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
			== demanded_mcs);
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->spb_status.block_status_dl
			== EGPRS_RESEG_SECOND_SEG_SENT);

	egprs3 = (struct gprs_rlc_dl_header_egprs_3 *) msg->data;
	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->spb == 3);
	bsn2 = (egprs3->bsn1_hi << 9) || (egprs3->bsn1_mid << 1) ||
			(egprs3->bsn1_lo);
	OSMO_ASSERT(bsn2 == bsn1);

	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs3->cps == 3);

	/* Handle (MCS3, MCS3) -> MCS6 case */
	dl_tbf->ms()->set_current_cs_dl
		(static_cast < GprsCodingScheme::Scheme >
			(GprsCodingScheme::CS4 + mcs));

	dl_tbf->m_window.m_v_b.mark_nacked(0);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	egprs2 = (struct gprs_rlc_dl_header_egprs_2 *) msg->data;

	/* Table 10.4.8a.3.1 of 44.060 */
	OSMO_ASSERT(egprs2->cps == 0);
	bsn3 = (egprs2->bsn1_hi << 9) || (egprs2->bsn1_mid << 1) ||
			(egprs2->bsn1_lo);
	OSMO_ASSERT(bsn3 == bsn2);

	tbf_cleanup(dl_tbf);
}
static void establish_and_use_egprs_dl_tbf_for_spb(BTS *the_bts,
		int mcs, int demanded_mcs)
{
	uint32_t fn = 0;
	gprs_rlcmac_dl_tbf *dl_tbf;
	uint8_t block_nr = 0;
	int index1 = 0;
	uint8_t bn;
	struct msgb *msg;
	struct gprs_rlc_dl_header_egprs_3 *egprs3;

	printf("Testing retx for MCS %d to reseg_mcs %d\n", mcs, demanded_mcs);

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
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
			== mcs);

	dl_tbf->m_window.m_v_b.mark_nacked(0);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));

	dl_tbf->ms()->set_current_cs_dl
		(static_cast < GprsCodingScheme::Scheme >
			(GprsCodingScheme::CS4 + demanded_mcs));

	fn = fn_add_blocks(fn, 1);

	/* Send first segment with demanded_mcs */
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
			== demanded_mcs);
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
	msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
	OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
	OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
			== demanded_mcs);
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
		int mcs, int demanded_mcs)
{
	uint32_t fn = 0;
	gprs_rlcmac_dl_tbf *dl_tbf;
	uint8_t block_nr = 0;
	int index1 = 0;
	uint8_t bn;
	struct msgb *msg;

	printf("Testing retx for MCS %d - %d\n", mcs, demanded_mcs);

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
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);

		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== mcs);
		OSMO_ASSERT(dl_tbf->m_rlc.block(1)->cs_current_trans.to_num()
				== mcs);

		dl_tbf->m_window.m_v_b.mark_nacked(0);
		dl_tbf->m_window.m_v_b.mark_nacked(1);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(1));

		/* Set the demanded MCS to demanded_mcs */
		dl_tbf->ms()->set_current_cs_dl
			(static_cast < GprsCodingScheme::Scheme >
				(GprsCodingScheme::CS4 + demanded_mcs));

		fn = fn_add_blocks(fn, 1);
		/* Retransmit the first RLC data block with demanded_mcs */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== demanded_mcs);

		fn = fn_add_blocks(fn, 1);
		/* Retransmit the second RLC data block with demanded_mcs */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(1)->cs_current_trans.to_num()
				== demanded_mcs);
	} else if (((mcs == 5) && (demanded_mcs > 6)) ||
		((mcs == 6) && (demanded_mcs > 8))) {
		fn = fn_add_blocks(fn, 1);
		/* Send first RLC data block BSN 0 */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== mcs);

		fn = fn_add_blocks(fn, 1);
		/* Send second RLC data block BSN 1 */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(1)->cs_current_trans.to_num()
				== mcs);

		dl_tbf->m_window.m_v_b.mark_nacked(0);
		dl_tbf->m_window.m_v_b.mark_nacked(1);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(1));

		dl_tbf->ms()->set_current_cs_dl
			(static_cast < GprsCodingScheme::Scheme >
				(GprsCodingScheme::CS4 + demanded_mcs));

		fn = fn_add_blocks(fn, 1);
		/* Send first, second RLC data blocks with demanded_mcs */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== demanded_mcs);
		OSMO_ASSERT(dl_tbf->m_rlc.block(1)->cs_current_trans.to_num()
				== demanded_mcs);
	} else if (mcs > 6) {
		/* No Mcs change cases are handled here for mcs > MCS6*/
		fn = fn_add_blocks(fn, 1);
		/* Send first,second RLC data blocks */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== mcs);
		OSMO_ASSERT(dl_tbf->m_rlc.block(1)->cs_current_trans.to_num()
				== mcs);

		dl_tbf->m_window.m_v_b.mark_nacked(0);
		dl_tbf->m_window.m_v_b.mark_nacked(1);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(1));

		fn = fn_add_blocks(fn, 1);
		/* Send first,second RLC data blocks with demanded_mcs*/
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(1));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== mcs);
		OSMO_ASSERT(dl_tbf->m_rlc.block(1)->cs_current_trans.to_num()
				== mcs);
	} else {

		/* No MCS change cases are handled here for mcs <= MCS6*/
		fn = fn_add_blocks(fn, 1);
		/* Send first RLC data block */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== mcs);

		dl_tbf->m_window.m_v_b.mark_nacked(0);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_nacked(0));

		fn = fn_add_blocks(fn, 1);
		/* Send first RLC data block with demanded_mcs */
		msg = dl_tbf->create_dl_acked_block(fn, dl_tbf->control_ts);
		OSMO_ASSERT(dl_tbf->m_window.m_v_b.is_unacked(0));
		OSMO_ASSERT(dl_tbf->m_rlc.block(0)->cs_current_trans.to_num()
				== mcs);
	}

	tbf_cleanup(dl_tbf);
}

static void test_tbf_egprs_retx_dl(void)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	int i, j;

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->cs_downgrade_threshold = 0;
	setup_bts(&the_bts, ts_no);
	bts->dl_tbf_idle_msec = 200;
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

	printf("=== end %s ===\n", __func__);
}

static void test_tbf_egprs_spb_dl(void)
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	int i, j;

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();
	bts->cs_downgrade_threshold = 0;
	setup_bts(&the_bts, ts_no);
	bts->dl_tbf_idle_msec = 200;
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

	printf("=== end %s ===\n", __func__);
}

static void test_tbf_egprs_dl()
{
	BTS the_bts;
	gprs_rlcmac_bts *bts;
	uint8_t ts_no = 4;
	int i;

	printf("=== start %s ===\n", __func__);

	bts = the_bts.bts_data();

	setup_bts(&the_bts, ts_no);
	bts->dl_tbf_idle_msec = 200;
	bts->egprs_enabled = 1;
	/* ARQ II */
	bts->dl_arq_type = EGPRS_ARQ2;

	for (i = 1; i <= 9; i++)
		establish_and_use_egprs_dl_tbf(&the_bts, i);

	printf("=== end %s ===\n", __func__);
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
        {"DNS","\033[1;34m", "GPRS Network Service Protocol (NS)", LOGL_INFO , 1},
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
