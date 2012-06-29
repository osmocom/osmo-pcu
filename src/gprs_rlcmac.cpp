/* gprs_rlcmac.cpp
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
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <gsmL1prim.h>

LLIST_HEAD(gprs_rlcmac_tbfs);
void *rlcmac_tall_ctx;
LLIST_HEAD(block_queue);

int tfi_alloc()
{
	struct gprs_rlcmac_tbf *tbf;
	uint32_t tfi_map = 0;
	uint32_t tfi_ind = 0;
	uint32_t mask = 1;
	uint8_t i;

	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		tfi_ind = 1 << tbf->tfi;
		tfi_map = tfi_map|tfi_ind;
	}
	
	for (i = 0; i < 32; i++) {
		if(((tfi_map >> i) & mask) == 0) {
			return i;
		}
	}
	return -1;
}

/* lookup TBF Entity (by TFI) */
static struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi, gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;

	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if ((tbf->tfi == tfi)&&(tbf->direction == dir))
			return tbf;
	}
	return NULL;
}

static struct gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli, gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;
	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if ((tbf->tlli == tlli)&&(tbf->direction == dir))
			return tbf;
	}
	return NULL;
}

static void tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	llist_del(&tbf->list);
	talloc_free(tbf);
}

/* Lookup LLC PDU in TBF list of LLC PDUs by number. */
static struct tbf_llc_pdu *tbf_llc_pdu_by_num(struct llist_head llc_pdus, uint8_t num)
{
	struct tbf_llc_pdu *llc_pdu;

	llist_for_each_entry(llc_pdu, &llc_pdus, list) {
		if (llc_pdu->num == num)
			return llc_pdu;
	}
	return NULL;
}

/* Add new LLC PDU to the TBF list of LLC PDUs. */
int tbf_add_llc_pdu(struct gprs_rlcmac_tbf *tbf, uint8_t *data, uint16_t llc_pdu_len)
{
	struct tbf_llc_pdu *llc_pdu;

	llc_pdu = talloc_zero(rlcmac_tall_ctx, struct tbf_llc_pdu);
	if (!llc_pdu)
		return 0;

	llc_pdu->num = tbf->llc_pdu_list_len;
	llc_pdu->len = llc_pdu_len;
	
	LOGP(DBSSGP, LOGL_NOTICE, "LLC PDU = ");
	for (unsigned i = 0; i < llc_pdu_len; i++)
	{
		llc_pdu->data[i] = data[i];
		LOGPC(DBSSGP, LOGL_NOTICE, "%02x", llc_pdu->data[i]);
	}
	LOGPC(DBSSGP, LOGL_NOTICE, "\n");

	llist_add(&llc_pdu->list, &tbf->llc_pdus);
	tbf->llc_pdu_list_len++;
	return 1;
}

struct gprs_rlcmac_tbf *tbf_alloc(gprs_rlcmac_tbf_direction dir, uint32_t tlli)
{
	struct gprs_rlcmac_tbf *exist_tbf;
	struct gprs_rlcmac_tbf *tbf;
	uint8_t tfi;
	uint8_t trx, ts;

	// Downlink TDF allocation
	if (dir == GPRS_RLCMAC_DL_TBF)
	{
		// Try to find already exist DL TBF
		exist_tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_DL_TBF);
		if (exist_tbf)
		{
			// if DL TBF is in establish or data transfer state,
			// send additional LLC PDU during current DL TBF.
			if (exist_tbf->stage != TBF_RELEASE)
			{
				if (exist_tbf->state != FINISH_DATA_TRANSFER)
				{
					return exist_tbf;
				}
			}
		}
		
		//Try to find already exist UL TBF
		exist_tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
		if (exist_tbf)
		{
			// if UL TBF is in data transfer state,
			// establish new DL TBF during current UL TBF.
			if (exist_tbf->stage == TBF_DATA_TRANSFER && !(exist_tbf->next_tbf))
			{
				tbf = talloc_zero(rlcmac_tall_ctx, struct gprs_rlcmac_tbf);
				if (tbf)
				{
					// Create new TBF
					tfi = tfi_alloc();
					if (tfi < 0) {
						return NULL;
					}
					
					/* FIXME: select right TRX/TS */
					if (select_pdch(&trx, &ts)) {
						LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
						/* FIXME: send reject */
						return NULL;
					}
				
					tbf->tfi = tfi;
					tbf->trx = trx;
					tbf->ts = ts;
					tbf->arfcn = pcu_l1if_bts.trx[trx].arfcn;
					tbf->tsc = pcu_l1if_bts.trx[trx].ts[ts].tsc;
					tbf->llc_pdus = LLIST_HEAD_INIT(tbf->llc_pdus);
					tbf->llc_pdu_list_len = 0;
					tbf->direction = GPRS_RLCMAC_DL_TBF;
					tbf->stage = TBF_ESTABLISH;
					tbf->state = WAIT_ESTABLISH;
					tbf->tlli = tlli;
					llist_add(&tbf->list, &gprs_rlcmac_tbfs);
					exist_tbf->next_tbf = tbf;
					return tbf;
				}
				else
				{
					return NULL;
				}
			}
		}
		
		// No UL and DL TBFs for current TLLI are found.
		if (!exist_tbf)
		{
			tbf = talloc_zero(rlcmac_tall_ctx, struct gprs_rlcmac_tbf);
			if (tbf)
			{
				// Create new TBF
				tfi = tfi_alloc();
				if (tfi < 0) {
					return NULL;
				}
				
				/* FIXME: select right TRX/TS */
				if (select_pdch(&trx, &ts)) {
					LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
					/* FIXME: send reject */
					return NULL;
				}
				
				tbf->tfi = tfi;
				tbf->trx = trx;
				tbf->ts = ts;
				tbf->arfcn = pcu_l1if_bts.trx[trx].arfcn;
				tbf->tsc = pcu_l1if_bts.trx[trx].ts[ts].tsc;
				tbf->llc_pdus = LLIST_HEAD_INIT(tbf->llc_pdus);
				tbf->llc_pdu_list_len = 0;
				tbf->direction = GPRS_RLCMAC_DL_TBF;
				tbf->stage = TBF_ESTABLISH;
				tbf->state = CCCH_ESTABLISH;
				tbf->tlli = tlli;
				llist_add(&tbf->list, &gprs_rlcmac_tbfs);
				return tbf;
			}
			else
			{
				return NULL;
			}
		}
	}
	else
	{
		// Uplink TBF allocation
		tbf = talloc_zero(rlcmac_tall_ctx, struct gprs_rlcmac_tbf);
		if (tbf)
		{
			// Create new TBF
			tfi = tfi_alloc();
			if (tfi < 0) {
				return NULL;
			}
			if (select_pdch(&trx, &ts)) {
				LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
				/* FIXME: send reject */
				return NULL;
			}
			tbf->tfi = tfi;
			tbf->trx = trx;
			tbf->ts = ts;
			tbf->arfcn = pcu_l1if_bts.trx[trx].arfcn;
			tbf->tsc = pcu_l1if_bts.trx[trx].ts[ts].tsc;
			tbf->llc_pdus = LLIST_HEAD_INIT(tbf->llc_pdus);
			tbf->llc_pdu_list_len = 0;
			tbf->direction = GPRS_RLCMAC_UL_TBF;
			tbf->stage = TBF_ESTABLISH;
			tbf->state = WAIT_ESTABLISH;
			tbf->next_tbf = NULL;
			llist_add(&tbf->list, &gprs_rlcmac_tbfs);
			return tbf;
		}
		else
		{
			return NULL;
		}
	}
}

/* Management of uplink TBF establishment. */
int tbf_ul_establish(struct gprs_rlcmac_tbf *tbf, uint8_t ra, uint32_t Fn, uint16_t qta)
{
	if (tbf->direction != GPRS_RLCMAC_UL_TBF)
	{
		return -1;
	}
	
	if (tbf->stage == TBF_ESTABLISH)
	{
		switch (tbf->state) {
		case WAIT_ESTABLISH:
			{
				if (qta < 0)
					qta = 0;
				if (qta > 252)
					qta = 252;
				tbf->ta = qta >> 2;
				LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [UPLINK] START TFI: %u\n", tbf->tfi);
				LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] TFI: %u RACH qbit-ta=%d ra=%d, Fn=%d (%d,%d,%d)\n",
                                                  tbf->tfi, qta, ra, Fn, (Fn / (26 * 51)) % 32, Fn % 51, Fn % 26);
				LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u Packet Immidiate Assignment\n", tbf->tfi);
				bitvec *immediate_assignment = bitvec_alloc(23);
				bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
				int len = write_immediate_assignment(immediate_assignment, 0, ra, Fn, tbf->ta, tbf->arfcn, tbf->ts, tbf->tsc, tbf->tfi);
				pcu_l1if_tx_agch(immediate_assignment, len);
				bitvec_free(immediate_assignment);
				tbf->state = FINISH_ESTABLISH;
			}
			break;
		default:
			LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [UPLINK] TFI: %u Unexpected TBF state = %u for stage = %u \n", 
																			tbf->tfi, tbf->state, tbf->stage);
			break;
		}
	}
	else
	{
		return -1;
	}
	return 1;
}

/* Management of downlink TBF establishment. */
int tbf_dl_establish(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction != GPRS_RLCMAC_DL_TBF)
	{
		return -1;
	}
	
	if (tbf->stage == TBF_ESTABLISH)
	{
		switch (tbf->state) {
		case WAIT_ESTABLISH:
			// Wait while UL TBF establishes DL TBF.
			LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] TFI: Wait DL TBF establishment by UL TBF\n", tbf->tfi);
			break;
		case CCCH_ESTABLISH:
			// Downlink TBF Establishment on CCCH ( Immediate Assignment )
			tbf_gsm_timer_start(tbf, 1, 0);
			break;
		case PACCH_ESTABLISH:
			// Downlink TBF Establishment on PACCH ( Packet Immediate Assignment )
			gprs_rlcmac_packet_downlink_assignment(tbf);
			tbf->state = FINISH_ESTABLISH;
			break;
		default:
			LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] TFI: %u Unexpected TBF state = %u for stage = %u \n", 
																			tbf->tfi, tbf->state, tbf->stage);
			break;
		}
	}
	return 1;
}

/* Management of uplink TBF data transfer. */
int tbf_ul_data_transfer(struct gprs_rlcmac_tbf *tbf, RlcMacUplinkDataBlock_t * ul_data_block)
{
	if ((tbf->stage == TBF_RELEASE)||(tbf->direction != GPRS_RLCMAC_UL_TBF))
	{
		return -1;
	}

	if (tbf->stage == TBF_ESTABLISH)
	{
		tbf->stage = TBF_DATA_TRANSFER;
		tbf->state = WAIT_DATA_TRANSFER;
	}

	if (ul_data_block->TI == 1)
	{
		tbf->tlli = ul_data_block->TLLI;
		// TODO: Kill all other UL TBFs with this TLLI.
	}

	switch (tbf->state) {
	case WAIT_DATA_TRANSFER:
		if (ul_data_block->BSN == 0)
		{
			tbf->data_index = 0;
			gprs_rlcmac_data_block_parse(tbf, ul_data_block);
			gprs_rlcmac_tx_ul_ack(tbf->tfi, tbf->tlli, ul_data_block->CV ? 0: 1, ul_data_block->BSN);
			if (ul_data_block->CV == 0)
			{
				// Recieved last Data Block in this sequence.
				tbf->state = FINISH_DATA_TRANSFER;
				gprs_rlcmac_tx_ul_ud(tbf);
			}
			else
			{
				tbf->bsn = ul_data_block->BSN;
				tbf->state = DATA_TRANSFER;
			}
		}
		break;
	case DATA_TRANSFER:
		if (tbf->bsn == (ul_data_block->BSN - 1))
		{
			gprs_rlcmac_data_block_parse(tbf, ul_data_block);
			
			if (ul_data_block->CV == 0)
			{
				gprs_rlcmac_tx_ul_ack(tbf->tfi, tbf->tlli, 1, ul_data_block->BSN);
				// Recieved last Data Block in this sequence.
				tbf->state = FINISH_DATA_TRANSFER;
				gprs_rlcmac_tx_ul_ud(tbf);
			}
			else
			{
				tbf->bsn = ul_data_block->BSN;
			}
		}
		break;
	case FINISH_DATA_TRANSFER:
		// Now we just ignore all Data Blocks and wait release of TBF.
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [UPLINK] TFI: %u Unexpected TBF state = %u for stage = %u \n", 
																		tbf->tfi, tbf->state, tbf->stage);
		break;
	}

	if ((tbf->state == FINISH_DATA_TRANSFER) && (tbf->next_tbf))
	{
		// Establish DL TBF, if it is required.
		if ((tbf->next_tbf)->state == WAIT_ESTABLISH)
		{
			(tbf->next_tbf)->state = PACCH_ESTABLISH;
			tbf_dl_establish(tbf->next_tbf);
		}
	}

	return 1;
}

/* Management of downlink TBF data transfer. */
int tbf_dl_data_transfer(struct gprs_rlcmac_tbf *tbf, uint8_t *llc_pdu, uint16_t llc_pdu_len)
{
	if ((tbf->stage == TBF_RELEASE) || (tbf->direction != GPRS_RLCMAC_DL_TBF))
	{
		return -1;
	}
	
	if (llc_pdu_len > 0)
	{
		tbf_add_llc_pdu(tbf, llc_pdu, llc_pdu_len);
	}

	if (tbf->stage == TBF_ESTABLISH)
	{
		if (tbf->state == FINISH_ESTABLISH)
		{
			tbf->stage = TBF_DATA_TRANSFER;
			tbf->state = DATA_TRANSFER;
		}
	}

	if (tbf->stage == TBF_DATA_TRANSFER)
	{
		switch (tbf->state) {
		case DATA_TRANSFER:
			gprs_rlcmac_tx_llc_pdus(tbf);
			tbf->state = FINISH_DATA_TRANSFER;
			break;
		default:
			LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] TFI: %u Unexpected TBF state = %u for stage = %u \n", 
																			tbf->tfi, tbf->state, tbf->stage);
			break;
		}
	}

	return 1;
}

/* Management of uplink TBF release. */
int tbf_ul_release(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction != GPRS_RLCMAC_UL_TBF)
	{
		return -1;
	}

	if (tbf->next_tbf)
	{
		// UL TBF data transfer is finished, start DL TBF data transfer.
		tbf_dl_data_transfer(tbf->next_tbf);
	}
	tbf->stage = TBF_RELEASE;
	tbf->state = RELEASE;
	LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [UPLINK] END TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
	tbf_free(tbf);
	return 1;
}

/* Management of downlink TBF release. */
int tbf_dl_release(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction != GPRS_RLCMAC_DL_TBF)
	{
		return -1;
	}

	tbf->stage = TBF_RELEASE;
	tbf->state = RELEASE;
	LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] END TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
	tbf_free(tbf);
	return 1;
}

static void tbf_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	tbf->num_T_exp++;

	switch (tbf->T) {
	case 1111:
		// TODO: We should add timers for TBF.
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Timer expired in unknown mode: %u \n", tbf->T);
	}
}

static void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
				unsigned int seconds)
{
	if (osmo_timer_pending(&tbf->timer))
		LOGP(DRLCMAC, LOGL_NOTICE, "Starting TBF timer %u while old timer %u pending \n", T, tbf->T);
	tbf->T = T;
	tbf->num_T_exp = 0;

	/* FIXME: we should do this only once ? */
	tbf->timer.data = tbf;
	tbf->timer.cb = &tbf_timer_cb;

	osmo_timer_schedule(&tbf->timer, seconds, 0);
}


static void tbf_gsm_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	tbf->num_fT_exp++;

	switch (tbf->fT) {
	case 1:
		if (tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF))
		{
			// Wait release of UL TBF
			tbf_gsm_timer_start(tbf, 1, 10);
		}
		else
		{
			gprs_rlcmac_downlink_assignment(tbf);
			// FIXME: Remove magic delay!
			int delay = 50;
			tbf_gsm_timer_start(tbf, 2, delay);
		}
		break;
	case 2:
		tbf->state = FINISH_ESTABLISH;
		tbf_dl_data_transfer(tbf);
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Timer expired in unknown mode: %u \n", tbf->fT);
	}
}

static void tbf_gsm_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int fT,
				int frames)
{
	if (osmo_gsm_timer_pending(&tbf->gsm_timer))
		LOGP(DRLCMAC, LOGL_NOTICE, "Starting TBF timer %u while old timer %u pending \n", fT, tbf->fT);
	tbf->fT = fT;
	tbf->num_fT_exp = 0;

	/* FIXME: we should do this only once ? */
	tbf->gsm_timer.data = tbf;
	tbf->gsm_timer.cb = &tbf_gsm_timer_cb;

	osmo_gsm_timer_schedule(&tbf->gsm_timer, frames);
}

static void gprs_rlcmac_enqueue_block(bitvec *block, int len)
{
	struct msgb *msg = msgb_alloc(len, "rlcmac_dl");
	bitvec_pack(block, msgb_put(msg, len));
	msgb_enqueue(&block_queue, msg);
}

void write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t tfi, uint16_t arfcn, uint8_t tn, uint8_t ta, uint8_t tsc)
{
	// Packet downlink assignment TS 44.060 11.2.7

	int i;

	block->PAYLOAD_TYPE = 0x1; // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0; // N+13
	block->SP           = 0x1; // RRBP field is valid
	block->USF          = 0x1; // Uplink state flag

	block->u.Packet_Downlink_Assignment.MESSAGE_TYPE = 0x2;  // Packet Downlink Assignment
	block->u.Packet_Downlink_Assignment.PAGE_MODE    = 0x0;  // Normal Paging

	block->u.Packet_Downlink_Assignment.Exist_PERSISTENCE_LEVEL      = 0x0;   // PERSISTENCE_LEVEL: off

	block->u.Packet_Downlink_Assignment.ID.UnionType                 = 0x0;   // TFI = on
	block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.UnionType    = 0x0;   // UPLINK TFI = on
	block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.u.UPLINK_TFI = tfi-1; // TFI

	block->u.Packet_Downlink_Assignment.MAC_MODE            = 0x0; // Dynamic Allocation
	block->u.Packet_Downlink_Assignment.RLC_MODE            = 0x0; // RLC acknowledged mode
	block->u.Packet_Downlink_Assignment.CONTROL_ACK         = 0x0; // NW establishes no new DL TBF for the MS with running timer T3192
	block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION = 0x80 >> tn; // timeslot(s)

	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_TIMING_ADVANCE_VALUE = 0x1; // TIMING_ADVANCE_VALUE = on
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_VALUE       = ta;  // TIMING_ADVANCE_VALUE
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x0; // TIMING_ADVANCE_INDEX = off

	block->u.Packet_Downlink_Assignment.Exist_P0_and_BTS_PWR_CTRL_MODE = 0x0;   // POWER CONTROL = off

	block->u.Packet_Downlink_Assignment.Exist_Frequency_Parameters     = 0x1;   // Frequency Parameters = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.TSC       = tsc;   // Training Sequence Code (TSC)
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.UnionType = 0x0;   // ARFCN = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.u.ARFCN   = arfcn; // ARFCN

	block->u.Packet_Downlink_Assignment.Exist_DOWNLINK_TFI_ASSIGNMENT  = 0x1;   // DOWNLINK TFI ASSIGNMENT = on
	block->u.Packet_Downlink_Assignment.DOWNLINK_TFI_ASSIGNMENT        = tfi;   // TFI

	block->u.Packet_Downlink_Assignment.Exist_Power_Control_Parameters = 0x1;   // Power Control Parameters = on
	block->u.Packet_Downlink_Assignment.Power_Control_Parameters.ALPHA = 0x0;   // ALPHA

	for (i = 0; i < 8; i++)
	{
		if (tn == i)
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[i].Exist    = 0x1; // Slot[i] = on
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[i].GAMMA_TN = 0x0; // GAMMA_TN
		}
		else
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[i].Exist    = 0x0; // Slot[i] = off
		}
	}

	block->u.Packet_Downlink_Assignment.Exist_TBF_Starting_Time   = 0x0; // TBF Starting TIME = off
	block->u.Packet_Downlink_Assignment.Exist_Measurement_Mapping = 0x0; // Measurement_Mapping = off
	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x0; // AdditionsR99 = off
}

// GSM 04.08 9.1.18 Immediate assignment
int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra, uint32_t fn,
								uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, uint8_t tfi, uint32_t tlli)
{
	unsigned wp = 0;

	bitvec_write_field(dest, wp,0x0,4);  // Skip Indicator
	bitvec_write_field(dest, wp,0x6,4);  // Protocol Discriminator
	bitvec_write_field(dest, wp,0x3F,8); // Immediate Assignment Message Type

	// 10.5.2.25b Dedicated mode or TBF
	bitvec_write_field(dest, wp,0x0,1);      // spare
	bitvec_write_field(dest, wp,0x0,1);      // TMA : Two-message assignment: No meaning
	bitvec_write_field(dest, wp,downlink,1); // Downlink : Downlink assignment to mobile in packet idle mode
	bitvec_write_field(dest, wp,0x1,1);      // T/D : TBF or dedicated mode: this message assigns a Temporary Block Flow (TBF).

	bitvec_write_field(dest, wp,0x0,4); // Page Mode

	// GSM 04.08 10.5.2.25a Packet Channel Description
	bitvec_write_field(dest, wp,0x1,5);                               // Channel type
	bitvec_write_field(dest, wp,ts,3);     // TN
	bitvec_write_field(dest, wp,tsc,3);    // TSC
	bitvec_write_field(dest, wp,0x0,3);                               // non-hopping RF channel configuraion
	bitvec_write_field(dest, wp,arfcn,10); // ARFCN

	//10.5.2.30 Request Reference
	bitvec_write_field(dest, wp,ra,8);                    // RA
	bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
	bitvec_write_field(dest, wp,fn % 51,6);               // T3
	bitvec_write_field(dest, wp,fn % 26,5);               // T2

	// 10.5.2.40 Timing Advance
	bitvec_write_field(dest, wp,0x0,2); // spare
	bitvec_write_field(dest, wp,ta,6);  // Timing Advance value

	// No mobile allocation in non-hopping systems.
	// A zero-length LV.  Just write L=0.
	bitvec_write_field(dest, wp,0,8);

	if (downlink)
	{
		// GSM 04.08 10.5.2.16 IA Rest Octets
		bitvec_write_field(dest, wp, 3, 2);   // "HH"
		bitvec_write_field(dest, wp, 1, 2);   // "01" Packet Downlink Assignment
		bitvec_write_field(dest, wp,tlli,32); // TLLI
		bitvec_write_field(dest, wp,0x1,1);   // switch TFI   : on
		bitvec_write_field(dest, wp,tfi,5);   // TFI
		bitvec_write_field(dest, wp,0x0,1);   // RLC acknowledged mode
		bitvec_write_field(dest, wp,0x0,1);   // ALPHA = present
		bitvec_write_field(dest, wp,0x0,5);   // GAMMA power control parameter
		bitvec_write_field(dest, wp,0x0,1);   // Polling Bit
		bitvec_write_field(dest, wp,0x1,1);   // TA_VALID ???
		bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
		bitvec_write_field(dest, wp,0x0,4);   // TIMING_ADVANCE_INDEX
		bitvec_write_field(dest, wp,0x0,1);   // TBF Starting TIME present
		bitvec_write_field(dest, wp,0x0,1);   // P0 not present
		bitvec_write_field(dest, wp,0x1,1);   // P0 not present
		bitvec_write_field(dest, wp,0xb,4);
	}
	else
	{
		// GMS 04.08 10.5.2.37b 10.5.2.16
		bitvec_write_field(dest, wp, 3, 2);    // "HH"
		bitvec_write_field(dest, wp, 0, 2);    // "0" Packet Uplink Assignment
		bitvec_write_field(dest, wp, 1, 1);    // Block Allocation : Not Single Block Allocation
		bitvec_write_field(dest, wp, tfi, 5);  // TFI_ASSIGNMENT Temporary Flow Identity
		bitvec_write_field(dest, wp, 0, 1);    // POLLING
		bitvec_write_field(dest, wp, 0, 1);    // ALLOCATION_TYPE: dynamic
		bitvec_write_field(dest, wp, 1, 3);    // USF
		bitvec_write_field(dest, wp, 0, 1);    // USF_GRANULARITY
		bitvec_write_field(dest, wp, 0 , 1);   // "0" power control: Not Present
		bitvec_write_field(dest, wp, 0, 2);    // CHANNEL_CODING_COMMAND 
		bitvec_write_field(dest, wp, 0, 1);    // TLLI_BLOCK_CHANNEL_CODING
		bitvec_write_field(dest, wp, 1 , 1);   // "1" Alpha : Present
		bitvec_write_field(dest, wp, 0, 4);    // Alpha
		bitvec_write_field(dest, wp, 0, 5);    // Gamma
		bitvec_write_field(dest, wp, 0, 1);    // TIMING_ADVANCE_INDEX_FLAG
		bitvec_write_field(dest, wp, 0, 1);    // TBF_STARTING_TIME_FLAG
	}

	if (wp%8)
		return wp/8+1;
	else
		return wp/8;
}

void write_packet_uplink_ack(RlcMacDownlink_t * block, uint8_t tfi, uint32_t tlli, uint8_t fi, uint8_t bsn)
{
	// Packet Uplink Ack/Nack  TS 44.060 11.2.28

	int i;

	block->PAYLOAD_TYPE = 0x1; // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0; // N+13
	block->SP           = fi;  // RRBP field is valid, if it is final ack
	block->USF          = 0x1; // Uplink state flag

	block->u.Packet_Uplink_Ack_Nack.MESSAGE_TYPE = 0x9; // Packet Downlink Assignment
	block->u.Packet_Uplink_Ack_Nack.PAGE_MODE    = 0x0; // Normal Paging
	block->u.Packet_Uplink_Ack_Nack.UPLINK_TFI   = tfi; // Uplink TFI

	block->u.Packet_Uplink_Ack_Nack.UnionType    = 0x0; // PU_AckNack_GPRS = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.CHANNEL_CODING_COMMAND                        = 0x0;      // CS1
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.FINAL_ACK_INDICATION     = fi;       // FINAL ACK INDICATION
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER = bsn + 1;  // STARTING SEQUENCE NUMBER
	for (i = 0; i < 8; i++)
	{
		block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP[i] = 0xff; // RECEIVED BLOCK BITMAP
	}

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.UnionType            = 0x0; // Fixed Allocation Dummy = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.u.FixedAllocationDummy = 0x0; // Fixed Allocation Dummy
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Exist_AdditionsR99   = 0x0; // AdditionsR99 = off

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI = 0x1;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI       = tlli;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance      = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits             = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters   = 0x0;
}

void gprs_rlcmac_tx_ul_ack(uint8_t tfi, uint32_t tlli, uint8_t fi, uint8_t bsn)
{
	bitvec *packet_uplink_ack_vec = bitvec_alloc(23);
	bitvec_unhex(packet_uplink_ack_vec, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlink_t * packet_uplink_ack = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	write_packet_uplink_ack(packet_uplink_ack, tfi, tlli, fi, bsn);
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u TLLI: 0x%08x Packet Uplink Ack\n", tfi, tlli);
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ TX : Packet Uplink Ack +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink(packet_uplink_ack_vec, packet_uplink_ack);
	LOGPC(DRLCMAC, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- TX : Packet Uplink Ack -------------------------\n");
	free(packet_uplink_ack);
	gprs_rlcmac_enqueue_block(packet_uplink_ack_vec, 23);
	bitvec_free(packet_uplink_ack_vec);
}

void gprs_rlcmac_data_block_parse(gprs_rlcmac_tbf* tbf, RlcMacUplinkDataBlock_t * ul_data_block)
{
	// 1. Count the number of octets in header and number of LLC PDU in uplink data block.
	unsigned data_block_hdr_len = 3; // uplink data block header length: 3 mandatory octets
	unsigned llc_pdu_num = 0; // number of LLC PDU in data block

	
	if (ul_data_block->E_1 == 0) // Extension octet follows immediately
	{
		unsigned i = -1;
		do
		{
			i++;
			data_block_hdr_len += 1;
			llc_pdu_num++;
			
			// Singular case, TS 44.060 10.4.14
			if (ul_data_block->LENGTH_INDICATOR[i] == 0)
			{
				break;
			}
			
			// New LLC PDU starts after the current LLC PDU and continues until
			// the end of the RLC information field, no more extension octets.
			if ((ul_data_block->M[i] == 1)&&(ul_data_block->E[i] == 1))
			{
				llc_pdu_num++;
			}
		} while(ul_data_block->E[i] == 0); // there is another extension octet, which delimits the new LLC PDU
	}
	else
	{
		llc_pdu_num++;
	}
	if(ul_data_block->TI == 1) // TLLI field is present
	{
		tbf->tlli = ul_data_block->TLLI;
		data_block_hdr_len += 4; // TLLI length : 4 octets
		if (ul_data_block->PI == 1) // PFI is present if TI field indicates presence of TLLI
		{
			data_block_hdr_len += 1; // PFI length : 1 octet
		}
	}
	
	// 2. Extract all LLC PDU from uplink data block and send them to SGSN.
	unsigned llc_pdu_len = 0;
	unsigned data_octet_num = 0;

	for (unsigned num = 0; num < llc_pdu_num; num ++)
	{
		if (ul_data_block->E_1 == 0) // Extension octet follows immediately
		{
			// Singular case, TS 44.060 10.4.14
			if (ul_data_block->LENGTH_INDICATOR[num] == 0)
			{
				llc_pdu_len = UL_RLC_DATA_BLOCK_LEN - data_block_hdr_len;
			}
			else
			{
				llc_pdu_len = ul_data_block->LENGTH_INDICATOR[num];
			}
		}
		else
		{
			llc_pdu_len = UL_RLC_DATA_BLOCK_LEN - data_block_hdr_len;
		}
		
		for (unsigned i = tbf->data_index; i < tbf->data_index + llc_pdu_len; i++)
		{
			tbf->rlc_data[i] = ul_data_block->RLC_DATA[data_octet_num];
			data_octet_num++;
		}
		tbf->data_index += llc_pdu_len;
		
		if (ul_data_block->E_1 == 0) // Extension octet follows immediately
		{
			// New LLC PDU starts after the current LLC PDU 
			if (ul_data_block->M[num] == 1)
			{
				gprs_rlcmac_tx_ul_ud(tbf);
				tbf->data_index = 0;
				// New LLC PDU continues until the end of the RLC information field, no more extension octets.
				if ((ul_data_block->E[num] == 1))
				{
					llc_pdu_len = UL_RLC_DATA_BLOCK_LEN - data_block_hdr_len - data_octet_num;
					for (unsigned i = tbf->data_index; i < tbf->data_index + llc_pdu_len; i++)
					{
						tbf->rlc_data[i] = ul_data_block->RLC_DATA[data_octet_num];
						data_octet_num++;
					}
					tbf->data_index += llc_pdu_len;
					num++;
				}
			}
		}
	}
}

/* Received Uplink RLC data block. */
int gprs_rlcmac_rcv_data_block(bitvec *rlc_block)
{
	struct gprs_rlcmac_tbf *tbf;
	int rc = 0;

	LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] Uplink Data Block\n");
	RlcMacUplinkDataBlock_t * ul_data_block = (RlcMacUplinkDataBlock_t *)malloc(sizeof(RlcMacUplinkDataBlock_t));
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ RX : Uplink Data Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink_data(rlc_block, ul_data_block);
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- RX : Uplink Data Block -------------------------\n");

	tbf = tbf_by_tfi(ul_data_block->TFI, GPRS_RLCMAC_UL_TBF);
	if (!tbf) {
		return -1;
	}
	
	rc = tbf_ul_data_transfer(tbf, ul_data_block);
	free(ul_data_block);
	return rc;
}

/* Received Uplink RLC control block. */
int gprs_rlcmac_rcv_control_block(bitvec *rlc_block)
{
	uint8_t tfi = 0;
	uint32_t tlli = 0;
	struct gprs_rlcmac_tbf *tbf;
	RlcMacUplink_t * ul_control_block = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	LOGPC(DRLCMAC, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- RX : Uplink Control Block -------------------------\n");
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		tlli = ul_control_block->u.Packet_Control_Acknowledgement.TLLI;
		tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
		if (!tbf) {
			return 0;
		}
		LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] TFI: %u TLLI: 0x%08x Packet Control Ack\n", tbf->tfi, tbf->tlli);
		tbf_ul_release(tbf);
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		tfi = ul_control_block->u.Packet_Downlink_Ack_Nack.DOWNLINK_TFI;
		tbf = tbf_by_tfi(tfi, GPRS_RLCMAC_DL_TBF);
		if (!tbf) {
			return 0;
		}
		LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] TFI: %u TLLI: 0x%08x Packet Downlink Ack/Nack\n", tbf->tfi, tbf->tlli);
		tbf_dl_release(tbf);
		break;
	}
	free(ul_control_block);
	return 1;
}

void gprs_rlcmac_rcv_block(bitvec *rlc_block)
{
	unsigned readIndex = 0;
	unsigned payload = bitvec_read_field(rlc_block, readIndex, 2);

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		gprs_rlcmac_rcv_data_block(rlc_block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		gprs_rlcmac_rcv_control_block(rlc_block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload.\n");
	}
}

struct msgb *gen_dummy_msg(uint8_t usf)
{
	struct msgb *msg = msgb_alloc(23, "rlcmac_dl_idle");
	// RLC/MAC filler with USF=1
	bitvec *filler = bitvec_alloc(23);
#warning HACK
	if (usf == 1)
		bitvec_unhex(filler, "41942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	else
		bitvec_unhex(filler, "42942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	bitvec_pack(filler, msgb_put(msg, 23));
	bitvec_free(filler);
	return msg;
}

void gprs_rlcmac_rcv_rts_block(uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
	struct msgb *msg;
	
	set_current_fn(fn);
	msg = msgb_dequeue(&block_queue);
	if (!msg)
		msg = gen_dummy_msg(block_nr ? 2 : 1);
	pcu_l1if_tx_pdtch(msg, trx, ts, arfcn, fn, block_nr);
}

int select_pdch(uint8_t *_trx, uint8_t *_ts)
{
	uint8_t trx, ts;

	for (trx = 0; trx < 8; trx++) {
		for (ts = 0; ts < 8; ts++) {
			if (pcu_l1if_bts.trx[trx].ts[ts].enable) {
				*_trx = trx;
				*_ts = ts;
				return 0;
			}
		}
	}

	return -EBUSY;
}

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta)
{
	struct gprs_rlcmac_tbf *tbf;
	uint8_t trx, ts;

	static uint8_t prev_ra = 0;

	if (prev_ra == ra)
	{
		return -1;
	}

	tbf = tbf_alloc(GPRS_RLCMAC_UL_TBF);

	return tbf_ul_establish(tbf, ra, Fn, qta);
}

int gprs_rlcmac_tx_llc_pdus(struct gprs_rlcmac_tbf *tbf)
{
	int fbi = 0;
	int bsn = 0;


	if (tbf->llc_pdu_list_len == 0)
	{
		return -1;
	}
	
	bitvec *data_block_vector = bitvec_alloc(BLOCK_LEN);
	bitvec_unhex(data_block_vector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlinkDataBlock_t * data_block = (RlcMacDownlinkDataBlock_t *)malloc(sizeof(RlcMacDownlinkDataBlock_t));
	
	struct tbf_llc_pdu *llc_pdu;
	
	int data_block_ready = 0;
	unsigned data_oct_num = 0;
	int llc_pdu_index;
	for (unsigned i = 0; i < tbf->llc_pdu_list_len; i++)
	{
		llc_pdu = tbf_llc_pdu_by_num(tbf->llc_pdus, i);
		if (!llc_pdu)
		{
			return -1;
		}

		llc_pdu_index = 0;

		do
		{
			data_block->PAYLOAD_TYPE = 0;
			data_block->RRBP = 0;
			data_block->SP = 1;
			data_block->USF = 1;
			data_block->PR = 0;
			data_block->TFI = tbf->tfi;
			data_block->BSN = bsn;

			// Write LLC PDU to Data Block
			int j;
			for(j = llc_pdu_index; j < llc_pdu->len; j++)
			{
				data_block->RLC_DATA[data_oct_num] = llc_pdu->data[j];
				data_oct_num++;
				llc_pdu_index++;
				// RLC data field is completely filled.
				if (data_oct_num == BLOCK_LEN - 3)
				{
					fbi = 0;
					data_block->E_1 = 1;
					data_block_ready = 1;
					break;
				}
			}
			if(!data_block_ready)
			{
				data_block->E_1 = 0;
				data_block->LENGTH_INDICATOR[0] = data_oct_num;
				if ((i+1) == tbf->llc_pdu_list_len)
				{
					// Current LLC PDU is last in TBF.
					data_block->M[0] = 0;
					data_block->E[0] = 1;
					fbi = 1;
					for(unsigned k = data_oct_num; k < BLOCK_LEN - 4; k++)
					{
						data_block->RLC_DATA[k] = 0x2b;
					}
					data_block_ready = 1; 
				}
				else
				{
					// More LLC PDUs should be transmited in this TBF.
					data_block->M[0] = 1;
					data_block->E[0] = 1;
					data_block_ready = 1;
					break;
				}
			}

			data_block->FBI = fbi;

			if(data_block_ready)
			{
				LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] Downlink Data Block\n");
				LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ TX : Downlink Data Block +++++++++++++++++++++++++\n");
				encode_gsm_rlcmac_downlink_data(data_block_vector, data_block);
				LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- TX : Downlink Data Block -------------------------\n");
				gprs_rlcmac_enqueue_block(data_block_vector, BLOCK_LEN);
				bitvec_unhex(data_block_vector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
				bsn++;
				data_block_ready = 0;
				data_oct_num = 0;
			}
		}
		while(llc_pdu->len != llc_pdu_index);
	}

	return 0;
}

/* Send Uplink unit-data to SGSN. */
void gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf)
{
	const uint8_t qos_profile = QOS_PROFILE;
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + tbf->data_index;

	LOGP(DBSSGP, LOGL_NOTICE, "TX: [PCU -> SGSN ] TFI: %u TLLI: 0x%08x DataLen: %u", tbf->tfi, tbf->tlli, tbf->data_index);
	//LOGP(DBSSGP, LOGL_NOTICE, " Data = ");
	//for (unsigned i = 0; i < tbf->data_index; i++)
	//	LOGPC(DBSSGP, LOGL_NOTICE, "%02x ", tbf->rlc_data[i]);
	
	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = MNC;
	bctx->ra_id.mcc = MCC;
	bctx->ra_id.lac = PCU_LAC;
	bctx->ra_id.rac = PCU_RAC;
	bctx->bvci = BVCI;

	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	msgb_tvlv_push(llc_pdu, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*tbf->data_index, tbf->rlc_data);
	bssgp_tx_ul_ud(bctx, tbf->tlli, &qos_profile, llc_pdu);
}

void gprs_rlcmac_downlink_assignment(gprs_rlcmac_tbf *tbf)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u TLLI: 0x%08x Immidiate Assignment (CCCH)\n", tbf->tfi, tbf->tlli);
	bitvec *immediate_assignment = bitvec_alloc(23);
	bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	int len = write_immediate_assignment(immediate_assignment, 1, 125, get_current_fn(), tbf->ta, tbf->arfcn, tbf->ts, tbf->tsc, tbf->tfi, tbf->tlli);
	pcu_l1if_tx_agch(immediate_assignment, len);
	bitvec_free(immediate_assignment);
}

void gprs_rlcmac_packet_downlink_assignment(gprs_rlcmac_tbf *tbf)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u TLLI: 0x%08x Packet DL Assignment\n", tbf->tfi, tbf->tlli);
	bitvec *packet_downlink_assignment_vec = bitvec_alloc(23);
	bitvec_unhex(packet_downlink_assignment_vec, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlink_t * packet_downlink_assignment = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	write_packet_downlink_assignment(packet_downlink_assignment, tbf->tfi, tbf->arfcn, tbf->ts, tbf->ta, tbf->tsc);
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ TX : Packet Downlink Assignment +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink(packet_downlink_assignment_vec, packet_downlink_assignment);
	LOGPC(DRLCMAC, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- TX : Packet Downlink Assignment -------------------------\n");
	free(packet_downlink_assignment);
	gprs_rlcmac_enqueue_block(packet_downlink_assignment_vec, 23);
	bitvec_free(packet_downlink_assignment_vec);
}

