/* gsm_rlcmac.c
 * Routines for GSM RLC MAC control plane message dissection in wireshark.
 * TS 44.060 and 24.008
 *
 * Copyright (C) 2011 Ivan Klyuchnikov
 *
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
 * Copyright (c) 2011 ST-Ericsson
 *
 * $Id: packet-gsm_rlcmac.c 39164 2011-09-27 12:05:32Z etxrab $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

extern "C" {
#include <osmocom/core/utils.h>
}

#include "gsm_rlcmac.h"
/* Initialize the protocol and registered fields
*/
#include <iostream>
#include <cstdlib>
#include <assert.h>
#include <gprs_debug.h>
using namespace std;

/* Payload type as defined in TS 44.060 / 10.4.7 */
#define PAYLOAD_TYPE_DATA              0
#define PAYLOAD_TYPE_CTRL_NO_OPT_OCTET 1
#define PAYLOAD_TYPE_CTRL_OPT_OCTET    2
#define PAYLOAD_TYPE_RESERVED          3

/* CSN1 structures */
/*(not all parts of CSN_DESCR structure are always initialized.)*/
static const
CSN_DESCR_BEGIN(PLMN_t)
  M_UINT       (PLMN_t,  MCC2,  4),
  M_UINT       (PLMN_t,  MCC1,  4),
  M_UINT       (PLMN_t,  MNC3,  4),
  M_UINT       (PLMN_t,  MCC3,  4),
  M_UINT       (PLMN_t,  MNC2,  4),
  M_UINT       (PLMN_t,  MNC1,  4),
CSN_DESCR_END  (PLMN_t)

static const
CSN_DESCR_BEGIN(StartingTime_t)
  M_UINT       (StartingTime_t,  N32,  5),
  M_UINT       (StartingTime_t,  N51,  6),
  M_UINT       (StartingTime_t,  N26,  5),
CSN_DESCR_END  (StartingTime_t)

/*< Global TFI IE >*/
static const
CSN_DESCR_BEGIN(Global_TFI_t)
  M_UNION      (Global_TFI_t, 2),
  M_UINT       (Global_TFI_t,  u.UPLINK_TFI,  5),
  M_UINT       (Global_TFI_t,  u.DOWNLINK_TFI,  5),
CSN_DESCR_END  (Global_TFI_t)

/*< Starting Frame Number Description IE >*/
static const
CSN_DESCR_BEGIN(Starting_Frame_Number_t)
  M_UNION      (Starting_Frame_Number_t, 2),
  M_TYPE       (Starting_Frame_Number_t, u.StartingTime, StartingTime_t),
  M_UINT       (Starting_Frame_Number_t,  u.k,  13),
CSN_DESCR_END(Starting_Frame_Number_t)

/*< Ack/Nack Description IE >*/
static const
CSN_DESCR_BEGIN(Ack_Nack_Description_t)
  M_UINT       (Ack_Nack_Description_t,  FINAL_ACK_INDICATION, 1),
  M_UINT       (Ack_Nack_Description_t,  STARTING_SEQUENCE_NUMBER,  7),
  M_BITMAP     (Ack_Nack_Description_t, RECEIVED_BLOCK_BITMAP, 64),
CSN_DESCR_END  (Ack_Nack_Description_t)

/*< Packet Timing Advance IE >*/
static const
CSN_DESCR_BEGIN(Packet_Timing_Advance_t)
  M_NEXT_EXIST (Packet_Timing_Advance_t, Exist_TIMING_ADVANCE_VALUE, 1),
  M_UINT       (Packet_Timing_Advance_t,  TIMING_ADVANCE_VALUE,  6),

  M_NEXT_EXIST (Packet_Timing_Advance_t, Exist_IndexAndtimeSlot, 2),
  M_UINT       (Packet_Timing_Advance_t,  TIMING_ADVANCE_INDEX,  4),
  M_UINT       (Packet_Timing_Advance_t,  TIMING_ADVANCE_TIMESLOT_NUMBER,  3),
CSN_DESCR_END  (Packet_Timing_Advance_t)

/*< Power Control Parameters IE >*/
static const
CSN_DESCR_BEGIN(GPRS_Power_Control_Parameters_t)
  M_UINT       (GPRS_Power_Control_Parameters_t,  ALPHA,  4),
  M_UINT       (GPRS_Power_Control_Parameters_t,  T_AVG_W,  5),
  M_UINT       (GPRS_Power_Control_Parameters_t,  T_AVG_T,  5),
  M_UINT       (GPRS_Power_Control_Parameters_t,  PC_MEAS_CHAN, 1),
  M_UINT       (GPRS_Power_Control_Parameters_t,  N_AVG_I,  4),
CSN_DESCR_END  (GPRS_Power_Control_Parameters_t)

/*< Global Power Control Parameters IE >*/
static const
CSN_DESCR_BEGIN(Global_Power_Control_Parameters_t)
  M_UINT       (Global_Power_Control_Parameters_t,  ALPHA,  4),
  M_UINT       (Global_Power_Control_Parameters_t,  T_AVG_W,  5),
  M_UINT       (Global_Power_Control_Parameters_t,  T_AVG_T,  5),
  M_UINT       (Global_Power_Control_Parameters_t,  Pb,  4),
  M_UINT       (Global_Power_Control_Parameters_t,  PC_MEAS_CHAN,  1),
  M_UINT       (Global_Power_Control_Parameters_t,  INT_MEAS_CHANNEL_LIST_AVAIL,  1),
  M_UINT       (Global_Power_Control_Parameters_t,  N_AVG_I,  4),
CSN_DESCR_END  (Global_Power_Control_Parameters_t)

/*< Global Packet Timing Advance IE >*/
static const
CSN_DESCR_BEGIN(Global_Packet_Timing_Advance_t)
  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_TIMING_ADVANCE_VALUE, 1),
  M_UINT       (Global_Packet_Timing_Advance_t,  TIMING_ADVANCE_VALUE,  6),

  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_UPLINK_TIMING_ADVANCE, 2),
  M_UINT       (Global_Packet_Timing_Advance_t,  UPLINK_TIMING_ADVANCE_INDEX,  4),
  M_UINT       (Global_Packet_Timing_Advance_t,  UPLINK_TIMING_ADVANCE_TIMESLOT_NUMBER,  3),

  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_DOWNLINK_TIMING_ADVANCE, 2),
  M_UINT       (Global_Packet_Timing_Advance_t,  DOWNLINK_TIMING_ADVANCE_INDEX,  4),
  M_UINT       (Global_Packet_Timing_Advance_t,  DOWNLINK_TIMING_ADVANCE_TIMESLOT_NUMBER,  3),
CSN_DESCR_END  (Global_Packet_Timing_Advance_t)

/*< Channel Quality Report struct >*/
static const
CSN_DESCR_BEGIN(Channel_Quality_Report_t)
  M_UINT       (Channel_Quality_Report_t,  C_VALUE,  6),
  M_UINT       (Channel_Quality_Report_t,  RXQUAL,  3),
  M_UINT       (Channel_Quality_Report_t,  SIGN_VAR,  6),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[0].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[0].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[1].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[1].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[2].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[2].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[3].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[3].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[4].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[4].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[5].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[5].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[6].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[6].I_LEVEL_TN,  4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[7].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[7].I_LEVEL_TN,  4),
CSN_DESCR_END  (Channel_Quality_Report_t)

/*< EGPRS Ack/Nack Description struct >*/
static const
CSN_DESCR_BEGIN   (EGPRS_AckNack_Desc_t)
  M_UINT          (EGPRS_AckNack_Desc_t,  FINAL_ACK_INDICATION,  1),
  M_UINT          (EGPRS_AckNack_Desc_t,  BEGINNING_OF_WINDOW,  1),
  M_UINT          (EGPRS_AckNack_Desc_t,  END_OF_WINDOW,  1),
  M_UINT          (EGPRS_AckNack_Desc_t,  STARTING_SEQUENCE_NUMBER,  11),

  M_NEXT_EXIST    (EGPRS_AckNack_Desc_t,  Exist_CRBB, 3),
  M_UINT          (EGPRS_AckNack_Desc_t,  CRBB_LENGTH,  7),
  M_UINT          (EGPRS_AckNack_Desc_t,  CRBB_STARTING_COLOR_CODE,  1),
  M_LEFT_VAR_BMP  (EGPRS_AckNack_Desc_t,  CRBB, CRBB_LENGTH, 0),

  M_LEFT_VAR_BMP_1(EGPRS_AckNack_Desc_t,  URBB, URBB_LENGTH, 0),
CSN_DESCR_END     (EGPRS_AckNack_Desc_t)

/*< EGPRS Ack/Nack Description IE >*/
gint16 Egprs_Ack_Nack_Desc_w_len_Dissector(csnStream_t* ar, bitvec *vector, unsigned *readIndex, void* data)
{
  if (ar->direction == 0)
  {
    return csnStreamEncoder(ar, CSNDESCR(EGPRS_AckNack_Desc_t), vector, readIndex, data);
  }
  else
  {
    return csnStreamDecoder(ar, CSNDESCR(EGPRS_AckNack_Desc_t), vector, readIndex, data);
  }
}

/* this intermediate structure is only required because M_SERIALIZE cannot be used as a member of M_UNION */
static const
CSN_DESCR_BEGIN(EGPRS_AckNack_w_len_t)
  M_SERIALIZE  (EGPRS_AckNack_w_len_t, Desc, 8, Egprs_Ack_Nack_Desc_w_len_Dissector),
CSN_DESCR_END  (EGPRS_AckNack_w_len_t)

static const
CSN_DESCR_BEGIN(EGPRS_AckNack_t)
  M_UNION      (EGPRS_AckNack_t,  2),
  M_TYPE       (EGPRS_AckNack_t, Desc, EGPRS_AckNack_Desc_t),
  M_TYPE       (EGPRS_AckNack_t, Desc, EGPRS_AckNack_w_len_t),
CSN_DESCR_END  (EGPRS_AckNack_t)

/*<P1 Rest Octets>*/
/*<P2 Rest Octets>*/
static const
CSN_DESCR_BEGIN(MobileAllocationIE_t)
  M_UINT       (MobileAllocationIE_t,  Length,  8),
  M_VAR_ARRAY  (MobileAllocationIE_t, MA, Length, 0),
CSN_DESCR_END  (MobileAllocationIE_t)

static const
CSN_DESCR_BEGIN(SingleRFChannel_t)
  M_UINT       (SingleRFChannel_t,  spare,  2),
  M_UINT       (SingleRFChannel_t,  ARFCN,  10),
CSN_DESCR_END  (SingleRFChannel_t)

static const
CSN_DESCR_BEGIN(RFHoppingChannel_t)
  M_UINT       (RFHoppingChannel_t,  MAIO,  6),
  M_UINT       (RFHoppingChannel_t,  HSN,  6),
CSN_DESCR_END  (RFHoppingChannel_t)

static const
CSN_DESCR_BEGIN(MobileAllocation_or_Frequency_Short_List_t)
  M_UNION      (MobileAllocation_or_Frequency_Short_List_t, 2),
  M_BITMAP     (MobileAllocation_or_Frequency_Short_List_t, u.Frequency_Short_List, 64),
  M_TYPE       (MobileAllocation_or_Frequency_Short_List_t, u.MA, MobileAllocationIE_t),
CSN_DESCR_END  (MobileAllocation_or_Frequency_Short_List_t)

static const
CSN_DESCR_BEGIN(Channel_Description_t)
  M_UINT       (Channel_Description_t,  Channel_type_and_TDMA_offset,  5),
  M_UINT       (Channel_Description_t,  TN,  3),
  M_UINT       (Channel_Description_t,  TSC,  3),

  M_UNION      (Channel_Description_t, 2),
  M_TYPE       (Channel_Description_t, u.SingleRFChannel, SingleRFChannel_t),
  M_TYPE       (Channel_Description_t, u.RFHoppingChannel, RFHoppingChannel_t),
CSN_DESCR_END(Channel_Description_t)

static const
CSN_DESCR_BEGIN(Group_Channel_Description_t)
  M_TYPE       (Group_Channel_Description_t, Channel_Description, Channel_Description_t),

  M_NEXT_EXIST (Group_Channel_Description_t, Exist_Hopping, 1),
  M_TYPE       (Group_Channel_Description_t, MA_or_Frequency_Short_List, MobileAllocation_or_Frequency_Short_List_t),
CSN_DESCR_END  (Group_Channel_Description_t)

static const
CSN_DESCR_BEGIN(Group_Call_Reference_t)
  M_UINT       (Group_Call_Reference_t,  value,  27),
  M_UINT       (Group_Call_Reference_t,  SF, 1),
  M_UINT       (Group_Call_Reference_t,  AF, 1),
  M_UINT       (Group_Call_Reference_t,  call_priority,  3),
  M_UINT       (Group_Call_Reference_t,  Ciphering_information,  4),
CSN_DESCR_END  (Group_Call_Reference_t)

static const
CSN_DESCR_BEGIN(Group_Call_information_t)
  M_TYPE       (Group_Call_information_t, Group_Call_Reference, Group_Call_Reference_t),

  M_NEXT_EXIST (Group_Call_information_t, Exist_Group_Channel_Description, 1),
  M_TYPE       (Group_Call_information_t, Group_Channel_Description, Group_Channel_Description_t),
CSN_DESCR_END (Group_Call_information_t)

static const
CSN_DESCR_BEGIN  (P1_Rest_Octets_t)
  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_NLN_PCH_and_NLN_status, 2),
  M_UINT         (P1_Rest_Octets_t,  NLN_PCH,  2),
  M_UINT         (P1_Rest_Octets_t,  NLN_status,  1),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P1_Rest_Octets_t,  Priority1,  3),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P1_Rest_Octets_t,  Priority2,  3),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Group_Call_information, 1),
  M_TYPE         (P1_Rest_Octets_t, Group_Call_information, Group_Call_information_t),

  M_UINT_LH      (P1_Rest_Octets_t,  Packet_Page_Indication_1,  1),
  M_UINT_LH      (P1_Rest_Octets_t,  Packet_Page_Indication_2,  1),
CSN_DESCR_END    (P1_Rest_Octets_t)

static const
CSN_DESCR_BEGIN  (P2_Rest_Octets_t)
  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_CN3, 1),
  M_UINT         (P2_Rest_Octets_t,  CN3,  2),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_NLN_and_status, 2),
  M_UINT         (P2_Rest_Octets_t,  NLN,  2),
  M_UINT         (P2_Rest_Octets_t,  NLN_status,  1),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority1,  3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority2,  3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority3, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority3,  3),

  M_UINT_LH      (P2_Rest_Octets_t,  Packet_Page_Indication_3,  1),
CSN_DESCR_END    (P2_Rest_Octets_t)


/* <IA Rest Octets>
 * Note!!
 * - first two bits skipped and frequencyparameters skipped
 * - additions for R99 and EGPRS added
 */
static const
CSN_DESCR_BEGIN(DynamicAllocation_t)
  M_UINT       (DynamicAllocation_t,  USF,  3),
  M_UINT       (DynamicAllocation_t,  USF_GRANULARITY,  1),

  M_NEXT_EXIST (DynamicAllocation_t, Exist_P0_PR_MODE, 2),
  M_UINT       (DynamicAllocation_t,  P0,  4),
  M_UINT       (DynamicAllocation_t,  PR_MODE,  1),
CSN_DESCR_END  (DynamicAllocation_t)

static const
CSN_DESCR_BEGIN(EGPRS_TwoPhaseAccess_t)
  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_ALPHA, 1),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  ALPHA,  4),

  M_UINT       (EGPRS_TwoPhaseAccess_t,  GAMMA,  5),
  M_TYPE       (EGPRS_TwoPhaseAccess_t, TBF_STARTING_TIME, StartingTime_t),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  NR_OF_RADIO_BLOCKS_ALLOCATED,  2),

  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  P0,  4),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  BTS_PWR_CTRL_MODE,  1),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  PR_MODE,  1),
CSN_DESCR_END  (EGPRS_TwoPhaseAccess_t)

static const
CSN_DESCR_BEGIN(EGPRS_OnePhaseAccess_t)
  M_UINT       (EGPRS_OnePhaseAccess_t,  TFI_ASSIGNMENT,  5),
  M_UINT       (EGPRS_OnePhaseAccess_t,  POLLING,  1),

  M_UNION      (EGPRS_OnePhaseAccess_t, 2),
  M_TYPE       (EGPRS_OnePhaseAccess_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR    (EGPRS_OnePhaseAccess_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT       (EGPRS_OnePhaseAccess_t,  EGPRS_CHANNEL_CODING_COMMAND,  4),
  M_UINT       (EGPRS_OnePhaseAccess_t,  TLLI_BLOCK_CHANNEL_CODING,  1),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  BEP_PERIOD2,  4),

  M_UINT       (EGPRS_OnePhaseAccess_t,  RESEGMENT,  1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  EGPRS_WindowSize,  5),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_ALPHA, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  ALPHA,  4),

  M_UINT       (EGPRS_OnePhaseAccess_t,  GAMMA,  5),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  TIMING_ADVANCE_INDEX,  4),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE       (EGPRS_OnePhaseAccess_t, TBF_STARTING_TIME, StartingTime_t),
CSN_DESCR_END  (EGPRS_OnePhaseAccess_t)

static const
CSN_DESCR_BEGIN(IA_EGPRS_00_t)
  M_UINT       (IA_EGPRS_00_t,  ExtendedRA,  5),

  M_REC_ARRAY  (IA_EGPRS_00_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UNION      (IA_EGPRS_00_t, 2),
  M_TYPE       (IA_EGPRS_00_t, Access.TwoPhaseAccess, EGPRS_TwoPhaseAccess_t),
  M_TYPE       (IA_EGPRS_00_t, Access.OnePhaseAccess, EGPRS_OnePhaseAccess_t),
CSN_DESCR_END  (IA_EGPRS_00_t)

static const
CSN_ChoiceElement_t IA_EGPRS_Choice[] =
{
  {2, 0x00, 0, M_TYPE   (IA_EGPRS_t, u.IA_EGPRS_PUA, IA_EGPRS_00_t)},
  {2, 0x01, 0, CSN_ERROR(IA_EGPRS_t, "01 <IA_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED)},
  {1, 0x01, 0, CSN_ERROR(IA_EGPRS_t, "1 <IA_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED)}
};

/* Please observe the double usage of UnionType element.
 * First, it is used to store the second bit of LL/LH identification of EGPRS contents.
 * Thereafter, UnionType will be used to store the index to detected choice.
 */
static const
CSN_DESCR_BEGIN(IA_EGPRS_t)
  M_UINT       (IA_EGPRS_t,  UnionType ,  1 ),
  M_CHOICE     (IA_EGPRS_t, UnionType, IA_EGPRS_Choice, ElementsOf(IA_EGPRS_Choice)),
CSN_DESCR_END  (IA_EGPRS_t)

static const
CSN_DESCR_BEGIN(IA_FreqParamsBeforeTime_t)
  M_UINT       (IA_FreqParamsBeforeTime_t,  Length,  6),
  M_UINT       (IA_FreqParamsBeforeTime_t,  MAIO,  6),
  M_VAR_ARRAY  (IA_FreqParamsBeforeTime_t, MobileAllocation, Length, 8),
CSN_DESCR_END  (IA_FreqParamsBeforeTime_t)

static const
CSN_DESCR_BEGIN  (GPRS_SingleBlockAllocation_t)
  M_NEXT_EXIST   (GPRS_SingleBlockAllocation_t, Exist_ALPHA, 1),
  M_UINT         (GPRS_SingleBlockAllocation_t,  ALPHA,  4),

  M_UINT         (GPRS_SingleBlockAllocation_t,  GAMMA,  5),
  M_FIXED        (GPRS_SingleBlockAllocation_t, 2, 0x01),
  M_TYPE         (GPRS_SingleBlockAllocation_t, TBF_STARTING_TIME, StartingTime_t), /*bit(16)*/

  M_NEXT_EXIST_LH(GPRS_SingleBlockAllocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT         (GPRS_SingleBlockAllocation_t,  P0,  4),
  M_UINT         (GPRS_SingleBlockAllocation_t,  BTS_PWR_CTRL_MODE,  1),
  M_UINT         (GPRS_SingleBlockAllocation_t,  PR_MODE,  1),
CSN_DESCR_END    (GPRS_SingleBlockAllocation_t)

static const
CSN_DESCR_BEGIN  (GPRS_DynamicOrFixedAllocation_t)
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TFI_ASSIGNMENT,  5),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  POLLING,  1),

  M_UNION        (GPRS_DynamicOrFixedAllocation_t, 2),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR      (GPRS_DynamicOrFixedAllocation_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  CHANNEL_CODING_COMMAND,  2),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TLLI_BLOCK_CHANNEL_CODING,  1),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_ALPHA, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  ALPHA,  4),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  GAMMA,  5),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TIMING_ADVANCE_INDEX,  4),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, TBF_STARTING_TIME, StartingTime_t),
CSN_DESCR_END    (GPRS_DynamicOrFixedAllocation_t)

static const
CSN_DESCR_BEGIN(PU_IA_AdditionsR99_t)
  M_NEXT_EXIST (PU_IA_AdditionsR99_t, Exist_ExtendedRA, 1),
  M_UINT       (PU_IA_AdditionsR99_t,  ExtendedRA,  5),
CSN_DESCR_END  (PU_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN          (Packet_Uplink_ImmAssignment_t)
  M_UNION                (Packet_Uplink_ImmAssignment_t, 2),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.SingleBlockAllocation, GPRS_SingleBlockAllocation_t),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.DynamicOrFixedAllocation, GPRS_DynamicOrFixedAllocation_t),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Uplink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, AdditionsR99, PU_IA_AdditionsR99_t),
CSN_DESCR_END            (Packet_Uplink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN(PD_IA_AdditionsR99_t)
  M_UINT       (PD_IA_AdditionsR99_t,  EGPRS_WindowSize,  5),
  M_UINT       (PD_IA_AdditionsR99_t,  LINK_QUALITY_MEASUREMENT_MODE,  2),

  M_NEXT_EXIST (PD_IA_AdditionsR99_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (PD_IA_AdditionsR99_t,  BEP_PERIOD2,  4),
CSN_DESCR_END  (PD_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(Packet_Downlink_ImmAssignment_t)
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TLLI,  32),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TFI_to_TA_VALID, 6 + 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TFI_ASSIGNMENT,  5),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  RLC_MODE,  1),
  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_ALPHA, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  ALPHA,  4),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  GAMMA,  5),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  POLLING,  1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TA_VALID,  1),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TIMING_ADVANCE_INDEX,  4),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, TBF_STARTING_TIME, StartingTime_t),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_P0_PR_MODE, 3),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  P0,  4),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  BTS_PWR_CTRL_MODE,  1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  PR_MODE,  1),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Downlink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, AdditionsR99, PD_IA_AdditionsR99_t),
CSN_DESCR_END  (Packet_Downlink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN          (Second_Part_Packet_Assignment_t)
  M_NEXT_EXIST_OR_NULL_LH(Second_Part_Packet_Assignment_t, Exist_SecondPart, 2),
  M_NEXT_EXIST           (Second_Part_Packet_Assignment_t, Exist_ExtendedRA, 1),
  M_UINT                 (Second_Part_Packet_Assignment_t,  ExtendedRA,  5),
CSN_DESCR_END            (Second_Part_Packet_Assignment_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_UL_DL_t)
  M_UNION      (IA_PacketAssignment_UL_DL_t, 2),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Uplink_ImmAssignment, Packet_Uplink_ImmAssignment_t),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Downlink_ImmAssignment, Packet_Downlink_ImmAssignment_t),
CSN_DESCR_END  (IA_PacketAssignment_UL_DL_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_t)
  M_UNION      (IA_PacketAssignment_t, 2),
  M_TYPE       (IA_PacketAssignment_t, u.UplinkDownlinkAssignment, IA_PacketAssignment_UL_DL_t),
  M_TYPE       (IA_PacketAssignment_t, u.UplinkDownlinkAssignment, Second_Part_Packet_Assignment_t),
CSN_DESCR_END  (IA_PacketAssignment_t)

/* <Packet Polling Request> */
static const
CSN_ChoiceElement_t PacketPollingID[] =
{
  {1, 0,    0, M_TYPE(PacketPollingID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketPollingID_t, u.TLLI, 32)},
  {3, 0x06, 0, M_UINT(PacketPollingID_t, u.TQI, 16)},
/*{3, 0x07 , 0, M_TYPE(PacketUplinkID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},*/
};

static const
CSN_DESCR_BEGIN(PacketPollingID_t)
  M_CHOICE     (PacketPollingID_t, UnionType, PacketPollingID, ElementsOf(PacketPollingID)),
CSN_DESCR_END  (PacketPollingID_t)

static const
CSN_DESCR_BEGIN(Packet_Polling_Request_t)
  M_UINT       (Packet_Polling_Request_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Polling_Request_t,  PAGE_MODE,  2),
  M_TYPE       (Packet_Polling_Request_t, ID, PacketPollingID_t),
  M_UINT       (Packet_Polling_Request_t,  TYPE_OF_ACK, 1),
  M_PADDING_BITS(Packet_Polling_Request_t),
CSN_DESCR_END  (Packet_Polling_Request_t)

static const
CSN_DESCR_BEGIN(MobileAllocation_t)
  M_UINT_OFFSET(MobileAllocation_t, MA_BitLength, 6, 1),
  M_VAR_BITMAP (MobileAllocation_t, MA_BITMAP, MA_BitLength, 0),
CSN_DESCR_END  (MobileAllocation_t)

static const
CSN_DESCR_BEGIN(ARFCN_index_list_t)
  M_REC_ARRAY  (ARFCN_index_list_t, ARFCN_INDEX, ElementsOf_ARFCN_INDEX, 6),
CSN_DESCR_END  (ARFCN_index_list_t)

static const
CSN_DESCR_BEGIN(GPRS_Mobile_Allocation_t)
  M_UINT       (GPRS_Mobile_Allocation_t,  HSN,  6),
  M_REC_ARRAY  (GPRS_Mobile_Allocation_t, RFL_NUMBER, ElementsOf_RFL_NUMBER, 4),
  M_UNION      (GPRS_Mobile_Allocation_t, 2),
  M_TYPE       (GPRS_Mobile_Allocation_t, u.MA, MobileAllocation_t),
  M_TYPE       (GPRS_Mobile_Allocation_t, u.ARFCN_index_list, ARFCN_index_list_t),
CSN_DESCR_END  (GPRS_Mobile_Allocation_t)

/*< SI 13 Rest Octets >*/
static const
CSN_DESCR_BEGIN (Extension_Bits_t)
  M_UINT_OFFSET (Extension_Bits_t, extension_length, 6, 1),
  M_LEFT_VAR_BMP(Extension_Bits_t, Extension_Info, extension_length, 0),
CSN_DESCR_END   (Extension_Bits_t)

static const
CSN_DESCR_BEGIN(GPRS_Cell_Options_t)
  M_UINT       (GPRS_Cell_Options_t,  NMO,  2),
  M_UINT        (GPRS_Cell_Options_t, T3168, 3),
  M_UINT        (GPRS_Cell_Options_t, T3192, 3),
  M_UINT       (GPRS_Cell_Options_t,  DRX_TIMER_MAX,  3),
  M_UINT       (GPRS_Cell_Options_t,  ACCESS_BURST_TYPE, 1),
  M_UINT       (GPRS_Cell_Options_t,  CONTROL_ACK_TYPE, 1),
  M_UINT       (GPRS_Cell_Options_t,  BS_CV_MAX,  4),

  M_NEXT_EXIST (GPRS_Cell_Options_t, Exist_PAN, 3),
  M_UINT       (GPRS_Cell_Options_t,  PAN_DEC,  3),
  M_UINT       (GPRS_Cell_Options_t,  PAN_INC,  3),
  M_UINT       (GPRS_Cell_Options_t,  PAN_MAX,  3),

  M_NEXT_EXIST (GPRS_Cell_Options_t, Exist_Extension_Bits, 1),
  M_TYPE       (GPRS_Cell_Options_t, Extension_Bits, Extension_Bits_t),
CSN_DESCR_END  (GPRS_Cell_Options_t)

static const
CSN_DESCR_BEGIN(PBCCH_Not_present_t)
  M_UINT       (PBCCH_Not_present_t,  RAC,  8),
  M_UINT       (PBCCH_Not_present_t,  SPGC_CCCH_SUP, 1),
  M_UINT       (PBCCH_Not_present_t,  PRIORITY_ACCESS_THR,  3),
  M_UINT       (PBCCH_Not_present_t,  NETWORK_CONTROL_ORDER,  2),
  M_TYPE       (PBCCH_Not_present_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE       (PBCCH_Not_present_t, GPRS_Power_Control_Parameters, GPRS_Power_Control_Parameters_t),
CSN_DESCR_END  (PBCCH_Not_present_t)

static const
CSN_ChoiceElement_t SI13_PBCCH_Description_Channel[] =
{/* this one is used in SI13*/
  {2, 0x00, 0, M_NULL(PBCCH_Description_t, u.dummy, 0)},/*Default to BCCH carrier*/
  {2, 0x01, 0, M_UINT(PBCCH_Description_t, u.ARFCN, 10)},
  {1, 0x01, 0, M_UINT(PBCCH_Description_t, u.MAIO, 6)},
};

static const
CSN_DESCR_BEGIN(PBCCH_Description_t)/*SI13*/
  M_UINT       (PBCCH_Description_t,  Pb,  4),
  M_UINT       (PBCCH_Description_t,  TSC,  3),
  M_UINT       (PBCCH_Description_t,  TN,  3),

  M_CHOICE     (PBCCH_Description_t, UnionType, SI13_PBCCH_Description_Channel, ElementsOf(SI13_PBCCH_Description_Channel)),
CSN_DESCR_END  (PBCCH_Description_t)

static const
CSN_DESCR_BEGIN(PBCCH_present_t)
  M_UINT       (PBCCH_present_t,  PSI1_REPEAT_PERIOD,  4),
  M_TYPE       (PBCCH_present_t, PBCCH_Description, PBCCH_Description_t),
CSN_DESCR_END  (PBCCH_present_t)

static const
CSN_DESCR_BEGIN(SI13_AdditionsR6)
  M_NEXT_EXIST (SI13_AdditionsR6, Exist_LB_MS_TXPWR_MAX_CCH, 1),
  M_UINT       (SI13_AdditionsR6,  LB_MS_TXPWR_MAX_CCH,  5),
  M_UINT       (SI13_AdditionsR6,  SI2n_SUPPORT,  2),
CSN_DESCR_END  (SI13_AdditionsR6)

static const
CSN_DESCR_BEGIN(SI13_AdditionsR4)
  M_UINT       (SI13_AdditionsR4,  SI_STATUS_IND,  1),
  M_NEXT_EXIST_OR_NULL_LH (SI13_AdditionsR4, Exist_AdditionsR6, 1),
  M_TYPE       (SI13_AdditionsR4,  AdditionsR6, SI13_AdditionsR6),
CSN_DESCR_END  (SI13_AdditionsR4)

static const
CSN_DESCR_BEGIN(SI13_AdditionR99)
  M_UINT       (SI13_AdditionR99,  SGSNR,  1),
  M_NEXT_EXIST_OR_NULL_LH (SI13_AdditionR99, Exist_AdditionsR4, 1),
  M_TYPE       (SI13_AdditionR99,  AdditionsR4, SI13_AdditionsR4),
CSN_DESCR_END  (SI13_AdditionR99)

static const
CSN_DESCR_BEGIN          (SI_13_t)
  M_THIS_EXIST_LH        (SI_13_t),

  M_UINT                 (SI_13_t,  BCCH_CHANGE_MARK,  3),
  M_UINT                 (SI_13_t,  SI_CHANGE_FIELD,  4),

  M_NEXT_EXIST           (SI_13_t, Exist_MA, 2),
  M_UINT                 (SI_13_t,  SI13_CHANGE_MARK,  2),
  M_TYPE                 (SI_13_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),

  M_UNION                (SI_13_t, 2),
  M_TYPE                 (SI_13_t, u.PBCCH_Not_present, PBCCH_Not_present_t),
  M_TYPE                 (SI_13_t, u.PBCCH_present, PBCCH_present_t),

  M_NEXT_EXIST_OR_NULL_LH(SI_13_t, Exist_AdditionsR99, 1),
  M_TYPE                 (SI_13_t, AdditionsR99, SI13_AdditionR99),
CSN_DESCR_END            (SI_13_t)

/************************************************************/
/*                         TS 44.060 messages               */
/************************************************************/

/*< Packet TBF Release message content >*/
static const
CSN_DESCR_BEGIN(Packet_TBF_Release_t)
  M_UINT       (Packet_TBF_Release_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_TBF_Release_t,  PAGE_MODE,  2),
  M_FIXED      (Packet_TBF_Release_t, 1, 0x00),
  M_TYPE       (Packet_TBF_Release_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_TBF_Release_t,  UPLINK_RELEASE, 1),
  M_UINT       (Packet_TBF_Release_t,  DOWNLINK_RELEASE, 1),
  M_UINT       (Packet_TBF_Release_t,  TBF_RELEASE_CAUSE,  4),
  M_PADDING_BITS(Packet_TBF_Release_t ),
CSN_DESCR_END  (Packet_TBF_Release_t)

/*< Packet Control Acknowledgement message content >*/

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_AdditionsR6_t)
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR6_t, Exist_CTRL_ACK_Extension, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR6_t,  CTRL_ACK_Extension,  9),
CSN_DESCR_END          (Packet_Control_Acknowledgement_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_AdditionsR5_t)
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_TN_RRBP, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR5_t,  TN_RRBP,  3),
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_G_RNTI_Extension, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR5_t,  G_RNTI_Extension,  4),

  M_NEXT_EXIST_OR_NULL (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_AdditionsR6, 1),
  M_TYPE               (Packet_Control_Acknowledgement_AdditionsR5_t, AdditionsR6, Packet_Control_Acknowledgement_AdditionsR6_t),
CSN_DESCR_END          (Packet_Control_Acknowledgement_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_t)
  M_UINT               (Packet_Control_Acknowledgement_t,  PayloadType,  2),
  M_UINT               (Packet_Control_Acknowledgement_t,  spare,  5),
  M_BIT                (Packet_Control_Acknowledgement_t,  R),

  M_UINT               (Packet_Control_Acknowledgement_t,  MESSAGE_TYPE,  6),
  M_UINT               (Packet_Control_Acknowledgement_t,  TLLI,  32),
  M_UINT               (Packet_Control_Acknowledgement_t,  CTRL_ACK,  2),
  M_NEXT_EXIST_OR_NULL (Packet_Control_Acknowledgement_t, Exist_AdditionsR5, 1),
  M_TYPE               (Packet_Control_Acknowledgement_t, AdditionsR5, Packet_Control_Acknowledgement_AdditionsR5_t),
  M_PADDING_BITS       (Packet_Control_Acknowledgement_t),
CSN_DESCR_END  (Packet_Control_Acknowledgement_t)

/*< Packet Downlink Dummy Control Block message content >*/
static const
CSN_DESCR_BEGIN(Packet_Downlink_Dummy_Control_Block_t)
  M_UINT       (Packet_Downlink_Dummy_Control_Block_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Downlink_Dummy_Control_Block_t,  PAGE_MODE,  2),

  M_NEXT_EXIST (Packet_Downlink_Dummy_Control_Block_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (Packet_Downlink_Dummy_Control_Block_t, PERSISTENCE_LEVEL, 4, 4),
  M_PADDING_BITS(Packet_Downlink_Dummy_Control_Block_t ),
CSN_DESCR_END  (Packet_Downlink_Dummy_Control_Block_t)

/*< Packet Uplink Dummy Control Block message content >*/
static const
CSN_DESCR_BEGIN(Packet_Uplink_Dummy_Control_Block_t)
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t,  PayloadType,  2),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t,  spare,  5),
  M_BIT        (Packet_Uplink_Dummy_Control_Block_t,  R),

  M_UINT       (Packet_Uplink_Dummy_Control_Block_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t,  TLLI,  32),
/*M_FIXED      (Packet_Uplink_Dummy_Control_Block_t, 1, 0),*/
  M_PADDING_BITS(Packet_Uplink_Dummy_Control_Block_t),
CSN_DESCR_END  (Packet_Uplink_Dummy_Control_Block_t)

static const
CSN_DESCR_BEGIN(Receive_N_PDU_Number_t)
  M_UINT       (Receive_N_PDU_Number_t,  nsapi,  4),
  M_UINT       (Receive_N_PDU_Number_t,  value,  8),
CSN_DESCR_END  (Receive_N_PDU_Number_t)

gint16 Receive_N_PDU_Number_list_Dissector(csnStream_t* ar, bitvec *vector, unsigned *readIndex, void* data)
{
  if (ar->direction == 0)
  {
    return csnStreamEncoder(ar, CSNDESCR(Receive_N_PDU_Number_t), vector, readIndex, data);
  }
  else
  {
    return csnStreamDecoder(ar, CSNDESCR(Receive_N_PDU_Number_t), vector, readIndex, data);
  }
}

static const
CSN_DESCR_BEGIN(Receive_N_PDU_Number_list_t)
  M_SERIALIZE  (Receive_N_PDU_Number_list_t, IEI, 7, Receive_N_PDU_Number_list_Dissector),
  M_VAR_TARRAY (Receive_N_PDU_Number_list_t, Receive_N_PDU_Number, Receive_N_PDU_Number_t, Count_Receive_N_PDU_Number),
CSN_DESCR_END  (Receive_N_PDU_Number_list_t)

/*< MS Radio Access capability IE >*/
static const
CSN_DESCR_BEGIN       (DTM_EGPRS_t)
  M_NEXT_EXIST        (DTM_EGPRS_t, Exist_DTM_EGPRS_multislot_class, 1),
  M_UINT              (DTM_EGPRS_t,  DTM_EGPRS_multislot_class,  2),
CSN_DESCR_END         (DTM_EGPRS_t)

static const
CSN_DESCR_BEGIN       (DTM_EGPRS_HighMultislotClass_t)
  M_NEXT_EXIST        (DTM_EGPRS_HighMultislotClass_t, Exist_DTM_EGPRS_HighMultislotClass, 1),
  M_UINT              (DTM_EGPRS_HighMultislotClass_t,  DTM_EGPRS_HighMultislotClass,  3),
CSN_DESCR_END         (DTM_EGPRS_HighMultislotClass_t)

static const
CSN_DESCR_BEGIN       (DownlinkDualCarrierCapability_r7_t)
  M_NEXT_EXIST        (DownlinkDualCarrierCapability_r7_t, MultislotCapabilityReductionForDL_DualCarrier, 1),
  M_UINT              (DownlinkDualCarrierCapability_r7_t, DL_DualCarrierForDTM,  3),
CSN_DESCR_END         (DownlinkDualCarrierCapability_r7_t)

static const
CSN_DESCR_BEGIN       (Multislot_capability_t)
  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_HSCSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t,  HSCSD_multislot_class,  5),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_GPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t,  GPRS_multislot_class,  5),
  M_UINT              (Multislot_capability_t,  GPRS_Extended_Dynamic_Allocation_Capability,  1),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_SM, 2),
  M_UINT              (Multislot_capability_t,  SMS_VALUE,  4),
  M_UINT              (Multislot_capability_t,  SM_VALUE,  4),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_ECSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t,  ECSD_multislot_class,  5),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_EGPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t,  EGPRS_multislot_class,  5),
  M_UINT              (Multislot_capability_t,  EGPRS_Extended_Dynamic_Allocation_Capability,  1),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT              (Multislot_capability_t,  DTM_GPRS_multislot_class,  2),
  M_UINT              (Multislot_capability_t,  Single_Slot_DTM,  1),
  M_TYPE              (Multislot_capability_t, DTM_EGPRS_Params, DTM_EGPRS_t),
CSN_DESCR_END         (Multislot_capability_t)

static const
CSN_DESCR_BEGIN       (Content_t)
  M_UINT              (Content_t,  RF_Power_Capability,  3),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_A5_bits, 1),
  M_UINT_OR_NULL      (Content_t,  A5_bits,  7),

  M_UINT_OR_NULL      (Content_t,  ES_IND,  1),
  M_UINT_OR_NULL      (Content_t,  PS,  1),
  M_UINT_OR_NULL      (Content_t,  VGCS,  1),
  M_UINT_OR_NULL      (Content_t,  VBS,  1),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_Multislot_capability, 1),
  M_TYPE              (Content_t, Multislot_capability, Multislot_capability_t),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_Eight_PSK_Power_Capability, 1),
  M_UINT              (Content_t,  Eight_PSK_Power_Capability,  2),

  M_UINT_OR_NULL      (Content_t,  COMPACT_Interference_Measurement_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  Revision_Level_Indicator,  1),
  M_UINT_OR_NULL      (Content_t,  UMTS_FDD_Radio_Access_Technology_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  UMTS_384_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  CDMA2000_Radio_Access_Technology_Capability,  1),

  M_UINT_OR_NULL      (Content_t,  UMTS_128_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  GERAN_Feature_Package_1,  1),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_Extended_DTM_multislot_class, 2),
  M_UINT              (Content_t,  Extended_DTM_GPRS_multislot_class,  2),
  M_UINT              (Content_t,  Extended_DTM_EGPRS_multislot_class,  2),

  M_UINT_OR_NULL      (Content_t,  Modulation_based_multislot_class_support,  1),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_HighMultislotCapability, 1),
  M_UINT              (Content_t,  HighMultislotCapability,  2),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_GERAN_lu_ModeCapability, 1),
  M_UINT              (Content_t,  GERAN_lu_ModeCapability,  4),

  M_UINT_OR_NULL      (Content_t,  GMSK_MultislotPowerProfile,  2),
  M_UINT_OR_NULL      (Content_t,  EightPSK_MultislotProfile,  2),

  M_UINT_OR_NULL      (Content_t,  MultipleTBF_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  DownlinkAdvancedReceiverPerformance,  2),
  M_UINT_OR_NULL      (Content_t,  ExtendedRLC_MAC_ControlMessageSegmentionsCapability,  1),
  M_UINT_OR_NULL      (Content_t,  DTM_EnhancementsCapability,  1),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_DTM_GPRS_HighMultislotClass, 2),
  M_UINT              (Content_t,  DTM_GPRS_HighMultislotClass,  3),
  M_TYPE              (Content_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT_OR_NULL      (Content_t,  PS_HandoverCapability,  1),

  /* additions in release 7 */
  M_UINT_OR_NULL      (Content_t,  DTM_Handover_Capability,  1),
  M_NEXT_EXIST_OR_NULL(Content_t, Exist_DownlinkDualCarrierCapability_r7, 1),
  M_TYPE              (Content_t, DownlinkDualCarrierCapability_r7, DownlinkDualCarrierCapability_r7_t),

  M_UINT_OR_NULL      (Content_t,  FlexibleTimeslotAssignment,  1),
  M_UINT_OR_NULL      (Content_t,  GAN_PS_HandoverCapability,  1),
  M_UINT_OR_NULL      (Content_t,  RLC_Non_persistentMode,  1),
  M_UINT_OR_NULL      (Content_t,  ReducedLatencyCapability,  1),
  M_UINT_OR_NULL      (Content_t,  UplinkEGPRS2,  2),
  M_UINT_OR_NULL      (Content_t,  DownlinkEGPRS2,  2),

  /* additions in release 8 */
  M_UINT_OR_NULL      (Content_t,  EUTRA_FDD_Support,  1),
  M_UINT_OR_NULL      (Content_t,  EUTRA_TDD_Support,  1),
  M_UINT_OR_NULL      (Content_t,  GERAN_To_EUTRAN_supportInGERAN_PTM,  2),
  M_UINT_OR_NULL      (Content_t,  PriorityBasedReselectionSupport,  1),

CSN_DESCR_END         (Content_t)

gint16 Content_Dissector(csnStream_t* ar, bitvec *vector, unsigned *readIndex, void* data)
{
  if (ar->direction == 0)
    {
      return csnStreamEncoder(ar, CSNDESCR(Content_t), vector, readIndex, data);
    }
  else
    {
      return csnStreamDecoder(ar, CSNDESCR(Content_t), vector, readIndex, data);
    }
}

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_struct_t)
  M_UINT              (Additional_access_technologies_struct_t,  Access_Technology_Type,  4),
  M_UINT              (Additional_access_technologies_struct_t,  GMSK_Power_class,  3),
  M_UINT              (Additional_access_technologies_struct_t,  Eight_PSK_Power_class,  2),
CSN_DESCR_END         (Additional_access_technologies_struct_t)

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_t)
  M_REC_TARRAY        (Additional_access_technologies_t, Additional_access_technologies, Additional_access_technologies_struct_t, Count_additional_access_technologies),
CSN_DESCR_END         (Additional_access_technologies_t)

gint16 Additional_access_technologies_Dissector(csnStream_t* ar, bitvec* vector, unsigned *readIndex, void* data)
{
  if (ar->direction == 0)
  {
    return csnStreamEncoder(ar, CSNDESCR(Additional_access_technologies_t), vector, readIndex, data);
  }
  else
  {
    return csnStreamDecoder(ar, CSNDESCR(Additional_access_technologies_t), vector, readIndex, data);
  }
}

static const
CSN_ChoiceElement_t MS_RA_capability_value_Choice[] =
{
  {4, AccTech_GSMP,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSME,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMR,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1800,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1900,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM450,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM480,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM850,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM750,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT830,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT410,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT900,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM710,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT810,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMOther, 0, M_SERIALIZE (MS_RA_capability_value_t, u.Additional_access_technologies, 7, Additional_access_technologies_Dissector)}, /* Short Form */
};

static const
CSN_DESCR_BEGIN(MS_RA_capability_value_t)
  M_CHOICE     (MS_RA_capability_value_t, IndexOfAccTech, MS_RA_capability_value_Choice, ElementsOf(MS_RA_capability_value_Choice)),
CSN_DESCR_END  (MS_RA_capability_value_t)

static const
CSN_DESCR_BEGIN (MS_Radio_Access_capability_t)
/*Will be done in the main routines:*/
/*M_UINT        (MS_Radio_Access_capability_t,  IEI,  8),*/
/*M_UINT        (MS_Radio_Access_capability_t,  Length,  8),*/

  M_REC_TARRAY_1(MS_Radio_Access_capability_t, MS_RA_capability_value, MS_RA_capability_value_t, Count_MS_RA_capability_value),
CSN_DESCR_END   (MS_Radio_Access_capability_t)

/*< MS Classmark 3 IE >*/
static const
CSN_DESCR_BEGIN(ARC_t)
  M_UINT       (ARC_t,  A5_Bits,  4),
  M_UINT       (ARC_t,  Arc2_Spare,  4),
  M_UINT       (ARC_t,  Arc1,  4),
CSN_DESCR_END  (ARC_t)

static const
CSN_ChoiceElement_t MultibandChoice[] =
{
  {3, 0x00, 0, M_UINT(Multiband_t, u.A5_Bits, 4)},
  {3, 0x05, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x06, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x01, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x02, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x04, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
};

static const
CSN_DESCR_BEGIN(Multiband_t)
  M_CHOICE     (Multiband_t, Multiband, MultibandChoice, ElementsOf(MultibandChoice)),
CSN_DESCR_END  (Multiband_t)

static const
CSN_DESCR_BEGIN(EDGE_RF_Pwr_t)
  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap1, 1),
  M_UINT       (EDGE_RF_Pwr_t,  EDGE_RF_PwrCap1,  2),

  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap2, 1),
  M_UINT       (EDGE_RF_Pwr_t,  EDGE_RF_PwrCap2,  2),
CSN_DESCR_END  (EDGE_RF_Pwr_t)

static const
CSN_DESCR_BEGIN(MS_Class3_Unpacked_t)
  M_UINT       (MS_Class3_Unpacked_t,  Spare1,  1),
  M_TYPE       (MS_Class3_Unpacked_t, Multiband, Multiband_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_R_Support, 1),
  M_UINT       (MS_Class3_Unpacked_t,  R_GSM_Arc,  3),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  MultiSlotClass,  5),

  M_UINT       (MS_Class3_Unpacked_t,  UCS2,  1),
  M_UINT       (MS_Class3_Unpacked_t,  ExtendedMeasurementCapability,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_MeasurementCapability, 2),
  M_UINT       (MS_Class3_Unpacked_t,  SMS_VALUE,  4),
  M_UINT       (MS_Class3_Unpacked_t,  SM_VALUE,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_PositioningMethodCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  MS_PositioningMethod,  5),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  EDGE_MultiSlotClass,  5),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_Struct, 2),
  M_UINT       (MS_Class3_Unpacked_t,  ModulationCapability,  1),
  M_TYPE       (MS_Class3_Unpacked_t, EDGE_RF_PwrCaps, EDGE_RF_Pwr_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM400_Info, 2),
  M_UINT       (MS_Class3_Unpacked_t,  GSM400_Bands,  2),
  M_UINT       (MS_Class3_Unpacked_t,  GSM400_Arc,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM850_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM850_Arc,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_PCS1900_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t,  PCS1900_Arc,  4),

  M_UINT       (MS_Class3_Unpacked_t,  UMTS_FDD_Radio_Access_Technology_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  UMTS_384_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  CDMA2000_Radio_Access_Technology_Capability,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_GPRS_multislot_class,  2),
  M_UINT       (MS_Class3_Unpacked_t,  Single_Slot_DTM,  1),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_Params, DTM_EGPRS_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_SingleBandSupport, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM_Band,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM_700_Associated_Radio_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM_700_Associated_Radio_Capability,  4),

  M_UINT       (MS_Class3_Unpacked_t,  UMTS_128_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  GERAN_Feature_Package_1,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_Extended_DTM_multislot_class, 2),
  M_UINT       (MS_Class3_Unpacked_t,  Extended_DTM_GPRS_multislot_class,  2),
  M_UINT       (MS_Class3_Unpacked_t,  Extended_DTM_EGPRS_multislot_class,  2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_HighMultislotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  HighMultislotCapability,  2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GERAN_lu_ModeCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GERAN_lu_ModeCapability,  4),

  M_UINT       (MS_Class3_Unpacked_t,  GERAN_FeaturePackage_2,  1),

  M_UINT       (MS_Class3_Unpacked_t,  GMSK_MultislotPowerProfile,  2),
  M_UINT       (MS_Class3_Unpacked_t,  EightPSK_MultislotProfile,  2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_400_Bands, 2),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_400_BandsSupported,  2),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_400_AssociatedRadioCapability,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_900_AssociatedRadioCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_900_AssociatedRadioCapability,  4),

  M_UINT       (MS_Class3_Unpacked_t,  DownlinkAdvancedReceiverPerformance,  2),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_EnhancementsCapability,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_HighMultislotClass, 3),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_GPRS_HighMultislotClass,  3),
  M_UINT       (MS_Class3_Unpacked_t,  OffsetRequired,  1),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT       (MS_Class3_Unpacked_t,  RepeatedSACCH_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  Spare2,  1),
CSN_DESCR_END  (MS_Class3_Unpacked_t)

static const
CSN_DESCR_BEGIN(Channel_Request_Description_t)
  M_UINT       (Channel_Request_Description_t,  PEAK_THROUGHPUT_CLASS,  4),
  M_UINT       (Channel_Request_Description_t,  RADIO_PRIORITY,  2),
  M_UINT       (Channel_Request_Description_t,  RLC_MODE, 1),
  M_UINT       (Channel_Request_Description_t,  LLC_PDU_TYPE, 1),
  M_UINT       (Channel_Request_Description_t,  RLC_OCTET_COUNT,  16),
CSN_DESCR_END  (Channel_Request_Description_t)

/* < Packet Resource Request message content > */
static const
CSN_ChoiceElement_t PacketResourceRequestID[] =
{
  {1, 0,    0, M_TYPE(PacketResourceRequestID_t, u.Global_TFI, Global_TFI_t)},
  {1, 0x01, 0, M_UINT(PacketResourceRequestID_t, u.TLLI, 32)},
};

static const
CSN_DESCR_BEGIN(PacketResourceRequestID_t)
  M_CHOICE     (PacketResourceRequestID_t, UnionType, PacketResourceRequestID, ElementsOf(PacketResourceRequestID)),
CSN_DESCR_END  (PacketResourceRequestID_t)

static const
CSN_DESCR_BEGIN(BEP_MeasurementReport_t)
  M_NEXT_EXIST (BEP_MeasurementReport_t, Exist, 3),
  M_UNION      (BEP_MeasurementReport_t, 2),
  M_UINT       (BEP_MeasurementReport_t,  u.MEAN_BEP_GMSK,  4),
  M_UINT       (BEP_MeasurementReport_t,  u.MEAN_BEP_8PSK,  4),
CSN_DESCR_END  (BEP_MeasurementReport_t)

static const
CSN_DESCR_BEGIN(InterferenceMeasurementReport_t)
  M_NEXT_EXIST (InterferenceMeasurementReport_t, Exist, 1),
  M_UINT       (InterferenceMeasurementReport_t,  I_LEVEL,  4),
CSN_DESCR_END  (InterferenceMeasurementReport_t)

static const
CSN_DESCR_BEGIN(EGPRS_TimeslotLinkQualityMeasurements_t)
  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_t, Exist_BEP_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_t, BEP_MEASUREMENTS, BEP_MeasurementReport_t, 8),

  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_t, Exist_INTERFERENCE_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_t, INTERFERENCE_MEASUREMENTS, InterferenceMeasurementReport_t, 8),
CSN_DESCR_END  (EGPRS_TimeslotLinkQualityMeasurements_t)

static const
CSN_DESCR_BEGIN(EGPRS_BEP_LinkQualityMeasurements_t)
  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_t, Exist_MEAN_CV_BEP_GMSK, 2),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  MEAN_BEP_GMSK,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  CV_BEP_GMSK,  3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_t, Exist_MEAN_CV_BEP_8PSK, 2),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  MEAN_BEP_8PSK,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  CV_BEP_8PSK,  3),
CSN_DESCR_END  (EGPRS_BEP_LinkQualityMeasurements_t)

static const
CSN_DESCR_BEGIN(IU_Mode_Channel_Request_Desk_t)

  M_UINT       (IU_Mode_Channel_Request_Desk_t,  RB_ID,  5),
  M_UINT       (IU_Mode_Channel_Request_Desk_t,  RADIO_PRIORITY,  2),

  M_NEXT_EXIST (IU_Mode_Channel_Request_Desk_t, Exist_RLC_BLOCK_COUNT, 1),
  M_UINT       (IU_Mode_Channel_Request_Desk_t,  RLC_BLOCK_COUNT,  8),

  /* Don't use M_REC_TARRAY as we don't support multiple TBFs
  M_NEXT_EXIST (IU_Mode_Channel_Request_Desk_t, Exist_Iu_Mode_ChRequestDesk, 1),
  M_TYPE       (IU_Mode_Channel_Request_Desk1, IU_Mode_Channel_Request_Desk_t),*/
  M_UINT       (IU_Mode_Channel_Request_Desk_t, Exist_Iu_Mode_ChRequestDesk, 1),

CSN_DESCR_END  (IU_Mode_Channel_Request_Desk_t)

static const
CSN_DESCR_BEGIN(IU_Mode_Channel_Request_Desk_RNTI_t)

  M_NEXT_EXIST (IU_Mode_Channel_Request_Desk_RNTI_t, Exist_G_RNTI_Extension, 1),
  M_UINT       (IU_Mode_Channel_Request_Desk_RNTI_t,  G_RNTI_Extension,  4),

  M_TYPE       (IU_Mode_Channel_Request_Desk_RNTI_t, IU_Mode_Channel_Request_Desk, IU_Mode_Channel_Request_Desk_t),

CSN_DESCR_END  (IU_Mode_Channel_Request_Desk_RNTI_t)


static const
CSN_DESCR_BEGIN(Ext_Channel_Request_desc_t)

  M_UINT       (Ext_Channel_Request_desc_t,  PFI, 7),
  M_UINT       (Ext_Channel_Request_desc_t,  RADIO_PRIORITY,  2),
  M_UINT       (Ext_Channel_Request_desc_t,  RLC_Mode, 1),

  M_NEXT_EXIST (Ext_Channel_Request_desc_t, Exist_LCC_PDU, 1),
  M_UINT       (Ext_Channel_Request_desc_t,  LCC_PDU,  1),

 /* Don't use M_REC_TARRAY as we don't support multiple TBFs
  M_NEXT_EXIST (Ext_Channel_Request_desc_t, Exist_Ext_Channel_Request_desc, 1),
  M_TYPE       (Ext_Channel_Request_desc_t, Ext_Channel_Request_desc, Ext_Channel_Request_desc_t),*/
  M_UINT       (Ext_Channel_Request_desc_t, Exist_Ext_Channel_Request_desc, 1),

CSN_DESCR_END  (Ext_Channel_Request_desc_t)

static const
CSN_DESCR_BEGIN(EGPRS_BEP_LinkQualityMeasurements_type2_t)

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_GMSK_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  GMSK_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  GMSK_CV_BEP, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_8PSK_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p8PSK_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p8PSK_CV_BEP, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_QPSK_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  QPSK_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  QPSK_CV_BEP, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_16QAM_NSR_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p16QAM_NSR_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p16QAM_NSR_CV_BEP, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_32QAM_NSR_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p32QAM_NSR_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p32QAM_NSR_CV_BEP, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_16QAM_HSR_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p16QAM_HSR_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p16QAM_HSR_CV_BEP, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_type2_t, Exist_32QAM_HSR_MEAN_BEP, 1),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p32QAM_HSR_MEAN_BEP,  5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_type2_t,  p32QAM_HSR_CV_BEP, 3),

CSN_DESCR_END  (EGPRS_BEP_LinkQualityMeasurements_type2_t)

static const
CSN_DESCR_BEGIN(BEP_MeasurementReport_type2_t)
  M_NEXT_EXIST (BEP_MeasurementReport_type2_t, Exist, 1),
  M_UINT       (BEP_MeasurementReport_type2_t,  REPORTED_MODULATION,  2),
  M_UINT       (BEP_MeasurementReport_type2_t,  MEAN_BEP_TN,  4),
CSN_DESCR_END  (BEP_MeasurementReport_type2_t)

static const
CSN_DESCR_BEGIN(InterferenceMeasurementReport_type2_t)
  M_NEXT_EXIST (InterferenceMeasurementReport_type2_t, Exist, 1),
  M_UINT       (InterferenceMeasurementReport_type2_t,  I_LEVEL,  4),
CSN_DESCR_END  (InterferenceMeasurementReport_type2_t)
static const
CSN_DESCR_BEGIN(EGPRS_TimeslotLinkQualityMeasurements_type2_t)
  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_type2_t, Exist_BEP_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_type2_t, BEP_MEASUREMENTS, BEP_MeasurementReport_type2_t, 8),

  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_type2_t, Exist_INTERFERENCE_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_type2_t, INTERFERENCE_MEASUREMENTS, InterferenceMeasurementReport_type2_t, 8),
CSN_DESCR_END  (EGPRS_TimeslotLinkQualityMeasurements_type2_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR12_t)

  M_NEXT_EXIST (PRR_AdditionsR12_t, Exist_Downlink_eTFI, 1),
  M_UINT       (PRR_AdditionsR12_t,  DOWNLINK_ETFI,  3),

CSN_DESCR_END  (PRR_AdditionsR12_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR10_t)
  M_UINT       (PRR_AdditionsR10_t,  LOW_ACCESS_PRIORITY_SIGNALLING,  1),

  M_NEXT_EXIST_OR_NULL(PRR_AdditionsR10_t, Exist_AdditionsR12, 1),
  M_TYPE       (PRR_AdditionsR10_t, AdditionsR12, PRR_AdditionsR12_t),

CSN_DESCR_END  (PRR_AdditionsR10_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR7_t)
  M_UINT       (PRR_AdditionsR7_t,  EARLY_TBF_ESTABLISHMENT,  1),

  M_NEXT_EXIST (PRR_AdditionsR7_t, Exist_EGPRS_BEP_LinkQualityMeasurements_type2, 1),
  M_TYPE       (PRR_AdditionsR7_t, EGPRS_BEP_LinkQualityMeasurements_type2, EGPRS_BEP_LinkQualityMeasurements_type2_t),

  M_NEXT_EXIST (PRR_AdditionsR7_t, Exist_EGPRS_TimeslotLinkQualityMeasurements_type2, 1),
  M_TYPE       (PRR_AdditionsR7_t, EGPRS_TimeslotLinkQualityMeasurements_type2, EGPRS_TimeslotLinkQualityMeasurements_type2_t),

  M_NEXT_EXIST_OR_NULL(PRR_AdditionsR7_t, Exist_AdditionsR10, 1),
  M_TYPE       (PRR_AdditionsR7_t, AdditionsR10, PRR_AdditionsR10_t),

CSN_DESCR_END  (PRR_AdditionsR7_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR6_t)
  M_NEXT_EXIST (PRR_AdditionsR6_t, Exist_Ext_Channel_Request_desc, 1),
  M_TYPE       (PRR_AdditionsR6_t, Ext_Channel_Request_desc, Ext_Channel_Request_desc_t),

  M_NEXT_EXIST_OR_NULL(PRR_AdditionsR6_t, Exist_AdditionsR7, 1),
  M_TYPE       (PRR_AdditionsR6_t, AdditionsR7, PRR_AdditionsR7_t),

CSN_DESCR_END  (PRR_AdditionsR6_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR5_t)
  M_NEXT_EXIST (PRR_AdditionsR5_t, Exist_Iu_Mode_ChRequestDesk, 1),
  M_TYPE       (PRR_AdditionsR5_t, IU_Mode_Channel_Request_Desk_RNTI, IU_Mode_Channel_Request_Desk_RNTI_t),

  M_NEXT_EXIST (PRR_AdditionsR5_t, Exist_HFN_LSB, 1),
  M_UINT       (PRR_AdditionsR5_t,  HFN_LSb, 7),

  M_NEXT_EXIST_OR_NULL(PRR_AdditionsR5_t, Exist_AdditionsR6, 1),
  M_TYPE       (PRR_AdditionsR5_t, AdditionsR6, PRR_AdditionsR6_t),
CSN_DESCR_END  (PRR_AdditionsR5_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR99_t)
  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_EGPRS_BEP_LinkQualityMeasurements, 1),
  M_TYPE       (PRR_AdditionsR99_t, EGPRS_BEP_LinkQualityMeasurements, EGPRS_BEP_LinkQualityMeasurements_t),

  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_EGPRS_TimeslotLinkQualityMeasurements, 1),
  M_TYPE       (PRR_AdditionsR99_t, EGPRS_TimeslotLinkQualityMeasurements, EGPRS_TimeslotLinkQualityMeasurements_t),

  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_PFI, 1),
  M_UINT       (PRR_AdditionsR99_t,  PFI,  7),

  M_UINT       (PRR_AdditionsR99_t,  MS_RAC_AdditionalInformationAvailable,  1),
  M_UINT       (PRR_AdditionsR99_t,  RetransmissionOfPRR,  1),

  M_NEXT_EXIST_OR_NULL(PRR_AdditionsR99_t, Exist_AdditionsR5, 1),
  M_TYPE       (PRR_AdditionsR99_t, AdditionsR5, PRR_AdditionsR5_t),

CSN_DESCR_END  (PRR_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Resource_Request_t)
  /* Mac header */
  M_UINT              (Packet_Resource_Request_t,  PayloadType,  2),
  M_UINT              (Packet_Resource_Request_t,  spare,  5),
  M_UINT              (Packet_Resource_Request_t,  R,  1),
  M_UINT              (Packet_Resource_Request_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_ACCESS_TYPE, 1),
  M_UINT              (Packet_Resource_Request_t,  ACCESS_TYPE,  2),

  M_TYPE              (Packet_Resource_Request_t, ID, PacketResourceRequestID_t),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_MS_Radio_Access_capability, 1),
  M_TYPE              (Packet_Resource_Request_t, MS_Radio_Access_capability, MS_Radio_Access_capability_t),

  M_TYPE              (Packet_Resource_Request_t, Channel_Request_Description, Channel_Request_Description_t),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_CHANGE_MARK, 1),
  M_UINT              (Packet_Resource_Request_t,  CHANGE_MARK,  2),

  M_UINT              (Packet_Resource_Request_t,  C_VALUE,  6),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_SIGN_VAR, 1),
  M_UINT              (Packet_Resource_Request_t,  SIGN_VAR,  6),

  M_TYPE_ARRAY        (Packet_Resource_Request_t, I_LEVEL_TN, InterferenceMeasurementReport_t, 8),

  M_NEXT_EXIST_OR_NULL(Packet_Resource_Request_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Resource_Request_t, AdditionsR99, PRR_AdditionsR99_t),
  M_PADDING_BITS     (Packet_Resource_Request_t),
CSN_DESCR_END         (Packet_Resource_Request_t)

/*< Packet Mobile TBF Status message content > */
static const
CSN_DESCR_BEGIN(Packet_Mobile_TBF_Status_t)
  /* Mac header */
  M_UINT       (Packet_Mobile_TBF_Status_t,  PayloadType,  2),
  M_UINT       (Packet_Mobile_TBF_Status_t,  spare,  5),
  M_UINT       (Packet_Mobile_TBF_Status_t,  R,  1),
  M_UINT       (Packet_Mobile_TBF_Status_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_TYPE       (Packet_Mobile_TBF_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_Mobile_TBF_Status_t,  TBF_CAUSE,  3),

  M_NEXT_EXIST (Packet_Mobile_TBF_Status_t, Exist_STATUS_MESSAGE_TYPE, 1),
  M_UINT       (Packet_Mobile_TBF_Status_t,  STATUS_MESSAGE_TYPE,  6),
  M_PADDING_BITS(Packet_Mobile_TBF_Status_t),
CSN_DESCR_END  (Packet_Mobile_TBF_Status_t)

/*< Packet PSI Status message content > */
static const
CSN_DESCR_BEGIN(PSI_Message_t)
  M_UINT       (PSI_Message_t,  PSI_MESSAGE_TYPE,  6),
  M_UINT       (PSI_Message_t,  PSIX_CHANGE_MARK,  2),
  M_NEXT_EXIST (PSI_Message_t, Exist_PSIX_COUNT_and_Instance_Bitmap, 2),
  M_FIXED      (PSI_Message_t, 4, 0),   /* Placeholder for PSIX_COUNT (4 bits) */
  M_FIXED      (PSI_Message_t, 1, 0),   /* Placeholder for Instance bitmap (1 bit) */
CSN_DESCR_END  (PSI_Message_t)

static const
CSN_DESCR_BEGIN(PSI_Message_List_t)
  M_REC_TARRAY (PSI_Message_List_t, PSI_Message, PSI_Message_t, Count_PSI_Message),
  M_FIXED      (PSI_Message_List_t, 1, 0x00),
  M_UINT       (PSI_Message_List_t,  ADDITIONAL_MSG_TYPE,  1),
CSN_DESCR_END  (PSI_Message_List_t)

static const
CSN_DESCR_BEGIN(Unknown_PSI_Message_List_t)
  M_FIXED      (Unknown_PSI_Message_List_t, 1, 0x00),
  M_UINT       (Unknown_PSI_Message_List_t,  ADDITIONAL_MSG_TYPE,  1),
CSN_DESCR_END  (Unknown_PSI_Message_List_t)

static const
CSN_DESCR_BEGIN(Packet_PSI_Status_t)
  /* Mac header */
  M_UINT       (Packet_PSI_Status_t,  PayloadType,  2),
  M_UINT       (Packet_PSI_Status_t,  spare,  5),
  M_UINT       (Packet_PSI_Status_t,  R,  1),
  M_UINT       (Packet_PSI_Status_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_TYPE       (Packet_PSI_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_PSI_Status_t,  PBCCH_CHANGE_MARK,  3),
  M_TYPE       (Packet_PSI_Status_t, PSI_Message_List, PSI_Message_List_t),
  M_TYPE       (Packet_PSI_Status_t, Unknown_PSI_Message_List, Unknown_PSI_Message_List_t),
  M_PADDING_BITS(Packet_PSI_Status_t),
CSN_DESCR_END  (Packet_PSI_Status_t)

/* < Packet SI Status message content > */

static const
CSN_DESCR_BEGIN(SI_Message_t)
  M_UINT       (SI_Message_t,  SI_MESSAGE_TYPE,  8),
  M_UINT       (SI_Message_t,  MESS_REC,  2),
CSN_DESCR_END  (SI_Message_t)

static const
CSN_DESCR_BEGIN(SI_Message_List_t)
  M_REC_TARRAY (SI_Message_List_t, SI_Message, SI_Message_t, Count_SI_Message),
  M_FIXED      (SI_Message_List_t, 1, 0x00),
  M_UINT       (SI_Message_List_t,  ADDITIONAL_MSG_TYPE,  1),
CSN_DESCR_END  (SI_Message_List_t)

static const
CSN_DESCR_BEGIN(Unknown_SI_Message_List_t)
  M_FIXED      (Unknown_SI_Message_List_t, 1, 0x00),
  M_UINT       (Unknown_SI_Message_List_t,  ADDITIONAL_MSG_TYPE,  1),
CSN_DESCR_END  (Unknown_SI_Message_List_t)

static const
CSN_DESCR_BEGIN(Packet_SI_Status_t)
  /* Mac header */
  M_UINT       (Packet_SI_Status_t,  PayloadType,  2),
  M_UINT       (Packet_SI_Status_t,  spare,  5),
  M_UINT       (Packet_SI_Status_t,  R,  1),
  M_UINT       (Packet_SI_Status_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_TYPE       (Packet_SI_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_SI_Status_t,  BCCH_CHANGE_MARK,  3),
  M_TYPE       (Packet_SI_Status_t, SI_Message_List, SI_Message_List_t),
  M_TYPE       (Packet_SI_Status_t, Unknown_SI_Message_List, Unknown_SI_Message_List_t),
  M_PADDING_BITS(Packet_SI_Status_t),
CSN_DESCR_END  (Packet_SI_Status_t)

/* < Packet Downlink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(PD_AckNack_AdditionsR99_t)
  M_NEXT_EXIST (PD_AckNack_AdditionsR99_t, Exist_PFI, 1),
  M_UINT       (PD_AckNack_AdditionsR99_t,  PFI,  7),
CSN_DESCR_END  (PD_AckNack_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Downlink_Ack_Nack_t)
  M_UINT              (Packet_Downlink_Ack_Nack_t,  PayloadType,  2),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  spare,  5),
  M_BIT               (Packet_Downlink_Ack_Nack_t,  R),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  MESSAGE_TYPE,  6),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  DOWNLINK_TFI,  5),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, Ack_Nack_Description, Ack_Nack_Description_t),

  M_NEXT_EXIST        (Packet_Downlink_Ack_Nack_t, Exist_Channel_Request_Description, 1),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, Channel_Request_Description, Channel_Request_Description_t),

  M_TYPE              (Packet_Downlink_Ack_Nack_t, Channel_Quality_Report, Channel_Quality_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Downlink_Ack_Nack_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, AdditionsR99, PD_AckNack_AdditionsR99_t),
  M_PADDING_BITS      (Packet_Downlink_Ack_Nack_t),
CSN_DESCR_END         (Packet_Downlink_Ack_Nack_t)


/*< EGPRS Packet Downlink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(EGPRS_ChannelQualityReport_t)
  M_TYPE       (EGPRS_ChannelQualityReport_t, EGPRS_BEP_LinkQualityMeasurements, EGPRS_BEP_LinkQualityMeasurements_t),
  M_UINT       (EGPRS_ChannelQualityReport_t,  C_VALUE,  6),
  M_TYPE       (EGPRS_ChannelQualityReport_t, EGPRS_TimeslotLinkQualityMeasurements, EGPRS_TimeslotLinkQualityMeasurements_t),
CSN_DESCR_END  (EGPRS_ChannelQualityReport_t)

static const
CSN_DESCR_BEGIN(EGPRS_PD_AckNack_t)
/*  M_CALLBACK   (EGPRS_PD_AckNack_t, (void*)21, IsSupported, IsSupported), */
  M_UINT       (EGPRS_PD_AckNack_t,  PayloadType,  2),
  M_UINT       (EGPRS_PD_AckNack_t,  spare,  5),
  M_BIT        (EGPRS_PD_AckNack_t,  R),

  M_UINT       (EGPRS_PD_AckNack_t,  MESSAGE_TYPE,  6),
  M_UINT       (EGPRS_PD_AckNack_t,  DOWNLINK_TFI,  5),
  M_UINT       (EGPRS_PD_AckNack_t,  MS_OUT_OF_MEMORY,  1),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_EGPRS_ChannelQualityReport, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, EGPRS_ChannelQualityReport, EGPRS_ChannelQualityReport_t),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_ChannelRequestDescription, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, ChannelRequestDescription, Channel_Request_Description_t),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_PFI, 1),
  M_UINT       (EGPRS_PD_AckNack_t,  PFI,  7),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_ExtensionBits, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, ExtensionBits, Extension_Bits_t),

  M_TYPE       (EGPRS_PD_AckNack_t, EGPRS_AckNack, EGPRS_AckNack_t),
/*  M_CALLBACK   (EGPRS_PD_AckNack_t, (void*)24, EGPRS_AckNack, EGPRS_AckNack),  */
  M_PADDING_BITS(EGPRS_PD_AckNack_t),

CSN_DESCR_END  (EGPRS_PD_AckNack_t)

static const
CSN_DESCR_BEGIN(FDD_Target_Cell_t)
  M_UINT       (FDD_Target_Cell_t,  FDD_ARFCN,  14),
  M_UINT       (FDD_Target_Cell_t,  DIVERSITY,  1),
  M_NEXT_EXIST (FDD_Target_Cell_t, Exist_Bandwith_FDD, 1),
  M_UINT       (FDD_Target_Cell_t,  BANDWITH_FDD,  3),
  M_UINT       (FDD_Target_Cell_t,  SCRAMBLING_CODE,  9),
CSN_DESCR_END  (FDD_Target_Cell_t)

static const
CSN_DESCR_BEGIN(TDD_Target_Cell_t)
  M_UINT       (TDD_Target_Cell_t,  TDD_ARFCN,  14),
  M_UINT       (TDD_Target_Cell_t,  DIVERSITY_TDD,  1),
  M_NEXT_EXIST (TDD_Target_Cell_t, Exist_Bandwith_TDD, 1),
  M_UINT       (TDD_Target_Cell_t,  BANDWITH_TDD,  3),
  M_UINT       (TDD_Target_Cell_t,  CELL_PARAMETER,  7),
  M_UINT       (TDD_Target_Cell_t,  Sync_Case_TSTD,  1),
CSN_DESCR_END  (TDD_Target_Cell_t)

static const
CSN_DESCR_BEGIN(EUTRAN_Target_Cell_t)
  M_UINT       (EUTRAN_Target_Cell_t,  EARFCN,  16),
  M_NEXT_EXIST (EUTRAN_Target_Cell_t, Exist_Measurement_Bandwidth, 1),
  M_UINT       (EUTRAN_Target_Cell_t,  Measurement_Bandwidth,  3),
  M_UINT       (EUTRAN_Target_Cell_t,  Physical_Layer_Cell_Identity,  9),
CSN_DESCR_END  (EUTRAN_Target_Cell_t)

static const
CSN_DESCR_BEGIN(UTRAN_CSG_Target_Cell_t)
  M_UINT       (UTRAN_CSG_Target_Cell_t, UTRAN_CI,  28),
  M_NEXT_EXIST (UTRAN_CSG_Target_Cell_t, Exist_PLMN_ID, 1),
  M_TYPE       (UTRAN_CSG_Target_Cell_t, PLMN_ID, PLMN_t),
CSN_DESCR_END  (UTRAN_CSG_Target_Cell_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Target_Cell_t)
  M_UINT       (EUTRAN_CSG_Target_Cell_t, EUTRAN_CI,  28),
  M_UINT       (EUTRAN_CSG_Target_Cell_t, Tracking_Area_Code,  16),
  M_NEXT_EXIST (EUTRAN_CSG_Target_Cell_t, Exist_PLMN_ID, 1),
  M_TYPE       (EUTRAN_CSG_Target_Cell_t, PLMN_ID, PLMN_t),
CSN_DESCR_END  (EUTRAN_CSG_Target_Cell_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR9_t)
  M_NEXT_EXIST (PCCF_AdditionsR9_t, Exist_UTRAN_CSG_Target_Cell, 1),
  M_TYPE       (PCCF_AdditionsR9_t, UTRAN_CSG_Target_Cell, UTRAN_CSG_Target_Cell_t),
  M_NEXT_EXIST (PCCF_AdditionsR9_t, Exist_EUTRAN_CSG_Target_Cell, 1),
  M_TYPE       (PCCF_AdditionsR9_t, EUTRAN_CSG_Target_Cell, EUTRAN_CSG_Target_Cell_t),
CSN_DESCR_END  (PCCF_AdditionsR9_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR8_t)
  M_NEXT_EXIST (PCCF_AdditionsR8_t, Exist_EUTRAN_Target_Cell, 1),
  M_TYPE       (PCCF_AdditionsR8_t, EUTRAN_Target_Cell, EUTRAN_Target_Cell_t),
  M_NEXT_EXIST_OR_NULL(PCCF_AdditionsR8_t, Exist_AdditionsR9, 1),
  M_TYPE       (PCCF_AdditionsR8_t, AdditionsR9, PCCF_AdditionsR9_t),
CSN_DESCR_END  (PCCF_AdditionsR8_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR5_t)
  M_NEXT_EXIST (PCCF_AdditionsR5_t, Exist_G_RNTI_extension, 1),
  M_UINT       (PCCF_AdditionsR5_t,  G_RNTI_extension,  4),
  M_NEXT_EXIST_OR_NULL(PCCF_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE       (PCCF_AdditionsR5_t, AdditionsR8, PCCF_AdditionsR8_t),
CSN_DESCR_END  (PCCF_AdditionsR5_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR99_t)
  M_NEXT_EXIST (PCCF_AdditionsR99_t, Exist_FDD_Description, 1),
  M_TYPE       (PCCF_AdditionsR99_t, FDD_Target_Cell, FDD_Target_Cell_t),
  M_NEXT_EXIST (PCCF_AdditionsR99_t, Exist_TDD_Description, 1),
  M_TYPE       (PCCF_AdditionsR99_t, TDD_Target_Cell, TDD_Target_Cell_t),
  M_NEXT_EXIST_OR_NULL(PCCF_AdditionsR99_t, Exist_AdditionsR5, 1),
  M_TYPE       (PCCF_AdditionsR99_t, AdditionsR5, PCCF_AdditionsR5_t),
CSN_DESCR_END  (PCCF_AdditionsR99_t)

/*< Packet Cell Change Failure message content > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Failure_t)
  /* Mac header */
  M_UINT               (Packet_Cell_Change_Failure_t,  PayloadType,  2),
  M_UINT               (Packet_Cell_Change_Failure_t,  spare,  5),
  M_UINT               (Packet_Cell_Change_Failure_t,  R,  1),
  M_UINT               (Packet_Cell_Change_Failure_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_UINT               (Packet_Cell_Change_Failure_t,  TLLI,  32),
  M_UINT               (Packet_Cell_Change_Failure_t,  ARFCN,  10),
  M_UINT               (Packet_Cell_Change_Failure_t,  BSIC,  6),
  M_UINT               (Packet_Cell_Change_Failure_t,  CAUSE,  4),

  M_NEXT_EXIST_OR_NULL (Packet_Cell_Change_Failure_t, Exist_AdditionsR99, 1),
  M_TYPE               (Packet_Cell_Change_Failure_t, AdditionsR99, PCCF_AdditionsR99_t),

  M_PADDING_BITS       (Packet_Cell_Change_Failure_t),
CSN_DESCR_END          (Packet_Cell_Change_Failure_t)

/*< Packet Uplink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(Power_Control_Parameters_t)
  M_UINT       (Power_Control_Parameters_t,  ALPHA,  4),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[0].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[0].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[1].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[1].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[2].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[2].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[3].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[3].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[4].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[4].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[5].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[5].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[6].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[6].GAMMA_TN,  5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[7].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[7].GAMMA_TN,  5),
CSN_DESCR_END  (Power_Control_Parameters_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PU_AckNack_GPRS_AdditionsR99_t, Exist_PacketExtendedTimingAdvance, 1),
  M_UINT       (PU_AckNack_GPRS_AdditionsR99_t,  PacketExtendedTimingAdvance,  2),

  M_UINT       (PU_AckNack_GPRS_AdditionsR99_t,  TBF_EST,  1),
CSN_DESCR_END  (PU_AckNack_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PU_AckNack_GPRS_t)
  M_UINT              (PU_AckNack_GPRS_t,  CHANNEL_CODING_COMMAND,  2),
  M_TYPE              (PU_AckNack_GPRS_t, Ack_Nack_Description, Ack_Nack_Description_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI, 1),
  M_UINT              (PU_AckNack_GPRS_t,  Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI,  32),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Extension_Bits, Extension_Bits_t),

  M_UNION             (PU_AckNack_GPRS_t, 2), /* Fixed Allocation was removed */
  M_UINT              (PU_AckNack_GPRS_t,  u.FixedAllocationDummy,  1),
  CSN_ERROR           (PU_AckNack_GPRS_t, "01 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PU_AckNack_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PU_AckNack_GPRS_t, AdditionsR99, PU_AckNack_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PU_AckNack_GPRS_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_EGPRS_00_t)
  M_UINT       (PU_AckNack_EGPRS_00_t,  EGPRS_ChannelCodingCommand,  4),
  M_UINT       (PU_AckNack_EGPRS_00_t,  RESEGMENT,  1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  PRE_EMPTIVE_TRANSMISSION,  1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  PRR_RETRANSMISSION_REQUEST,  1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  ARAC_RETRANSMISSION_REQUEST,  1),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI,  32),

  M_UINT       (PU_AckNack_EGPRS_00_t,  TBF_EST,  1),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  Packet_Extended_Timing_Advance,  2),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Extension_Bits, Extension_Bits_t),

  M_TYPE       (PU_AckNack_EGPRS_00_t, EGPRS_AckNack, EGPRS_AckNack_t),
/*  M_CALLBACK   (PU_AckNack_EGPRS_00_t, (void*)24, EGPRS_AckNack, EGPRS_AckNack),  */
CSN_DESCR_END  (PU_AckNack_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_EGPRS_t)
/*  M_CALLBACK   (PU_AckNack_EGPRS_t, (void*)21, IsSupported, IsSupported), */
  M_UNION      (PU_AckNack_EGPRS_t, 4),
  M_TYPE       (PU_AckNack_EGPRS_t, u.PU_AckNack_EGPRS_00, PU_AckNack_EGPRS_00_t),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "01 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "10 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "11 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PU_AckNack_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Uplink_Ack_Nack_t)
  M_UINT       (Packet_Uplink_Ack_Nack_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Uplink_Ack_Nack_t,  PAGE_MODE,  2),
  M_FIXED      (Packet_Uplink_Ack_Nack_t, 2, 0x00),
  M_UINT       (Packet_Uplink_Ack_Nack_t,  UPLINK_TFI,  5),

  M_UNION      (Packet_Uplink_Ack_Nack_t, 2),
  M_TYPE       (Packet_Uplink_Ack_Nack_t, u.PU_AckNack_GPRS_Struct, PU_AckNack_GPRS_t),
  M_TYPE       (Packet_Uplink_Ack_Nack_t, u.PU_AckNack_EGPRS_Struct, PU_AckNack_EGPRS_t),
  M_PADDING_BITS(Packet_Uplink_Ack_Nack_t ),
CSN_DESCR_END  (Packet_Uplink_Ack_Nack_t)

/*< Packet Uplink Assignment message content > */
static const
CSN_DESCR_BEGIN(CHANGE_MARK_t)
  M_UINT       (CHANGE_MARK_t,  CHANGE_MARK_1,  2),

  M_NEXT_EXIST (CHANGE_MARK_t, Exist_CHANGE_MARK_2, 1),
  M_UINT       (CHANGE_MARK_t,  CHANGE_MARK_2,  2),
CSN_DESCR_END  (CHANGE_MARK_t)

static const
CSN_DESCR_BEGIN(Indirect_encoding_t)
  M_UINT       (Indirect_encoding_t,  MAIO,  6),
  M_UINT       (Indirect_encoding_t,  MA_NUMBER,  4),

  M_NEXT_EXIST (Indirect_encoding_t, Exist_CHANGE_MARK, 1),
  M_TYPE       (Indirect_encoding_t, CHANGE_MARK, CHANGE_MARK_t),
CSN_DESCR_END  (Indirect_encoding_t)

static const
CSN_DESCR_BEGIN(Direct_encoding_1_t)
  M_UINT       (Direct_encoding_1_t,  MAIO,  6),
  M_TYPE       (Direct_encoding_1_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),
CSN_DESCR_END  (Direct_encoding_1_t)

static const
CSN_DESCR_BEGIN(Direct_encoding_2_t)
  M_UINT       (Direct_encoding_2_t,  MAIO,  6),
  M_UINT       (Direct_encoding_2_t,  HSN,  6),
  M_UINT_OFFSET(Direct_encoding_2_t, Length_of_MA_Frequency_List, 4, 3),
  M_VAR_ARRAY  (Direct_encoding_2_t, MA_Frequency_List, Length_of_MA_Frequency_List, 0),
CSN_DESCR_END  (Direct_encoding_2_t)

static const
CSN_DESCR_BEGIN(Frequency_Parameters_t)
  M_UINT       (Frequency_Parameters_t,  TSC,  3),

  M_UNION      (Frequency_Parameters_t, 4),
  M_UINT       (Frequency_Parameters_t,  u.ARFCN,  10),
  M_TYPE       (Frequency_Parameters_t, u.Indirect_encoding, Indirect_encoding_t),
  M_TYPE       (Frequency_Parameters_t, u.Direct_encoding_1, Direct_encoding_1_t),
  M_TYPE       (Frequency_Parameters_t, u.Direct_encoding_2, Direct_encoding_2_t),
CSN_DESCR_END  (Frequency_Parameters_t)

static const
CSN_DESCR_BEGIN(Packet_Request_Reference_t)
  M_UINT       (Packet_Request_Reference_t,  RANDOM_ACCESS_INFORMATION,  11),
  M_UINT_ARRAY (Packet_Request_Reference_t, FRAME_NUMBER, 8, 2),
CSN_DESCR_END  (Packet_Request_Reference_t)

static const
CSN_DESCR_BEGIN(Timeslot_Allocation_t)
  M_NEXT_EXIST (Timeslot_Allocation_t, Exist, 1),
  M_UINT       (Timeslot_Allocation_t,  USF_TN,  3),
CSN_DESCR_END  (Timeslot_Allocation_t)

static const
CSN_DESCR_BEGIN(Timeslot_Allocation_Power_Ctrl_Param_t)
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  ALPHA,  4),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[0].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[0].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[0].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[1].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[1].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[1].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[2].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[2].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[2].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[3].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[3].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[3].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[4].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[4].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[4].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[5].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[5].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[5].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[6].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[6].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[6].GAMMA_TN,  5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[7].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[7].USF_TN,  3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[7].GAMMA_TN,  5),
CSN_DESCR_END  (Timeslot_Allocation_Power_Ctrl_Param_t)

/* USED in <Packet Uplink Assignment message content> */
static const
CSN_DESCR_BEGIN(Dynamic_Allocation_t)
  M_UINT       (Dynamic_Allocation_t,  Extended_Dynamic_Allocation,  1),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (Dynamic_Allocation_t,  P0,  4),
  M_UINT       (Dynamic_Allocation_t,  PR_MODE,  1),

  M_UINT       (Dynamic_Allocation_t,  USF_GRANULARITY,  1),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (Dynamic_Allocation_t,  UPLINK_TFI_ASSIGNMENT,  5),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED, 1),
  M_UINT       (Dynamic_Allocation_t,  RLC_DATA_BLOCKS_GRANTED,  8),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_TBF_Starting_Time, 1),
  M_TYPE       (Dynamic_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_UNION      (Dynamic_Allocation_t, 2),
  M_TYPE_ARRAY (Dynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (Dynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (Dynamic_Allocation_t)

static const
CSN_DESCR_BEGIN(Single_Block_Allocation_t)
  M_UINT       (Single_Block_Allocation_t,  TIMESLOT_NUMBER,  3),

  M_NEXT_EXIST (Single_Block_Allocation_t, Exist_ALPHA_and_GAMMA_TN, 2),
  M_UINT       (Single_Block_Allocation_t,  ALPHA,  4),
  M_UINT       (Single_Block_Allocation_t,  GAMMA_TN,  5),

  M_NEXT_EXIST (Single_Block_Allocation_t, Exist_P0, 3),
  M_UINT       (Single_Block_Allocation_t,  P0,  4),
  M_UINT       (Single_Block_Allocation_t,  BTS_PWR_CTRL_MODE,  1),
  M_UINT       (Single_Block_Allocation_t,  PR_MODE,  1),

  M_TYPE       (Single_Block_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),
CSN_DESCR_END  (Single_Block_Allocation_t)

static const
CSN_DESCR_BEGIN(DTM_Dynamic_Allocation_t)
  M_UINT       (DTM_Dynamic_Allocation_t,  Extended_Dynamic_Allocation,  1),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (DTM_Dynamic_Allocation_t,  P0,  4),
  M_UINT       (DTM_Dynamic_Allocation_t,  PR_MODE,  1),

  M_UINT       (DTM_Dynamic_Allocation_t,  USF_GRANULARITY,  1),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (DTM_Dynamic_Allocation_t,  UPLINK_TFI_ASSIGNMENT,  5),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED, 1),
  M_UINT       (DTM_Dynamic_Allocation_t,  RLC_DATA_BLOCKS_GRANTED,  8),

  M_UNION      (DTM_Dynamic_Allocation_t, 2),
  M_TYPE_ARRAY (DTM_Dynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (DTM_Dynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (DTM_Dynamic_Allocation_t)

static const
CSN_DESCR_BEGIN(DTM_Single_Block_Allocation_t)
  M_UINT       (DTM_Single_Block_Allocation_t,  TIMESLOT_NUMBER,  3),

  M_NEXT_EXIST (DTM_Single_Block_Allocation_t, Exist_ALPHA_and_GAMMA_TN, 2),
  M_UINT       (DTM_Single_Block_Allocation_t,  ALPHA,  4),
  M_UINT       (DTM_Single_Block_Allocation_t,  GAMMA_TN,  5),

  M_NEXT_EXIST (DTM_Single_Block_Allocation_t, Exist_P0, 3),
  M_UINT       (DTM_Single_Block_Allocation_t,  P0,  4),
  M_UINT       (DTM_Single_Block_Allocation_t,  BTS_PWR_CTRL_MODE,  1),
  M_UINT       (DTM_Single_Block_Allocation_t,  PR_MODE,  1),
CSN_DESCR_END  (DTM_Single_Block_Allocation_t)


/* Help structures */
typedef struct
{
  Global_TFI_t Global_TFI;  /* 0  < Global TFI : < Global TFI IE > > */
} h0_Global_TFI_t;

static const
CSN_DESCR_BEGIN(h0_Global_TFI_t)
  M_FIXED      (h0_Global_TFI_t, 1, 0x00),
  M_TYPE       (h0_Global_TFI_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (h0_Global_TFI_t)

typedef struct
{
  guint32 TLLI;/* | 10  < TLLI : bit (32) >*/
} h10_TLLI_t;

static const
CSN_DESCR_BEGIN(h10_TLLI_t)
  M_FIXED      (h10_TLLI_t, 2, 0x02),
  M_UINT       (h10_TLLI_t,  TLLI,  32),
CSN_DESCR_END (h10_TLLI_t)

typedef struct
{
  guint16 TQI;/*| 110  < TQI : bit (16) > */
} h110_TQI_t;

static const
CSN_DESCR_BEGIN(h110_TQI_t)
  M_FIXED      (h110_TQI_t, 3, 0x06),
  M_UINT       (h110_TQI_t,  TQI,  16),
CSN_DESCR_END  (h110_TQI_t)

typedef struct
{
  Packet_Request_Reference_t Packet_Request_Reference;/*| 111  < Packet Request Reference : < Packet Request Reference IE > > }*/
} h111_Packet_Request_Reference_t;

static const
CSN_DESCR_BEGIN(h111_Packet_Request_Reference_t)
  M_FIXED      (h111_Packet_Request_Reference_t, 3, 0x07),
  M_TYPE       (h111_Packet_Request_Reference_t, Packet_Request_Reference, Packet_Request_Reference_t),
CSN_DESCR_END  (h111_Packet_Request_Reference_t)

static const
CSN_ChoiceElement_t PacketUplinkID[] =
{
  {1, 0,    0, M_TYPE(PacketUplinkID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketUplinkID_t, u.TLLI, 32)},
  {3, 0x06, 0, M_UINT(PacketUplinkID_t, u.TQI, 16)},
  {3, 0x07, 0, M_TYPE(PacketUplinkID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
};

static const
CSN_DESCR_BEGIN(PacketUplinkID_t)
  M_CHOICE     (PacketUplinkID_t, UnionType, PacketUplinkID, ElementsOf(PacketUplinkID)),
CSN_DESCR_END  (PacketUplinkID_t)

static const
CSN_DESCR_BEGIN(PUA_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PUA_GPRS_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PUA_GPRS_AdditionsR99_t,  Packet_Extended_Timing_Advance,  2),
CSN_DESCR_END  (PUA_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PUA_GPRS_t)
  M_UINT              (PUA_GPRS_t,  CHANNEL_CODING_COMMAND,  2),
  M_UINT              (PUA_GPRS_t,  TLLI_BLOCK_CHANNEL_CODING, 1),
  M_TYPE              (PUA_GPRS_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (PUA_GPRS_t, Exist_Frequency_Parameters, 1),
  M_TYPE              (PUA_GPRS_t, Frequency_Parameters, Frequency_Parameters_t),

  M_UNION             (PUA_GPRS_t, 4),
  CSN_ERROR           (PUA_GPRS_t, "00 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE              (PUA_GPRS_t, u.Dynamic_Allocation, Dynamic_Allocation_t),
  M_TYPE              (PUA_GPRS_t, u.Single_Block_Allocation, Single_Block_Allocation_t),
  CSN_ERROR           (PUA_GPRS_t, "11 <Fixed Allocation> not supported", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PUA_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PUA_GPRS_t, AdditionsR99, PUA_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PUA_GPRS_t)

static const
CSN_DESCR_BEGIN(COMPACT_ReducedMA_t)
  M_UINT       (COMPACT_ReducedMA_t,  BitmapLength,  7),
  M_VAR_BITMAP (COMPACT_ReducedMA_t, ReducedMA_Bitmap, BitmapLength, 0),

  M_NEXT_EXIST (COMPACT_ReducedMA_t, Exist_MAIO_2, 1),
  M_UINT       (COMPACT_ReducedMA_t,  MAIO_2,  6),
CSN_DESCR_END  (COMPACT_TeducedMA_t)

static const
CSN_DESCR_BEGIN(MultiBlock_Allocation_t)
  M_UINT       (MultiBlock_Allocation_t,  TIMESLOT_NUMBER,  3),

  M_NEXT_EXIST (MultiBlock_Allocation_t, Exist_ALPHA_GAMMA_TN, 2),
  M_UINT       (MultiBlock_Allocation_t,  ALPHA,  4),
  M_UINT       (MultiBlock_Allocation_t,  GAMMA_TN,  5),

  M_NEXT_EXIST (MultiBlock_Allocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (MultiBlock_Allocation_t,  P0,  4),
  M_UINT       (MultiBlock_Allocation_t,  BTS_PWR_CTRL_MODE,  1),
  M_UINT       (MultiBlock_Allocation_t,  PR_MODE,  1),

  M_TYPE       (MultiBlock_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),
  M_UINT       (MultiBlock_Allocation_t,  NUMBER_OF_RADIO_BLOCKS_ALLOCATED,  2),
CSN_DESCR_END  (MultiBlock_Allocation_t)

static const
CSN_DESCR_BEGIN (PUA_EGPRS_00_t)
  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_CONTENTION_RESOLUTION_TLLI, 1),
  M_UINT        (PUA_EGPRS_00_t,  CONTENTION_RESOLUTION_TLLI,  32),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE        (PUA_EGPRS_00_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),

  M_UINT        (PUA_EGPRS_00_t,  EGPRS_CHANNEL_CODING_COMMAND,  4),
  M_UINT        (PUA_EGPRS_00_t,  RESEGMENT,  1),
  M_UINT        (PUA_EGPRS_00_t,  EGPRS_WindowSize,  5),

  M_REC_ARRAY   (PUA_EGPRS_00_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UINT        (PUA_EGPRS_00_t,  ARAC_RETRANSMISSION_REQUEST,  1),
  M_UINT        (PUA_EGPRS_00_t,  TLLI_BLOCK_CHANNEL_CODING,  1),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_BEP_PERIOD2, 1),
  M_UINT        (PUA_EGPRS_00_t,  BEP_PERIOD2,  4),

  M_TYPE        (PUA_EGPRS_00_t, PacketTimingAdvance, Packet_Timing_Advance_t),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT        (PUA_EGPRS_00_t,  Packet_Extended_Timing_Advance,  2),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_Frequency_Parameters, 1),
  M_TYPE        (PUA_EGPRS_00_t, Frequency_Parameters, Frequency_Parameters_t),

  M_UNION       (PUA_EGPRS_00_t, 4),
  CSN_ERROR     (PUA_EGPRS_00_t, "00 <extension>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE        (PUA_EGPRS_00_t, u.Dynamic_Allocation, Dynamic_Allocation_t),
  M_TYPE        (PUA_EGPRS_00_t, u.MultiBlock_Allocation, MultiBlock_Allocation_t),
  CSN_ERROR     (PUA_EGPRS_00_t, "11 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END   (PUA_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PUA_EGPRS_t)
  M_UNION      (PUA_EGPRS_t, 4),
  M_TYPE       (PUA_EGPRS_t, u.PUA_EGPRS_00, PUA_EGPRS_00_t),
  CSN_ERROR    (PUA_EGPRS_t, "01 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PUA_EGPRS_t, "10 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PUA_EGPRS_t, "11 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PUA_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Uplink_Assignment_t)
  M_UINT       (Packet_Uplink_Assignment_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Uplink_Assignment_t,  PAGE_MODE,  2),

  M_NEXT_EXIST (Packet_Uplink_Assignment_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (Packet_Uplink_Assignment_t, PERSISTENCE_LEVEL, 4, 4),

  M_TYPE       (Packet_Uplink_Assignment_t, ID, PacketUplinkID_t),

  M_UNION      (Packet_Uplink_Assignment_t, 2),
  M_TYPE       (Packet_Uplink_Assignment_t, u.PUA_GPRS_Struct, PUA_GPRS_t),
  M_TYPE       (Packet_Uplink_Assignment_t, u.PUA_EGPRS_Struct, PUA_EGPRS_t),

  M_PADDING_BITS(Packet_Uplink_Assignment_t ),
CSN_DESCR_END  (Packet_Uplink_Assignment_t)

/*< Packet Downlink Assignment message content > */
static const
CSN_DESCR_BEGIN(Measurement_Mapping_struct_t)
  M_TYPE       (Measurement_Mapping_struct_t, Measurement_Starting_Time, Starting_Frame_Number_t),
  M_UINT       (Measurement_Mapping_struct_t,  MEASUREMENT_INTERVAL,  5),
  M_UINT       (Measurement_Mapping_struct_t,  MEASUREMENT_BITMAP,  8),
CSN_DESCR_END  (Measurement_Mapping_struct_t)

static const
CSN_ChoiceElement_t PacketDownlinkID[] =
{
  {1,    0, 0, M_TYPE(PacketDownlinkID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketDownlinkID_t, u.TLLI, 32)},
};

static const
CSN_DESCR_BEGIN(PacketDownlinkID_t)
  M_CHOICE     (PacketDownlinkID_t, UnionType, PacketDownlinkID, ElementsOf(PacketDownlinkID)),
CSN_DESCR_END  (PacketDownlinkID_t)

static const
CSN_DESCR_BEGIN(PDA_AdditionsR99_t)
  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_EGPRS_Params, 4), /*if Exist_EGPRS_Params == FALSE then none of the following 4 vars exist */
  M_UINT       (PDA_AdditionsR99_t,  EGPRS_WindowSize,  5),
  M_UINT       (PDA_AdditionsR99_t,  LINK_QUALITY_MEASUREMENT_MODE,  2),
  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (PDA_AdditionsR99_t,  BEP_PERIOD2,  4),

  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PDA_AdditionsR99_t,  Packet_Extended_Timing_Advance,  2),

  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE       (PDA_AdditionsR99_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),
CSN_DESCR_END  (PDA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Downlink_Assignment_t)
  M_UINT              (Packet_Downlink_Assignment_t,  MESSAGE_TYPE,  6),
  M_UINT              (Packet_Downlink_Assignment_t,  PAGE_MODE,  2),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY        (Packet_Downlink_Assignment_t, PERSISTENCE_LEVEL, 4, 4),

  M_TYPE              (Packet_Downlink_Assignment_t, ID, PacketDownlinkID_t),

  M_FIXED             (Packet_Downlink_Assignment_t, 1, 0x00),/*-- Message escape */

  M_UINT              (Packet_Downlink_Assignment_t,  MAC_MODE,  2),
  M_UINT              (Packet_Downlink_Assignment_t,  RLC_MODE, 1),
  M_UINT              (Packet_Downlink_Assignment_t,  CONTROL_ACK, 1),
  M_UINT              (Packet_Downlink_Assignment_t,  TIMESLOT_ALLOCATION,  8),
  M_TYPE              (Packet_Downlink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_P0_and_BTS_PWR_CTRL_MODE, 3),
  M_UINT              (Packet_Downlink_Assignment_t,  P0,  4),
  M_UINT              (Packet_Downlink_Assignment_t,  BTS_PWR_CTRL_MODE, 1),
  M_UINT              (Packet_Downlink_Assignment_t,  PR_MODE,  1),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Frequency_Parameters, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Frequency_Parameters, Frequency_Parameters_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT              (Packet_Downlink_Assignment_t,  DOWNLINK_TFI_ASSIGNMENT,  5),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Power_Control_Parameters, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_TBF_Starting_Time, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Measurement_Mapping, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Measurement_Mapping, Measurement_Mapping_struct_t),

  M_NEXT_EXIST_OR_NULL(Packet_Downlink_Assignment_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, AdditionsR99, PDA_AdditionsR99_t),

  M_PADDING_BITS    (Packet_Downlink_Assignment_t),
CSN_DESCR_END         (Packet_Downlink_Assignment_t)

typedef Packet_Downlink_Assignment_t pdlaCheck_t;

static const
CSN_DESCR_BEGIN(pdlaCheck_t)
  M_UINT       (pdlaCheck_t,  MESSAGE_TYPE,  6),
  M_UINT       (pdlaCheck_t,  PAGE_MODE,  2),

  M_NEXT_EXIST (pdlaCheck_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (pdlaCheck_t, PERSISTENCE_LEVEL, 4, 4),

  M_TYPE       (pdlaCheck_t, ID, PacketDownlinkID_t),
CSN_DESCR_END  (pdlaCheck_t)

/* DTM Packet UL Assignment */
static const
CSN_DESCR_BEGIN(DTM_Packet_Uplink_Assignment_t)
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  CHANNEL_CODING_COMMAND,  2),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  TLLI_BLOCK_CHANNEL_CODING, 1),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_UNION      (DTM_Packet_Uplink_Assignment_t, 3),
  CSN_ERROR    (DTM_Packet_Uplink_Assignment_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, u.DTM_Dynamic_Allocation, DTM_Dynamic_Allocation_t),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, u.DTM_Single_Block_Allocation, DTM_Single_Block_Allocation_t),
  M_NEXT_EXIST_OR_NULL  (DTM_Packet_Uplink_Assignment_t, Exist_EGPRS_Parameters, 3),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  EGPRS_CHANNEL_CODING_COMMAND,  4),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  RESEGMENT,  1),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  EGPRS_WindowSize,  5),
  M_NEXT_EXIST (DTM_Packet_Uplink_Assignment_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  Packet_Extended_Timing_Advance,  2),
CSN_DESCR_END(DTM_Packet_Uplink_Assignment_t)

static const
CSN_DESCR_BEGIN(DTM_UL_t)
  M_TYPE       (DTM_UL_t, DTM_Packet_Uplink_Assignment, DTM_Packet_Uplink_Assignment_t),
CSN_DESCR_END(DTM_UL_t)

/* DTM Packet DL Assignment */
static const
CSN_DESCR_BEGIN(DTM_Packet_Downlink_Assignment_t)
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  MAC_MODE,  2),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  RLC_MODE ,1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  TIMESLOT_ALLOCATION,  8),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_P0_and_BTS_PWR_CTRL_MODE, 3),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  P0,  4),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  BTS_PWR_CTRL_MODE, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  PR_MODE,  1),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Power_Control_Parameters, 1),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  DOWNLINK_TFI_ASSIGNMENT,  5),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Measurement_Mapping, 1),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Measurement_Mapping, Measurement_Mapping_struct_t),
  M_NEXT_EXIST_OR_NULL  (DTM_Packet_Downlink_Assignment_t, EGPRS_Mode, 2),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  EGPRS_WindowSize,  5),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  LINK_QUALITY_MEASUREMENT_MODE,  2),
  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  Packet_Extended_Timing_Advance,  2),
CSN_DESCR_END(DTM_Packet_Downlink_Assignment_t)

static const
CSN_DESCR_BEGIN(DTM_DL_t)
  M_TYPE       (DTM_DL_t, DTM_Packet_Downlink_Assignment, DTM_Packet_Downlink_Assignment_t),
CSN_DESCR_END(DTM_DL_t)

/* GPRS Broadcast Information */
static const
CSN_DESCR_BEGIN(DTM_GPRS_Broadcast_Information_t)
  M_TYPE       (DTM_GPRS_Broadcast_Information_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE       (DTM_GPRS_Broadcast_Information_t, GPRS_Power_Control_Parameters, GPRS_Power_Control_Parameters_t),
CSN_DESCR_END(DTM_GPRS_Broadcast_Information_t)

static const
CSN_DESCR_BEGIN(DTM_GPRS_B_t)
  M_TYPE       (DTM_GPRS_B_t, DTM_GPRS_Broadcast_Information, DTM_GPRS_Broadcast_Information_t),
CSN_DESCR_END(DTM_GPRS_B_t)

static const
CSN_DESCR_BEGIN(DTM_Channel_Request_Description_t)
  M_UINT       (DTM_Channel_Request_Description_t,  DTM_Pkt_Est_Cause,  2),
  M_TYPE       (DTM_Channel_Request_Description_t, Channel_Request_Description, Channel_Request_Description_t),
  M_NEXT_EXIST (DTM_Channel_Request_Description_t, Exist_PFI, 1),
  M_UINT       (DTM_Channel_Request_Description_t,  PFI,  7),
CSN_DESCR_END(DTM_Channel_Request_Description_t)
/* DTM  */

/*< Packet Paging Request message content > */
typedef struct
{
  guint8 Length_of_Mobile_Identity_contents;/* bit (4) */
  guint8 Mobile_Identity[8];/* octet (val (Length of Mobile Identity contents)) */
} Mobile_Identity_t; /* helper */

static const
CSN_DESCR_BEGIN(Mobile_Identity_t)
  M_UINT       (Mobile_Identity_t,  Length_of_Mobile_Identity_contents,  4),
  M_VAR_ARRAY  (Mobile_Identity_t, Mobile_Identity, Length_of_Mobile_Identity_contents, 0),
CSN_DESCR_END  (Mobile_Identity_t)

static const
CSN_DESCR_BEGIN(Page_request_for_TBF_establishment_t)
  M_UNION      (Page_request_for_TBF_establishment_t, 2),
  M_UINT_ARRAY (Page_request_for_TBF_establishment_t, u.PTMSI, 8, 4),/* bit (32) == 8*4 */
  M_TYPE       (Page_request_for_TBF_establishment_t, u.Mobile_Identity, Mobile_Identity_t),
CSN_DESCR_END  (Page_request_for_TBF_establishment_t)

static const
CSN_DESCR_BEGIN(Page_request_for_RR_conn_t)
  M_UNION      (Page_request_for_RR_conn_t, 2),
  M_UINT_ARRAY (Page_request_for_RR_conn_t, u.TMSI, 8, 4),/* bit (32) == 8*4 */
  M_TYPE       (Page_request_for_RR_conn_t, u.Mobile_Identity, Mobile_Identity_t),

  M_UINT       (Page_request_for_RR_conn_t,  CHANNEL_NEEDED,  2),

  M_NEXT_EXIST (Page_request_for_RR_conn_t, Exist_eMLPP_PRIORITY, 1),
  M_UINT       (Page_request_for_RR_conn_t,  eMLPP_PRIORITY,  3),
CSN_DESCR_END  (Page_request_for_RR_conn_t)

static const
CSN_DESCR_BEGIN(Repeated_Page_info_t)
  M_UNION      (Repeated_Page_info_t, 2),
  M_TYPE       (Repeated_Page_info_t, u.Page_req_TBF, Page_request_for_TBF_establishment_t),
  M_TYPE       (Repeated_Page_info_t, u.Page_req_RR, Page_request_for_RR_conn_t),
CSN_DESCR_END  (Repeated_Page_info_t)

static const
CSN_DESCR_BEGIN(Packet_Paging_Request_t)
  M_UINT       (Packet_Paging_Request_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Paging_Request_t,  PAGE_MODE,  2),

  M_NEXT_EXIST (Packet_Paging_Request_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (Packet_Paging_Request_t, PERSISTENCE_LEVEL, 4, 4), /* 4bit*4 */

  M_NEXT_EXIST (Packet_Paging_Request_t, Exist_NLN, 1),
  M_UINT       (Packet_Paging_Request_t,  NLN,  2),

  M_REC_TARRAY (Packet_Paging_Request_t, Repeated_Page_info, Repeated_Page_info_t, Count_Repeated_Page_info),
  M_PADDING_BITS(Packet_Paging_Request_t),
CSN_DESCR_END  (Packet_Paging_Request_t)

static const
CSN_DESCR_BEGIN(Packet_PDCH_Release_t)
  M_UINT       (Packet_PDCH_Release_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_PDCH_Release_t,  PAGE_MODE,  2),

  M_FIXED      (Packet_PDCH_Release_t, 1, 0x01),
  M_UINT       (Packet_PDCH_Release_t,  TIMESLOTS_AVAILABLE,  8),
  M_PADDING_BITS(Packet_PDCH_Release_t),
CSN_DESCR_END  (Packet_PDCH_Release_t)

/*< Packet Power Control/Timing Advance message content >*/
static const
CSN_DESCR_BEGIN(GlobalTimingAndPower_t)
  M_TYPE       (GlobalTimingAndPower_t, Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_TYPE       (GlobalTimingAndPower_t, Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END  (GlobalTimingAndPower_t)

static const
CSN_DESCR_BEGIN(GlobalTimingOrPower_t)
  M_UNION      (GlobalTimingOrPower_t, 2),
  M_TYPE       (GlobalTimingOrPower_t, u.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_TYPE       (GlobalTimingOrPower_t, u.Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END  (GlobalTimingOrPower_t)

static const
CSN_ChoiceElement_t PacketPowerControlTimingAdvanceID[] =
{
  {1, 0,    0, M_TYPE(PacketPowerControlTimingAdvanceID_t, u.Global_TFI, Global_TFI_t)},
  {3, 0x06, 0, M_UINT(PacketPowerControlTimingAdvanceID_t, u.TQI, 16)},
  {3, 0x07, 0, M_TYPE(PacketPowerControlTimingAdvanceID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
};

static const
CSN_DESCR_BEGIN(PacketPowerControlTimingAdvanceID_t)
  M_CHOICE     (PacketPowerControlTimingAdvanceID_t, UnionType, PacketPowerControlTimingAdvanceID, ElementsOf(PacketPowerControlTimingAdvanceID)),
CSN_DESCR_END  (PacketPowerControlTimingAdvanceID_t)

static const
CSN_DESCR_BEGIN(Packet_Power_Control_Timing_Advance_t)
  M_UINT       (Packet_Power_Control_Timing_Advance_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Power_Control_Timing_Advance_t,  PAGE_MODE,  2),

  M_TYPE       (Packet_Power_Control_Timing_Advance_t, ID, PacketPowerControlTimingAdvanceID_t),

  /*-- Message escape*/
  M_FIXED      (Packet_Power_Control_Timing_Advance_t, 1, 0x00),

  M_NEXT_EXIST (Packet_Power_Control_Timing_Advance_t, Exist_Global_Power_Control_Parameters, 1),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, Global_Power_Control_Parameters, Global_Power_Control_Parameters_t),

  M_UNION      (Packet_Power_Control_Timing_Advance_t, 2),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, u.GlobalTimingAndPower, GlobalTimingAndPower_t),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, u.GlobalTimingOrPower, GlobalTimingOrPower_t),

  M_PADDING_BITS(Packet_Power_Control_Timing_Advance_t),
CSN_DESCR_END  (Packet_Power_Control_Timing_Advance_t)

/*< Packet Queueing Notification message content > */
static const
CSN_DESCR_BEGIN(Packet_Queueing_Notification_t)
  M_UINT       (Packet_Queueing_Notification_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Queueing_Notification_t,  PAGE_MODE,  2),

  M_FIXED      (Packet_Queueing_Notification_t, 3, 0x07),/* 111 Fixed */
  M_TYPE       (Packet_Queueing_Notification_t, Packet_Request_Reference, Packet_Request_Reference_t),

  M_UINT       (Packet_Queueing_Notification_t,  TQI,  16),
  M_PADDING_BITS(Packet_Queueing_Notification_t),
CSN_DESCR_END  (Packet_Queueing_Notification_t)

/* USED in Packet Timeslot Reconfigure message content
 * This is almost the same structure as used in
 * <Packet Uplink Assignment message content> but UPLINK_TFI_ASSIGNMENT is removed.
 */
static const
CSN_DESCR_BEGIN(TRDynamic_Allocation_t)
  M_UINT       (TRDynamic_Allocation_t,  Extended_Dynamic_Allocation,  1),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (TRDynamic_Allocation_t,  P0,  4),
  M_UINT       (TRDynamic_Allocation_t,  PR_MODE,  1),

  M_UINT       (TRDynamic_Allocation_t,  USF_GRANULARITY,  1),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED, 1),
  M_UINT       (TRDynamic_Allocation_t,  RLC_DATA_BLOCKS_GRANTED,  8),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_TBF_Starting_Time, 1),
  M_TYPE       (TRDynamic_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_UNION      (TRDynamic_Allocation_t, 2),
  M_TYPE_ARRAY (TRDynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (TRDynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (TRDynamic_Allocation_t)

/*< Packet Timeslot Reconfigure message content > */
static const
CSN_DESCR_BEGIN(PTR_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PTR_GPRS_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PTR_GPRS_AdditionsR99_t,  Packet_Extended_Timing_Advance,  2),
CSN_DESCR_END  (PTR_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PTR_GPRS_t)
  M_UINT              (PTR_GPRS_t,  CHANNEL_CODING_COMMAND,  2),
  M_TYPE              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_RLC_MODE,  1),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.CONTROL_ACK,  1),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TFI_ASSIGNMENT,  5),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.UPLINK_TFI_ASSIGNMENT,  5),

  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TIMESLOT_ALLOCATION,  8),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_Frequency_Parameters, 1),
  M_TYPE              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Frequency_Parameters, Frequency_Parameters_t),

  M_UNION             (PTR_GPRS_t, 2),
  M_TYPE              (PTR_GPRS_t, u.Dynamic_Allocation, TRDynamic_Allocation_t),
  CSN_ERROR           (PTR_GPRS_t, "1 - Fixed Allocation was removed", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PTR_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PTR_GPRS_t, AdditionsR99, PTR_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PTR_GPRS_t)

static const
CSN_DESCR_BEGIN(PTR_EGPRS_00_t)
  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE       (PTR_EGPRS_00_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),

  M_UINT       (PTR_EGPRS_00_t,  EGPRS_ChannelCodingCommand,  4),
  M_UINT       (PTR_EGPRS_00_t,  RESEGMENT,  1),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_DOWNLINK_EGPRS_WindowSize, 1),
  M_UINT       (PTR_EGPRS_00_t,  DOWNLINK_EGPRS_WindowSize,  5),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_UPLINK_EGPRS_WindowSize, 1),
  M_UINT       (PTR_EGPRS_00_t,  UPLINK_EGPRS_WindowSize,  5),

  M_UINT       (PTR_EGPRS_00_t,  LINK_QUALITY_MEASUREMENT_MODE,  2),

  M_TYPE       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PTR_EGPRS_00_t,  Packet_Extended_Timing_Advance,  2),

  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_RLC_MODE,  1),
  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.CONTROL_ACK,  1),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TFI_ASSIGNMENT,  5),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.UPLINK_TFI_ASSIGNMENT,  5),

  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TIMESLOT_ALLOCATION,  8),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_Frequency_Parameters, 1),
  M_TYPE       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Frequency_Parameters, Frequency_Parameters_t),

  M_UNION      (PTR_EGPRS_00_t, 2),
  M_TYPE       (PTR_EGPRS_00_t, u.Dynamic_Allocation, TRDynamic_Allocation_t),
  CSN_ERROR    (PTR_EGPRS_00_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PTR_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PTR_EGPRS_t)
  M_UNION      (PTR_EGPRS_t, 4),
  M_TYPE       (PTR_EGPRS_t, u.PTR_EGPRS_00, PTR_EGPRS_00_t),
  CSN_ERROR    (PTR_EGPRS_t, "01 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PTR_EGPRS_t, "10 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PTR_EGPRS_t, "11 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PTR_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Timeslot_Reconfigure_t)
  M_UINT       (Packet_Timeslot_Reconfigure_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Timeslot_Reconfigure_t,  PAGE_MODE,  2),

  M_FIXED      (Packet_Timeslot_Reconfigure_t, 1, 0x00),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, Global_TFI, Global_TFI_t),

  M_UNION      (Packet_Timeslot_Reconfigure_t, 2),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, u.PTR_GPRS_Struct, PTR_GPRS_t),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, u.PTR_EGPRS_Struct, PTR_EGPRS_t),

  M_PADDING_BITS(Packet_Timeslot_Reconfigure_t),
CSN_DESCR_END  (Packet_Timeslot_Reconfigure_t)

typedef Packet_Timeslot_Reconfigure_t PTRCheck_t;

static const
CSN_DESCR_BEGIN(PTRCheck_t)
  M_UINT       (PTRCheck_t,  MESSAGE_TYPE,  6),
  M_UINT       (PTRCheck_t,  PAGE_MODE,  2),
  M_FIXED      (PTRCheck_t, 1, 0x00),/* 0 fixed */
  M_TYPE       (PTRCheck_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (PTRCheck_t)

/*< Packet PRACH Parameters message content > */
static const
CSN_DESCR_BEGIN(PRACH_Control_t)
  M_UINT_ARRAY (PRACH_Control_t, ACC_CONTR_CLASS, 8, 2), /* bit (16) == 8bit*2 */
  M_UINT_ARRAY (PRACH_Control_t, MAX_RETRANS, 2, 4), /* bit (2) * 4 */
  M_UINT       (PRACH_Control_t,  S,  4),
  M_UINT       (PRACH_Control_t,  TX_INT,  4),
  M_NEXT_EXIST (PRACH_Control_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (PRACH_Control_t, PERSISTENCE_LEVEL, 4, 4),
CSN_DESCR_END  (PRACH_Control_t)

static const
CSN_DESCR_BEGIN(Cell_Allocation_t)
  M_REC_ARRAY  (Cell_Allocation_t, RFL_Number, NoOfRFLs, 4),
CSN_DESCR_END  (Cell_Allocation_t)

static const
CSN_DESCR_BEGIN(HCS_t)
  M_UINT       (HCS_t,  PRIORITY_CLASS,  3),
  M_UINT       (HCS_t,  HCS_THR,  5),
CSN_DESCR_END  (HCS_t)

static const
CSN_DESCR_BEGIN(Location_Repeat_t)
  M_UINT       (Location_Repeat_t,  PBCCH_LOCATION,  2),
  M_UINT       (Location_Repeat_t,  PSI1_REPEAT_PERIOD,  4),
CSN_DESCR_END  (Location_Repeat_t)

static const
CSN_DESCR_BEGIN(SI13_PBCCH_Location_t)
  M_UNION      (SI13_PBCCH_Location_t, 2),
  M_UINT       (SI13_PBCCH_Location_t,  u.SI13_LOCATION,  1),
  M_TYPE       (SI13_PBCCH_Location_t, u.lr, Location_Repeat_t),
CSN_DESCR_END  (SI13_PBCCH_Location_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_t)
  M_UINT       (Cell_Selection_t,  BSIC,  6),
  M_UINT       (Cell_Selection_t,  CELL_BAR_ACCESS_2,  1),
  M_UINT       (Cell_Selection_t,  EXC_ACC,  1),
  M_UINT       (Cell_Selection_t,  SAME_RA_AS_SERVING_CELL,  1),
  M_NEXT_EXIST (Cell_Selection_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (Cell_Selection_t,  GPRS_RXLEV_ACCESS_MIN,  6),
  M_UINT       (Cell_Selection_t,  GPRS_MS_TXPWR_MAX_CCH,  5),
  M_NEXT_EXIST (Cell_Selection_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (Cell_Selection_t,  GPRS_TEMPORARY_OFFSET,  3),
  M_UINT       (Cell_Selection_t,  GPRS_PENALTY_TIME,  5),
  M_NEXT_EXIST (Cell_Selection_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (Cell_Selection_t,  GPRS_RESELECT_OFFSET,  5),
  M_NEXT_EXIST (Cell_Selection_t, Exist_HCS, 1),
  M_TYPE       (Cell_Selection_t, HCS, HCS_t),
  M_NEXT_EXIST (Cell_Selection_t, Exist_SI13_PBCCH_Location, 1),
  M_TYPE       (Cell_Selection_t, SI13_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (Cell_Selection_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_Params_With_FreqDiff_t)
  M_VAR_BITMAP (Cell_Selection_Params_With_FreqDiff_t, FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_TYPE       (Cell_Selection_Params_With_FreqDiff_t, Cell_SelectionParams, Cell_Selection_t),
CSN_DESCR_END  (Cell_Selection_Params_With_FreqDiff_t)

static const
CSN_DESCR_BEGIN(NeighbourCellParameters_t)
  M_UINT       (NeighbourCellParameters_t,  START_FREQUENCY,  10),
  M_TYPE       (NeighbourCellParameters_t, Cell_Selection, Cell_Selection_t),
  M_UINT       (NeighbourCellParameters_t,  NR_OF_REMAINING_CELLS,  4),
  M_UINT_OFFSET(NeighbourCellParameters_t, FREQ_DIFF_LENGTH, 3, 1),/* offset 1 */
  M_VAR_TARRAY (NeighbourCellParameters_t, Cell_Selection_Params_With_FreqDiff, Cell_Selection_Params_With_FreqDiff_t, NR_OF_REMAINING_CELLS),
CSN_DESCR_END  (NeighbourCellParameters_t)

static const
CSN_DESCR_BEGIN(NeighbourCellList_t)
  M_REC_TARRAY (NeighbourCellList_t, Parameters, NeighbourCellParameters_t, Count),
CSN_DESCR_END  (NeighbourCellList_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_2_t)
  M_UINT       (Cell_Selection_2_t,  CELL_BAR_ACCESS_2,  1),
  M_UINT       (Cell_Selection_2_t,  EXC_ACC,  1),
  M_UINT       (Cell_Selection_2_t,  SAME_RA_AS_SERVING_CELL,  1),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (Cell_Selection_2_t,  GPRS_RXLEV_ACCESS_MIN,  6),
  M_UINT       (Cell_Selection_2_t,  GPRS_MS_TXPWR_MAX_CCH,  5),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (Cell_Selection_2_t,  GPRS_TEMPORARY_OFFSET,  3),
  M_UINT       (Cell_Selection_2_t,  GPRS_PENALTY_TIME,  5),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (Cell_Selection_2_t,  GPRS_RESELECT_OFFSET,  5),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_HCS, 1),
  M_TYPE       (Cell_Selection_2_t, HCS, HCS_t),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_SI13_PBCCH_Location, 1),
  M_TYPE       (Cell_Selection_2_t, SI13_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (Cell_Selection_2_t)

static const
CSN_DESCR_BEGIN(Packet_PRACH_Parameters_t)
  M_UINT       (Packet_PRACH_Parameters_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_PRACH_Parameters_t,  PAGE_MODE,  2),

  M_TYPE       (Packet_PRACH_Parameters_t, PRACH_Control, PRACH_Control_t),
  M_PADDING_BITS(Packet_PRACH_Parameters_t),
CSN_DESCR_END  (Packet_PRACH_Parameters_t)

/* < Packet Access Reject message content > */
static const
CSN_ChoiceElement_t RejectID[] =
{
  {1, 0x00, 0, M_UINT(RejectID_t, u.TLLI, 32)},
  {2, 0x02, 0, M_TYPE(RejectID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
  {2, 0x03, 0, M_TYPE(RejectID_t, u.Global_TFI, Global_TFI_t)},
};

static const
CSN_DESCR_BEGIN(RejectID_t)
  M_CHOICE     (RejectID_t, UnionType, RejectID, ElementsOf(RejectID)),
CSN_DESCR_END  (RejectID_t)

static const
CSN_DESCR_BEGIN(Reject_t)
  M_TYPE       (Reject_t, ID, RejectID_t),

  M_NEXT_EXIST (Reject_t, Exist_Wait, 2),
  M_UINT       (Reject_t,  WAIT_INDICATION,  8),
  M_UINT       (Reject_t,  WAIT_INDICATION_SIZE,  1),
CSN_DESCR_END  (Reject_t)

static const
CSN_DESCR_BEGIN(Packet_Access_Reject_t)
  M_UINT       (Packet_Access_Reject_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Access_Reject_t,  PAGE_MODE,  2),

  M_REC_TARRAY_1(Packet_Access_Reject_t, Reject, Reject_t, Count_Reject),
  M_PADDING_BITS(Packet_Access_Reject_t),
CSN_DESCR_END  (Packet_Access_Reject_t)

/* < Packet Cell Change Order message content > */
static const
CSN_ChoiceElement_t PacketCellChangeOrderID[] =
{
  {1, 0,    0, M_TYPE(PacketCellChangeOrderID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketCellChangeOrderID_t, u.TLLI, 32)},
};
/* PacketCellChangeOrderID_t; */

static const
CSN_DESCR_BEGIN(PacketCellChangeOrderID_t)
  M_CHOICE     (PacketCellChangeOrderID_t, UnionType, PacketCellChangeOrderID, ElementsOf(PacketCellChangeOrderID)),
CSN_DESCR_END  (PacketCellChangeOrderID_t)

static const
CSN_DESCR_BEGIN(h_FreqBsicCell_t)
  M_UINT       (h_FreqBsicCell_t,  BSIC,  6),
  M_TYPE       (h_FreqBsicCell_t, Cell_Selection, Cell_Selection_t),
CSN_DESCR_END  (h_FreqBsicCell_t)

static const CSN_DESCR_BEGIN(CellSelectionParamsWithFreqDiff_t)
  /*FREQUENCY_DIFF is really an integer but the number of bits to decode it are stored in FREQ_DIFF_LENGTH*/
  M_VAR_BITMAP (CellSelectionParamsWithFreqDiff_t, FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_UINT       (CellSelectionParamsWithFreqDiff_t,  BSIC,  6),
  M_NEXT_EXIST (CellSelectionParamsWithFreqDiff_t, Exist_CellSelectionParams, 1),
  M_TYPE       (CellSelectionParamsWithFreqDiff_t, CellSelectionParams, Cell_Selection_2_t),
CSN_DESCR_END  (CellSelectionParamsWithFreqDiff_t)

static const
CSN_DESCR_BEGIN(Add_Frequency_list_t)
  M_UINT       (Add_Frequency_list_t,  START_FREQUENCY,  10),
  M_UINT       (Add_Frequency_list_t,  BSIC,  6),

  M_NEXT_EXIST (Add_Frequency_list_t, Exist_Cell_Selection, 1),
  M_TYPE       (Add_Frequency_list_t, Cell_Selection, Cell_Selection_2_t),

  M_UINT       (Add_Frequency_list_t,  NR_OF_FREQUENCIES,  5),
  M_UINT_OFFSET(Add_Frequency_list_t, FREQ_DIFF_LENGTH, 3, 1),/*offset 1*/

  M_VAR_TARRAY (Add_Frequency_list_t, CellSelectionParamsWithFreqDiff, CellSelectionParamsWithFreqDiff_t, NR_OF_FREQUENCIES),
CSN_DESCR_END  (Add_Frequency_list_t)

static const CSN_DESCR_BEGIN(Removed_Freq_Index_t)
  M_UINT(Removed_Freq_Index_t, REMOVED_FREQ_INDEX, 6),
CSN_DESCR_END(Removed_Freq_Index_t)

static const
CSN_DESCR_BEGIN(NC_Frequency_list_t)
  M_NEXT_EXIST (NC_Frequency_list_t, Exist_REMOVED_FREQ, 2),
  M_UINT_OFFSET(NC_Frequency_list_t, NR_OF_REMOVED_FREQ, 5, 1),/*offset 1*/
  M_VAR_TARRAY (NC_Frequency_list_t, Removed_Freq_Index, Removed_Freq_Index_t, NR_OF_REMOVED_FREQ),
  M_REC_TARRAY (NC_Frequency_list_t, Add_Frequency, Add_Frequency_list_t, Count_Add_Frequency),
CSN_DESCR_END  (NC_Frequency_list_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Parameters_t)
  M_UINT       (NC_Measurement_Parameters_t,  NETWORK_CONTROL_ORDER,  2),

  M_NEXT_EXIST (NC_Measurement_Parameters_t, Exist_NC, 3),
  M_UINT       (NC_Measurement_Parameters_t,  NC_NON_DRX_PERIOD,  3),
  M_UINT       (NC_Measurement_Parameters_t,  NC_REPORTING_PERIOD_I,  3),
  M_UINT       (NC_Measurement_Parameters_t,  NC_REPORTING_PERIOD_T,  3),
CSN_DESCR_END  (NC_Measurement_Parameters_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Parameters_with_Frequency_List_t)
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NETWORK_CONTROL_ORDER,  2),

  M_NEXT_EXIST (NC_Measurement_Parameters_with_Frequency_List_t, Exist_NC, 3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NC_NON_DRX_PERIOD,  3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NC_REPORTING_PERIOD_I,  3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NC_REPORTING_PERIOD_T,  3),

  M_NEXT_EXIST (NC_Measurement_Parameters_with_Frequency_List_t, Exist_NC_FREQUENCY_LIST, 1),
  M_TYPE       (NC_Measurement_Parameters_with_Frequency_List_t, NC_Frequency_list, NC_Frequency_list_t),
CSN_DESCR_END  (NC_Measurement_Parameters_with_Frequency_List_t)

/*< Packet Cell Change Order message contents >*/
static const
CSN_DESCR_BEGIN(BA_IND_t)
  M_UINT       (BA_IND_t,  BA_IND,  1),
  M_UINT       (BA_IND_t,  BA_IND_3G,  1),
CSN_DESCR_END  (BA_IND_t)

static const
CSN_DESCR_BEGIN(GPRSReportPriority_t)
  M_UINT       (GPRSReportPriority_t,  NUMBER_CELLS,  7),
  M_VAR_BITMAP (GPRSReportPriority_t, REPORT_PRIORITY, NUMBER_CELLS, 0),
CSN_DESCR_END  (GPRSReportPriority_t)

static const
CSN_DESCR_BEGIN(OffsetThreshold_t)
  M_UINT       (OffsetThreshold_t,  REPORTING_OFFSET,  3),
  M_UINT       (OffsetThreshold_t,  REPORTING_THRESHOLD,  3),
CSN_DESCR_END  (OffsetThreshold_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams_PMO_PCCO_t)
  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_MULTI_BAND_REPORTING, 1),
  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t,  MULTI_BAND_REPORTING,  2),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_SERVING_BAND_REPORTING, 1),
  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t,  SERVING_BAND_REPORTING,  2),

  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t,  SCALE_ORD,  2),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold900, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold900, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold1800, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold1800, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold400, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold400, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold1900, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold1900, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold850, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold850, OffsetThreshold_t),
CSN_DESCR_END  (GPRSMeasurementParams_PMO_PCCO_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams3G_t)
  M_UINT       (GPRSMeasurementParams3G_t,  Qsearch_p,  4),
  M_UINT       (GPRSMeasurementParams3G_t,  SearchPrio3G,  1),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existRepParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t,  RepQuantFDD,  1),
  M_UINT       (GPRSMeasurementParams3G_t,  MultiratReportingFDD,  2),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existReportingParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingOffsetFDD,  3),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingThresholdFDD,  3),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existMultiratReportingTDD, 1),
  M_UINT       (GPRSMeasurementParams3G_t,  MultiratReportingTDD,  2),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existOffsetThresholdTDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingOffsetTDD,  3),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingThresholdTDD,  3),
CSN_DESCR_END  (GPRSMeasurementParams3G_t)

static const
CSN_DESCR_BEGIN(MultiratParams3G_t)
  M_NEXT_EXIST (MultiratParams3G_t, existMultiratReporting, 1),
  M_UINT       (MultiratParams3G_t,  MultiratReporting,  2),

  M_NEXT_EXIST (MultiratParams3G_t, existOffsetThreshold, 1),
  M_TYPE       (MultiratParams3G_t, OffsetThreshold, OffsetThreshold_t),
CSN_DESCR_END  (MultiratParams3G_t)

static const
CSN_DESCR_BEGIN(ENH_GPRSMeasurementParams3G_PMO_t)
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  Qsearch_P,  4),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  SearchPrio3G,  1),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PMO_t, existRepParamsFDD, 2),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  RepQuantFDD,  1),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  MultiratReportingFDD,  2),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PMO_t, existOffsetThreshold, 1),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, OffsetThreshold, OffsetThreshold_t),

  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, ParamsTDD, MultiratParams3G_t),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, ParamsCDMA2000, MultiratParams3G_t),
CSN_DESCR_END  (ENH_GPRSMeasurementParams3G_PMO_t)

static const
CSN_DESCR_BEGIN(ENH_GPRSMeasurementParams3G_PCCO_t)
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  Qsearch_P,  4),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  SearchPrio3G,  1),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PCCO_t, existRepParamsFDD, 2),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  RepQuantFDD,  1),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  MultiratReportingFDD,  2),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PCCO_t, existOffsetThreshold, 1),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PCCO_t, OffsetThreshold, OffsetThreshold_t),

  M_TYPE       (ENH_GPRSMeasurementParams3G_PCCO_t, ParamsTDD, MultiratParams3G_t),
CSN_DESCR_END  (ENH_GPRSMeasurementParams3G_PCCO_t)

static const
CSN_DESCR_BEGIN(N2_t)
  M_UINT       (N2_t,  REMOVED_3GCELL_INDEX,  7),
  M_UINT       (N2_t,  CELL_DIFF_LENGTH_3G,  3),
  M_VAR_BITMAP (N2_t, CELL_DIFF_3G, CELL_DIFF_LENGTH_3G, 0),
CSN_DESCR_END  (N2_t)

static const
CSN_DESCR_BEGIN (N1_t)
  M_UINT_OFFSET (N1_t, N2_Count, 5, 1), /*offset 1*/
  M_VAR_TARRAY  (N1_t, N2s, N2_t, N2_Count),
CSN_DESCR_END   (N1_t)

static const
CSN_DESCR_BEGIN (Removed3GCellDescription_t)
  M_UINT_OFFSET (Removed3GCellDescription_t, N1_Count, 2, 1),  /* offset 1 */
  M_VAR_TARRAY  (Removed3GCellDescription_t, N1s, N1_t, N1_Count),
CSN_DESCR_END   (Removed3GCellDescription_t)

static const
CSN_DESCR_BEGIN(CDMA2000_Description_t)
  M_UINT       (CDMA2000_Description_t,  Complete_This,  1),
  CSN_ERROR    (CDMA2000_Description_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (CDMA2000_Description_t)

static const
CSN_DESCR_BEGIN(UTRAN_FDD_NeighbourCells_t)
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  ZERO,      1),
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  UARFCN,   14),
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  Indic0,      1),
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  NrOfCells,   5),
/*  M_CALLBACK   (UTRAN_FDD_NeighbourCells_t, (void*) 14, NrOfCells, BitsInCellInfo), */
  M_VAR_BITMAP (UTRAN_FDD_NeighbourCells_t, CellInfo,  BitsInCellInfo, 0),
CSN_DESCR_END  (UTRAN_FDD_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(UTRAN_FDD_Description_t)
  M_NEXT_EXIST (UTRAN_FDD_Description_t, existBandwidth, 1),
  M_UINT       (UTRAN_FDD_Description_t,  Bandwidth,       3),
  M_REC_TARRAY (UTRAN_FDD_Description_t, CellParams, UTRAN_FDD_NeighbourCells_t, NrOfFrequencies),
CSN_DESCR_END  (UTRAN_FDD_Description_t)

static const
CSN_DESCR_BEGIN(UTRAN_TDD_NeighbourCells_t)
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  ZERO,      1),
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  UARFCN,   14),
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  Indic0,      1),
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  NrOfCells,   5),
/*  M_CALLBACK   (UTRAN_TDD_NeighbourCells_t, (void*) 23, NrOfCells, BitsInCellInfo), */
  M_VAR_BITMAP (UTRAN_TDD_NeighbourCells_t, CellInfo,  BitsInCellInfo, 0),
CSN_DESCR_END  (UTRAN_TDD_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(UTRAN_TDD_Description_t)
  M_NEXT_EXIST (UTRAN_TDD_Description_t, existBandwidth, 1),
  M_UINT       (UTRAN_TDD_Description_t,  Bandwidth,       3),
  M_REC_TARRAY (UTRAN_TDD_Description_t, CellParams, UTRAN_TDD_NeighbourCells_t, NrOfFrequencies),
CSN_DESCR_END  (UTRAN_TDD_Description_t)

static const
CSN_DESCR_BEGIN(NeighbourCellDescription3G_PMO_t)
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Index_Start_3G, 1),
  M_UINT       (NeighbourCellDescription3G_PMO_t,  Index_Start_3G,  7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Absolute_Index_Start_EMR, 1),
  M_UINT       (NeighbourCellDescription3G_PMO_t,  Absolute_Index_Start_EMR,  7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_UTRAN_FDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, UTRAN_FDD_Description, UTRAN_FDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_UTRAN_TDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, UTRAN_TDD_Description, UTRAN_TDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_CDMA2000_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, CDMA2000_Description, CDMA2000_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Removed3GCellDescription, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, Removed3GCellDescription, Removed3GCellDescription_t),
CSN_DESCR_END  (NeighbourCellDescription3G_PMO_t)

static const
CSN_DESCR_BEGIN(NeighbourCellDescription3G_PCCO_t)
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Index_Start_3G, 1),
  M_UINT       (NeighbourCellDescription3G_PCCO_t,  Index_Start_3G,  7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Absolute_Index_Start_EMR, 1),
  M_UINT       (NeighbourCellDescription3G_PCCO_t,  Absolute_Index_Start_EMR,  7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_UTRAN_FDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, UTRAN_FDD_Description, UTRAN_FDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_UTRAN_TDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, UTRAN_TDD_Description, UTRAN_TDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Removed3GCellDescription, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, Removed3GCellDescription, Removed3GCellDescription_t),
CSN_DESCR_END  (NeighbourCellDescription3G_PCCO_t)

static const
CSN_DESCR_BEGIN(ENH_Measurement_Parameters_PMO_t)
  M_UNION      (ENH_Measurement_Parameters_PMO_t, 2),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, u.BA_IND, BA_IND_t),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  u.PSI3_CHANGE_MARK,  2),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  PMO_IND,  1),

  M_UINT       (ENH_Measurement_Parameters_PMO_t,  REPORT_TYPE,  1),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  REPORTING_RATE,  1),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  INVALID_BSIC_REPORTING,  1),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_NeighbourCellDescription3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, NeighbourCellDescription3G, NeighbourCellDescription3G_PMO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSReportPriority, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSReportPriority, GPRSReportPriority_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSMeasurementParams, GPRSMeasurementParams_PMO_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSMeasurementParams3G, ENH_GPRSMeasurementParams3G_PMO_t),
CSN_DESCR_END  (ENH_Measurement_Parameters_PMO_t)

static const
CSN_DESCR_BEGIN(ENH_Measurement_Parameters_PCCO_t)
  M_UNION      (ENH_Measurement_Parameters_PCCO_t, 2),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, u.BA_IND, BA_IND_t),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  u.PSI3_CHANGE_MARK,  2),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  PMO_IND,  1),

  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  REPORT_TYPE,  1),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  REPORTING_RATE,  1),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  INVALID_BSIC_REPORTING,  1),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_NeighbourCellDescription3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, NeighbourCellDescription3G, NeighbourCellDescription3G_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSReportPriority, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSReportPriority, GPRSReportPriority_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSMeasurementParams, GPRSMeasurementParams_PMO_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSMeasurementParams3G, ENH_GPRSMeasurementParams3G_PCCO_t),
CSN_DESCR_END  (ENH_Measurement_Parameters_PCCO_t)

static const
CSN_DESCR_BEGIN(CCN_Support_Description_t)
  M_UINT       (CCN_Support_Description_t,  NUMBER_CELLS,  7),
  M_VAR_BITMAP (CCN_Support_Description_t, CCN_SUPPORTED, NUMBER_CELLS, 0),
CSN_DESCR_END  (CCN_Support_Description_t)

static const
CSN_DESCR_BEGIN(lu_ModeCellSelectionParameters_t)
  M_UINT       (lu_ModeCellSelectionParameters_t,  CELL_BAR_QUALIFY_3,  2),
  M_NEXT_EXIST (lu_ModeCellSelectionParameters_t, Exist_SI13_Alt_PBCCH_Location, 1),
  M_TYPE       (lu_ModeCellSelectionParameters_t, SI13_Alt_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (lu_ModeCellSelectionParameters_t)

static const
CSN_DESCR_BEGIN(lu_ModeCellSelectionParams_t)
  M_NEXT_EXIST (lu_ModeCellSelectionParams_t, Exist_lu_ModeCellSelectionParams, 1),
  M_TYPE       (lu_ModeCellSelectionParams_t, lu_ModeCellSelectionParameters, lu_ModeCellSelectionParameters_t),
CSN_DESCR_END  (lu_ModeCellSelectionParams_t)

static const
CSN_DESCR_BEGIN(lu_ModeNeighbourCellParams_t)
  M_TYPE       (lu_ModeNeighbourCellParams_t, lu_ModeCellSelectionParameters, lu_ModeCellSelectionParams_t),
  M_UINT       (lu_ModeNeighbourCellParams_t,  NR_OF_FREQUENCIES,  5),
  M_VAR_TARRAY (lu_ModeNeighbourCellParams_t, lu_ModeCellSelectionParams, lu_ModeCellSelectionParams_t, NR_OF_FREQUENCIES),
CSN_DESCR_END  (lu_ModeNeighbourCellParams_t)

static const
CSN_DESCR_BEGIN(lu_ModeOnlyCellSelection_t)
  M_UINT       (lu_ModeOnlyCellSelection_t,  CELL_BAR_QUALIFY_3,  2),
  M_UINT       (lu_ModeOnlyCellSelection_t,  SAME_RA_AS_SERVING_CELL,  1),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_RXLEV_ACCESS_MIN,  6),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_MS_TXPWR_MAX_CCH,  5),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_TEMPORARY_OFFSET,  3),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_PENALTY_TIME,  5),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_RESELECT_OFFSET,  5),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_HCS, 1),
  M_TYPE       (lu_ModeOnlyCellSelection_t, HCS, HCS_t),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_SI13_Alt_PBCCH_Location, 1),
  M_TYPE       (lu_ModeOnlyCellSelection_t, SI13_Alt_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (lu_ModeOnlyCellSelection_t)

static const
CSN_DESCR_BEGIN(lu_ModeOnlyCellSelectionParamsWithFreqDiff_t)
  /*FREQUENCY_DIFF is really an integer but the number of bits to decode it are stored in FREQ_DIFF_LENGTH*/
  M_VAR_BITMAP (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_UINT       (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t,  BSIC,  6),
  M_NEXT_EXIST (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, Exist_lu_ModeOnlyCellSelectionParams, 1),
  M_TYPE       (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, lu_ModeOnlyCellSelectionParams, lu_ModeOnlyCellSelection_t),
CSN_DESCR_END  (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t)

static const
CSN_DESCR_BEGIN(Add_lu_ModeOnlyFrequencyList_t)
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  START_FREQUENCY,  10),
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  BSIC,  6),

  M_NEXT_EXIST (Add_lu_ModeOnlyFrequencyList_t, Exist_lu_ModeCellSelection, 1),
  M_TYPE       (Add_lu_ModeOnlyFrequencyList_t, lu_ModeOnlyCellSelection, lu_ModeOnlyCellSelection_t),

  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  NR_OF_FREQUENCIES,  5),
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  FREQ_DIFF_LENGTH,  3),

  M_VAR_TARRAY (Add_lu_ModeOnlyFrequencyList_t, lu_ModeOnlyCellSelectionParamsWithFreqDiff, lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, NR_OF_FREQUENCIES),
CSN_DESCR_END  (Add_lu_ModeOnlyFrequencyList_t)

static const
CSN_DESCR_BEGIN(NC_lu_ModeOnlyCapableCellList_t)
  M_REC_TARRAY (NC_lu_ModeOnlyCapableCellList_t, Add_lu_ModeOnlyFrequencyList, Add_lu_ModeOnlyFrequencyList_t, Count_Add_lu_ModeOnlyFrequencyList),
CSN_DESCR_END  (NC_lu_ModeOnlyCapableCellList_t)

static const
CSN_DESCR_BEGIN(GPRS_AdditionalMeasurementParams3G_t)
  M_NEXT_EXIST (GPRS_AdditionalMeasurementParams3G_t, Exist_FDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (GPRS_AdditionalMeasurementParams3G_t,  FDD_REPORTING_THRESHOLD_2,  6),
CSN_DESCR_END  (GPRS_AdditionalMeasurementParams3G_t)

static const
CSN_DESCR_BEGIN(ServingCellPriorityParametersDescription_t)
  M_UINT       (ServingCellPriorityParametersDescription_t,  GERAN_PRIORITY,  3),
  M_UINT       (ServingCellPriorityParametersDescription_t,  THRESH_Priority_Search,  4),
  M_UINT       (ServingCellPriorityParametersDescription_t,  THRESH_GSM_low,  4),
  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2),
  M_UINT       (ServingCellPriorityParametersDescription_t,  T_Reselection,  2),
CSN_DESCR_END  (ServingCellPriorityParametersDescription_t)

static const
CSN_DESCR_BEGIN(RepeatedUTRAN_PriorityParameters_t)
  M_REC_ARRAY  (RepeatedUTRAN_PriorityParameters_t, UTRAN_FREQUENCY_INDEX_a, NumberOfFrequencyIndexes, 5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existUTRAN_PRIORITY, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  UTRAN_PRIORITY,  3),

  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  THRESH_UTRAN_high,  5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existTHRESH_UTRAN_low, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  THRESH_UTRAN_low,  5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existUTRAN_QRXLEVMIN, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  UTRAN_QRXLEVMIN,  5),
CSN_DESCR_END  (RepeatedUTRAN_PriorityParameters_t)

static const
CSN_DESCR_BEGIN(PriorityParametersDescription3G_PMO_t)

  M_NEXT_EXIST (PriorityParametersDescription3G_PMO_t, existDEFAULT_UTRAN_Parameters, 3),
  M_UINT       (PriorityParametersDescription3G_PMO_t,  DEFAULT_UTRAN_PRIORITY,  3),
  M_UINT       (PriorityParametersDescription3G_PMO_t,  DEFAULT_THRESH_UTRAN,  5),
  M_UINT       (PriorityParametersDescription3G_PMO_t,  DEFAULT_UTRAN_QRXLEVMIN,  5),

  M_REC_TARRAY (PriorityParametersDescription3G_PMO_t, RepeatedUTRAN_PriorityParameters_a, RepeatedUTRAN_PriorityParameters_t, NumberOfPriorityParameters),
CSN_DESCR_END  (PriorityParametersDescription3G_PMO_t)

static const
CSN_DESCR_BEGIN(EUTRAN_REPORTING_THRESHOLD_OFFSET_t)
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_THRESHOLD_OFFSET, 5),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_FDD_REPORTING_THRESHOLD,  3),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_FDD_REPORTING_THRESHOLD_2,  6),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_OFFSET, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_FDD_REPORTING_OFFSET,  3),

  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_THRESHOLD_OFFSET, 5),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_TDD_REPORTING_THRESHOLD,  3),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_TDD_REPORTING_THRESHOLD_2,  6),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_OFFSET, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_TDD_REPORTING_OFFSET,  3),
CSN_DESCR_END  (EUTRAN_REPORTING_THRESHOLD_OFFSET_t)

static const
CSN_DESCR_BEGIN(GPRS_EUTRAN_MeasurementParametersDescription_t)
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t,  Qsearch_P_EUTRAN,  4),
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t,  EUTRAN_REP_QUANT, 1),
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t,  EUTRAN_MULTIRAT_REPORTING,  2),
  M_TYPE       (GPRS_EUTRAN_MeasurementParametersDescription_t, EUTRAN_REPORTING_THRESHOLD_OFFSET, EUTRAN_REPORTING_THRESHOLD_OFFSET_t),
CSN_DESCR_END  (GPRS_EUTRAN_MeasurementParametersDescription_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_Cells_t)
  M_UINT       (RepeatedEUTRAN_Cells_t,  EARFCN,  16),
  M_NEXT_EXIST (RepeatedEUTRAN_Cells_t, existMeasurementBandwidth, 1),
  M_UINT       (RepeatedEUTRAN_Cells_t,  MeasurementBandwidth,  3),
CSN_DESCR_END  (RepeatedEUTRAN_Cells_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_NeighbourCells_t)
  M_REC_TARRAY (RepeatedEUTRAN_NeighbourCells_t, EUTRAN_Cells_a, RepeatedEUTRAN_Cells_t, nbrOfEUTRAN_Cells),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existEUTRAN_PRIORITY, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  EUTRAN_PRIORITY,  3),

  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  THRESH_EUTRAN_high,  5),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existTHRESH_EUTRAN_low, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  THRESH_EUTRAN_low,  5),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existEUTRAN_QRXLEVMIN, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  EUTRAN_QRXLEVMIN,  5),
CSN_DESCR_END  (RepeatedEUTRAN_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(PCID_Pattern_t)
  M_UINT       (PCID_Pattern_t,  PCID_Pattern_length,  3),
  M_VAR_BITMAP (PCID_Pattern_t, PCID_Pattern, PCID_Pattern_length, 1), /* offset 1, 44.060 12.57 */
  M_UINT       (PCID_Pattern_t,  PCID_Pattern_sense,  1),
CSN_DESCR_END  (PCID_Pattern_t)

static const
CSN_DESCR_BEGIN(PCID_Group_IE_t)

  M_REC_ARRAY  (PCID_Group_IE_t, PCID_a, NumberOfPCIDs, 9),

  M_NEXT_EXIST (PCID_Group_IE_t, existPCID_BITMAP_GROUP, 1),
  M_UINT       (PCID_Group_IE_t,  PCID_BITMAP_GROUP,  6),

  M_REC_TARRAY (PCID_Group_IE_t, PCID_Pattern_a, PCID_Pattern_t, NumberOfPCID_Patterns),
CSN_DESCR_END  (PCID_Group_IE_t)

static const
CSN_DESCR_BEGIN(EUTRAN_FREQUENCY_INDEX_t)
  M_UINT       (EUTRAN_FREQUENCY_INDEX_t,  EUTRAN_FREQUENCY_INDEX,  3),
CSN_DESCR_END  (EUTRAN_FREQUENCY_INDEX_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_NotAllowedCells_t)
  M_TYPE       (RepeatedEUTRAN_NotAllowedCells_t, NotAllowedCells, PCID_Group_IE_t),

  M_REC_TARRAY (RepeatedEUTRAN_NotAllowedCells_t, EUTRAN_FREQUENCY_INDEX_a, EUTRAN_FREQUENCY_INDEX_t, NumberOfFrequencyIndexes),
CSN_DESCR_END  (RepeatedEUTRAN_NotAllowedCells_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_PCID_to_TA_mapping_t)
  M_REC_TARRAY (RepeatedEUTRAN_PCID_to_TA_mapping_t, PCID_ToTA_Mapping_a, PCID_Group_IE_t, NumberOfMappings),
  M_REC_TARRAY (RepeatedEUTRAN_PCID_to_TA_mapping_t, EUTRAN_FREQUENCY_INDEX_a, EUTRAN_FREQUENCY_INDEX_t, NumberOfFrequencyIndexes),
CSN_DESCR_END  (RepeatedEUTRAN_PCID_to_TA_mapping_t)

static const
CSN_DESCR_BEGIN(EUTRAN_ParametersDescription_PMO_t)
  M_UINT       (EUTRAN_ParametersDescription_PMO_t,  EUTRAN_CCN_ACTIVE, 1),

  M_NEXT_EXIST (EUTRAN_ParametersDescription_PMO_t, existGPRS_EUTRAN_MeasurementParametersDescription, 1),
  M_TYPE       (EUTRAN_ParametersDescription_PMO_t, GPRS_EUTRAN_MeasurementParametersDescription, GPRS_EUTRAN_MeasurementParametersDescription_t),

  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_NeighbourCells_a, RepeatedEUTRAN_NeighbourCells_t, nbrOfRepeatedEUTRAN_NeighbourCellsStructs),
  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_NotAllowedCells_a, RepeatedEUTRAN_NotAllowedCells_t, NumberOfNotAllowedCells),
  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_PCID_to_TA_mapping_a, RepeatedEUTRAN_PCID_to_TA_mapping_t, NumberOfMappings),
CSN_DESCR_END  (EUTRAN_ParametersDescription_PMO_t)

static const
CSN_DESCR_BEGIN(PSC_Pattern_t)
  M_UINT       (PSC_Pattern_t,  PSC_Pattern_length,  3),
  M_VAR_BITMAP (PSC_Pattern_t,  PSC_Pattern, PSC_Pattern_length, 1),
  M_UINT        (PSC_Pattern_t,  PSC_Pattern_sense, 1),
CSN_DESCR_END  (PSC_Pattern_t)

static const
CSN_DESCR_BEGIN(PSC_Group_t)
  M_REC_ARRAY  (PSC_Group_t, PSC, PSC_Count, 9),
  M_REC_TARRAY (PSC_Group_t, PSC_Pattern, PSC_Pattern_t, PSC_Pattern_Count),
CSN_DESCR_END  (PSC_Group_t)

static const
CSN_DESCR_BEGIN(ThreeG_CSG_Description_Body_t)
  M_TYPE       (ThreeG_CSG_Description_Body_t, CSG_PSC_SPLIT, PSC_Group_t),
  M_REC_ARRAY  (ThreeG_CSG_Description_Body_t, UTRAN_FREQUENCY_INDEX, Count, 5),
CSN_DESCR_END  (ThreeG_CSG_Description_Body_t)

static const
CSN_DESCR_BEGIN(ThreeG_CSG_Description_t)
  M_REC_TARRAY (ThreeG_CSG_Description_t, ThreeG_CSG_Description_Body, ThreeG_CSG_Description_Body_t, Count),
CSN_DESCR_END  (ThreeG_CSG_Description_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Description_Body_t)
  M_TYPE       (EUTRAN_CSG_Description_Body_t, CSG_PCI_SPLIT, PSC_Group_t),
  M_REC_ARRAY  (EUTRAN_CSG_Description_Body_t, EUTRAN_FREQUENCY_INDEX, Count, 3),
CSN_DESCR_END  (EUTRAN_CSG_Description_Body_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Description_t)
  M_REC_TARRAY (EUTRAN_CSG_Description_t, EUTRAN_CSG_Description_Body, EUTRAN_CSG_Description_Body_t, Count),
CSN_DESCR_END  (EUTRAN_CSG_Description_t)

static const
CSN_DESCR_BEGIN(Meas_Ctrl_Param_Desp_t)
  M_NEXT_EXIST (Meas_Ctrl_Param_Desp_t, existMeasurement_Control_EUTRAN, 3),
  M_UINT       (Meas_Ctrl_Param_Desp_t,  Measurement_Control_EUTRAN, 1),
  M_UINT       (Meas_Ctrl_Param_Desp_t,  EUTRAN_FREQUENCY_INDEX_top, 3),
  M_REC_ARRAY  (Meas_Ctrl_Param_Desp_t,  EUTRAN_FREQUENCY_INDEX, Count_EUTRAN_FREQUENCY_INDEX, 3),
  M_NEXT_EXIST (Meas_Ctrl_Param_Desp_t, existMeasurement_Control_UTRAN, 1),
  M_UINT       (Meas_Ctrl_Param_Desp_t, Measurement_Control_UTRAN, 1),
  M_UINT       (Meas_Ctrl_Param_Desp_t, UTRAN_FREQUENCY_INDEX_top,  5),
  M_REC_ARRAY  (Meas_Ctrl_Param_Desp_t, UTRAN_FREQUENCY_INDEX, Count_UTRAN_FREQUENCY_INDEX, 5),
CSN_DESCR_END  (Meas_Ctrl_Param_Desp_t)

static const
CSN_DESCR_BEGIN(Reselection_Based_On_RSRQ_t)
  M_UINT       (Reselection_Based_On_RSRQ_t,  THRESH_EUTRAN_high_Q,  5),
  M_NEXT_EXIST (Reselection_Based_On_RSRQ_t, existTHRESH_EUTRAN_low_Q, 1),
  M_UINT       (Reselection_Based_On_RSRQ_t,  THRESH_EUTRAN_low_Q,  5),
  M_NEXT_EXIST (Reselection_Based_On_RSRQ_t, existEUTRAN_QQUALMIN, 1),
  M_UINT       (Reselection_Based_On_RSRQ_t,  EUTRAN_QQUALMIN,  4),
  M_NEXT_EXIST (Reselection_Based_On_RSRQ_t, existEUTRAN_RSRPmin, 1),
  M_UINT       (Reselection_Based_On_RSRQ_t,  EUTRAN_RSRPmin,  5),
CSN_DESCR_END  (Reselection_Based_On_RSRQ_t)

static const
CSN_DESCR_BEGIN(Rept_EUTRAN_Enh_Cell_Resel_Param_t)
  M_REC_ARRAY  (Rept_EUTRAN_Enh_Cell_Resel_Param_t,  EUTRAN_FREQUENCY_INDEX, Count_EUTRAN_FREQUENCY_INDEX, 3),
  M_UNION      (Rept_EUTRAN_Enh_Cell_Resel_Param_t, 2),
  M_UINT       (Rept_EUTRAN_Enh_Cell_Resel_Param_t,  u.EUTRAN_Qmin,  4),
  M_TYPE       (Rept_EUTRAN_Enh_Cell_Resel_Param_t,  u.Reselection_Based_On_RSRQ, Reselection_Based_On_RSRQ_t),
CSN_DESCR_END  (Rept_EUTRAN_Enh_Cell_Resel_Param_t)

static const
CSN_DESCR_BEGIN(Enh_Cell_Reselect_Param_Desp_t)
  M_REC_TARRAY (Enh_Cell_Reselect_Param_Desp_t, Repeated_EUTRAN_Enhanced_Cell_Reselection_Parameters, Rept_EUTRAN_Enh_Cell_Resel_Param_t, Count),
CSN_DESCR_END  (Enh_Cell_Reselect_Param_Desp_t)

static const
CSN_DESCR_BEGIN(UTRAN_CSG_Cells_Reporting_Desp_t)
  M_NEXT_EXIST (UTRAN_CSG_Cells_Reporting_Desp_t, existUTRAN_CSG_FDD_REPORTING_THRESHOLD, 2),
  M_UINT       (UTRAN_CSG_Cells_Reporting_Desp_t, UTRAN_CSG_FDD_REPORTING_THRESHOLD, 3),
  M_UINT       (UTRAN_CSG_Cells_Reporting_Desp_t, UTRAN_CSG_FDD_REPORTING_THRESHOLD_2, 6),
  M_NEXT_EXIST (UTRAN_CSG_Cells_Reporting_Desp_t, existUTRAN_CSG_TDD_REPORTING_THRESHOLD, 1),
  M_UINT       (UTRAN_CSG_Cells_Reporting_Desp_t, UTRAN_CSG_TDD_REPORTING_THRESHOLD, 3),
CSN_DESCR_END  (UTRAN_CSG_Cells_Reporting_Desp_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Cells_Reporting_Desp_t)
  M_NEXT_EXIST (EUTRAN_CSG_Cells_Reporting_Desp_t, existEUTRAN_CSG_FDD_REPORTING_THRESHOLD, 2),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_FDD_REPORTING_THRESHOLD, 3),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_FDD_REPORTING_THRESHOLD_2, 6),
  M_NEXT_EXIST (EUTRAN_CSG_Cells_Reporting_Desp_t, existEUTRAN_CSG_TDD_REPORTING_THRESHOLD, 2),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_TDD_REPORTING_THRESHOLD, 3),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_TDD_REPORTING_THRESHOLD_2, 6),
CSN_DESCR_END  (EUTRAN_CSG_Cells_Reporting_Desp_t)


static const
CSN_DESCR_BEGIN(CSG_Cells_Reporting_Desp_t)
  M_NEXT_EXIST (CSG_Cells_Reporting_Desp_t, existUTRAN_CSG_Cells_Reporting_Description, 1),
  M_TYPE       (CSG_Cells_Reporting_Desp_t, UTRAN_CSG_Cells_Reporting_Description, UTRAN_CSG_Cells_Reporting_Desp_t),
  M_NEXT_EXIST (CSG_Cells_Reporting_Desp_t, existEUTRAN_CSG_Cells_Reporting_Description, 1),
  M_TYPE       (CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_Cells_Reporting_Description, EUTRAN_CSG_Cells_Reporting_Desp_t),
CSN_DESCR_END  (CSG_Cells_Reporting_Desp_t)

static const
CSN_DESCR_BEGIN        (PriorityAndEUTRAN_ParametersDescription_PMO_t)
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existServingCellPriorityParametersDescription, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, ServingCellPriorityParametersDescription, ServingCellPriorityParametersDescription_t),
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existPriorityParametersDescription3G_PMO, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, PriorityParametersDescription3G_PMO, PriorityParametersDescription3G_PMO_t),
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existEUTRAN_ParametersDescription_PMO, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, EUTRAN_ParametersDescription_PMO, EUTRAN_ParametersDescription_PMO_t),
CSN_DESCR_END          (PriorityAndEUTRAN_ParametersDescription_PMO_t)


static const
CSN_DESCR_BEGIN        (Delete_All_Stored_Individual_Priorities_t)
  M_NULL               (Delete_All_Stored_Individual_Priorities_t, dummy, 0),
CSN_DESCR_END          (Delete_All_Stored_Individual_Priorities_t)

static const
CSN_DESCR_BEGIN        (Individual_UTRAN_Priority_FDD_t)
  M_REC_ARRAY          (Individual_UTRAN_Priority_FDD_t, FDD_ARFCN, Count, 14),
CSN_DESCR_END          (Individual_UTRAN_Priority_FDD_t)

static const
CSN_DESCR_BEGIN        (Individual_UTRAN_Priority_TDD_t)
  M_REC_ARRAY          (Individual_UTRAN_Priority_TDD_t, TDD_ARFCN, Count, 14),
CSN_DESCR_END          (Individual_UTRAN_Priority_TDD_t)

static const
CSN_DESCR_BEGIN        (Repeated_Individual_UTRAN_Priority_Parameters_t)
  M_UNION              (Repeated_Individual_UTRAN_Priority_Parameters_t, 2),
  M_TYPE               (Repeated_Individual_UTRAN_Priority_Parameters_t, u.Individual_UTRAN_Priority_FDD, Individual_UTRAN_Priority_FDD_t),
  M_TYPE               (Repeated_Individual_UTRAN_Priority_Parameters_t, u.Individual_UTRAN_Priority_TDD, Individual_UTRAN_Priority_TDD_t),
  M_UINT               (Repeated_Individual_UTRAN_Priority_Parameters_t,  UTRAN_PRIORITY,  3),
CSN_DESCR_END          (Repeated_Individual_UTRAN_Priority_Parameters_t)

static const
CSN_DESCR_BEGIN        (ThreeG_Individual_Priority_Parameters_Description_t)
  M_NEXT_EXIST         (ThreeG_Individual_Priority_Parameters_Description_t, Exist_DEFAULT_UTRAN_PRIORITY, 1),
  M_UINT               (ThreeG_Individual_Priority_Parameters_Description_t,  DEFAULT_UTRAN_PRIORITY,  3),
  M_REC_TARRAY         (ThreeG_Individual_Priority_Parameters_Description_t, Repeated_Individual_UTRAN_Priority_Parameters, Repeated_Individual_UTRAN_Priority_Parameters_t, Repeated_Individual_UTRAN_Priority_Parameters_Count),
CSN_DESCR_END          (ThreeG_Individual_Priority_Parameters_Description_t)

static const
CSN_DESCR_BEGIN        (Repeated_Individual_EUTRAN_Priority_Parameters_t)
  M_REC_ARRAY          (Repeated_Individual_EUTRAN_Priority_Parameters_t, EARFCN, Count, 16),
  M_UINT               (Repeated_Individual_EUTRAN_Priority_Parameters_t,  EUTRAN_PRIORITY,  3),
CSN_DESCR_END          (Repeated_Individual_EUTRAN_Priority_Parameters_t)

static const
CSN_DESCR_BEGIN        (EUTRAN_Individual_Priority_Parameters_Description_t)
  M_NEXT_EXIST         (EUTRAN_Individual_Priority_Parameters_Description_t, Exist_DEFAULT_EUTRAN_PRIORITY, 1),
  M_UINT               (EUTRAN_Individual_Priority_Parameters_Description_t,  DEFAULT_EUTRAN_PRIORITY,  3),
  M_REC_TARRAY         (EUTRAN_Individual_Priority_Parameters_Description_t, Repeated_Individual_EUTRAN_Priority_Parameters, Repeated_Individual_EUTRAN_Priority_Parameters_t, Count),
CSN_DESCR_END          (EUTRAN_Individual_Priority_Parameters_Description_t)

static const
CSN_DESCR_BEGIN        (Provide_Individual_Priorities_t)
  M_UINT               (Provide_Individual_Priorities_t,  GERAN_PRIORITY,  3),
  M_NEXT_EXIST         (Provide_Individual_Priorities_t, Exist_3G_Individual_Priority_Parameters_Description, 1),
  M_TYPE               (Provide_Individual_Priorities_t, ThreeG_Individual_Priority_Parameters_Description, ThreeG_Individual_Priority_Parameters_Description_t),
  M_NEXT_EXIST         (Provide_Individual_Priorities_t, Exist_EUTRAN_Individual_Priority_Parameters_Description, 1),
  M_TYPE               (Provide_Individual_Priorities_t, EUTRAN_Individual_Priority_Parameters_Description, EUTRAN_Individual_Priority_Parameters_Description_t),
  M_NEXT_EXIST         (Provide_Individual_Priorities_t, Exist_T3230_timeout_value, 1),
  M_UINT               (Provide_Individual_Priorities_t,  T3230_timeout_value,  3),
CSN_DESCR_END          (Provide_Individual_Priorities_t)

static const
CSN_DESCR_BEGIN        (Individual_Priorities_t)
  M_UNION              (Individual_Priorities_t, 2),
  M_TYPE               (Individual_Priorities_t, u.Delete_All_Stored_Individual_Priorities, Delete_All_Stored_Individual_Priorities_t),
  M_TYPE               (Individual_Priorities_t, u.Provide_Individual_Priorities, Provide_Individual_Priorities_t),
CSN_DESCR_END          (Individual_Priorities_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR9_t)
  M_NEXT_EXIST         (PMO_AdditionsR9_t, existEnhanced_Cell_Reselection_Parameters_Description, 1),
  M_TYPE               (PMO_AdditionsR9_t, Enhanced_Cell_Reselection_Parameters_Description, Enh_Cell_Reselect_Param_Desp_t),
  M_NEXT_EXIST         (PMO_AdditionsR9_t, existCSG_Cells_Reporting_Description, 1),
  M_TYPE               (PMO_AdditionsR9_t, CSG_Cells_Reporting_Description, CSG_Cells_Reporting_Desp_t),
CSN_DESCR_END          (PMO_AdditionsR9_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR8_t)
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existBA_IND_3G_PMO_IND, 2),
  M_UINT               (PMO_AdditionsR8_t, BA_IND_3G, 1),
  M_UINT               (PMO_AdditionsR8_t, PMO_IND, 1),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existPriorityAndEUTRAN_ParametersDescription_PMO, 1),
  M_TYPE               (PMO_AdditionsR8_t, PriorityAndEUTRAN_ParametersDescription_PMO, PriorityAndEUTRAN_ParametersDescription_PMO_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existIndividualPriorities_PMO, 1),
  M_TYPE               (PMO_AdditionsR8_t, IndividualPriorities_PMO, Individual_Priorities_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existThreeG_CSG_Description, 1),
  M_TYPE               (PMO_AdditionsR8_t, ThreeG_CSG_Description_PMO, ThreeG_CSG_Description_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existEUTRAN_CSG_Description, 1),
  M_TYPE               (PMO_AdditionsR8_t, EUTRAN_CSG_Description_PMO, EUTRAN_CSG_Description_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existMeasurement_Control_Parameters_Description, 1),
  M_TYPE               (PMO_AdditionsR8_t, Measurement_Control_Parameters_Description_PMO, Meas_Ctrl_Param_Desp_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR8_t, existAdditionsR9, 1),
  M_TYPE               (PMO_AdditionsR8_t, AdditionsR9, PMO_AdditionsR9_t),
CSN_DESCR_END          (PMO_AdditionsR8_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR7_t)
  M_NEXT_EXIST         (PMO_AdditionsR7_t, existREPORTING_OFFSET_THRESHOLD_700, 2),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_OFFSET_700,  3),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_THRESHOLD_700,  3),

  M_NEXT_EXIST         (PMO_AdditionsR7_t, existREPORTING_OFFSET_THRESHOLD_810, 2),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_OFFSET_810,  3),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_THRESHOLD_810,  3),

  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR7_t, existAdditionsR8, 1),
  M_TYPE               (PMO_AdditionsR7_t, additionsR8, PMO_AdditionsR8_t),
CSN_DESCR_END          (PMO_AdditionsR7_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR6_t)
  M_UINT               (PMO_AdditionsR6_t,  CCN_ACTIVE_3G,  1),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR6_t, existAdditionsR7, 1),
  M_TYPE               (PMO_AdditionsR6_t, additionsR7, PMO_AdditionsR7_t),
CSN_DESCR_END          (PMO_AdditionsR6_t)

static const
CSN_DESCR_BEGIN(PCCO_AdditionsR6_t)
  M_UINT       (PCCO_AdditionsR6_t,  CCN_ACTIVE_3G,  1),
CSN_DESCR_END  (PCCO_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR5_t)
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existGRNTI_Extension, 1),
  M_UINT               (PMO_AdditionsR5_t,  GRNTI,  4),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, exist_lu_ModeNeighbourCellParams, 1),
  M_REC_TARRAY         (PMO_AdditionsR5_t, lu_ModeNeighbourCellParams, lu_ModeNeighbourCellParams_t, count_lu_ModeNeighbourCellParams),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existNC_lu_ModeOnlyCapableCellList, 1),
  M_TYPE               (PMO_AdditionsR5_t, NC_lu_ModeOnlyCapableCellList, NC_lu_ModeOnlyCapableCellList_t),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existGPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE               (PMO_AdditionsR5_t, GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR5_t, existAdditionsR6, 1),
  M_TYPE               (PMO_AdditionsR5_t, additionsR6, PMO_AdditionsR6_t),
CSN_DESCR_END  (PMO_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR5_t)
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existGRNTI_Extension, 1),
  M_UINT               (PCCO_AdditionsR5_t,  GRNTI,  4),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, exist_lu_ModeNeighbourCellParams, 1),
  M_REC_TARRAY         (PCCO_AdditionsR5_t, lu_ModeNeighbourCellParams, lu_ModeNeighbourCellParams_t, count_lu_ModeNeighbourCellParams),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existNC_lu_ModeOnlyCapableCellList, 1),
  M_TYPE               (PCCO_AdditionsR5_t, NC_lu_ModeOnlyCapableCellList, NC_lu_ModeOnlyCapableCellList_t),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existGPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE               (PCCO_AdditionsR5_t, GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR5_t, existAdditionsR6, 1),
  M_TYPE               (PCCO_AdditionsR5_t, additionsR6, PCCO_AdditionsR6_t),
CSN_DESCR_END  (PCCO_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR4_t)
  M_UINT               (PMO_AdditionsR4_t,  CCN_ACTIVE,  1),
  M_NEXT_EXIST         (PMO_AdditionsR4_t, Exist_CCN_Support_Description_ID, 1),
  M_TYPE               (PMO_AdditionsR4_t, CCN_Support_Description, CCN_Support_Description_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR4_t, Exist_AdditionsR5, 1),
  M_TYPE               (PMO_AdditionsR4_t, AdditionsR5, PMO_AdditionsR5_t),
CSN_DESCR_END          (PMO_AdditionsR4_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR99_t)
  M_NEXT_EXIST         (PMO_AdditionsR99_t, Exist_ENH_Measurement_Parameters, 1),
  M_TYPE               (PMO_AdditionsR99_t, ENH_Measurement_Parameters, ENH_Measurement_Parameters_PMO_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR99_t, Exist_AdditionsR4, 1),
  M_TYPE               (PMO_AdditionsR99_t, AdditionsR4, PMO_AdditionsR4_t),
CSN_DESCR_END          (PMO_AdditionsR99_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR4_t)
  M_UINT               (PCCO_AdditionsR4_t,  CCN_ACTIVE,  1),
  M_NEXT_EXIST         (PCCO_AdditionsR4_t, Exist_Container_ID, 1),
  M_UINT               (PCCO_AdditionsR4_t,  CONTAINER_ID,  2),
  M_NEXT_EXIST         (PCCO_AdditionsR4_t, Exist_CCN_Support_Description_ID, 1),
  M_TYPE               (PCCO_AdditionsR4_t, CCN_Support_Description, CCN_Support_Description_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR4_t, Exist_AdditionsR5, 1),
  M_TYPE               (PCCO_AdditionsR4_t, AdditionsR5, PCCO_AdditionsR5_t),
CSN_DESCR_END  (PCCO_AdditionsR4_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR99_t)
  M_TYPE               (PCCO_AdditionsR99_t, ENH_Measurement_Parameters, ENH_Measurement_Parameters_PCCO_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR99_t, Exist_AdditionsR4, 1),
  M_TYPE               (PCCO_AdditionsR99_t, AdditionsR4, PCCO_AdditionsR4_t),
CSN_DESCR_END          (PCCO_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(LSA_ID_Info_Element_t)
  M_UNION      (LSA_ID_Info_Element_t, 2),
  M_UINT       (LSA_ID_Info_Element_t,  u.LSA_ID,  24),
  M_UINT       (LSA_ID_Info_Element_t,  u.ShortLSA_ID,  10),
CSN_DESCR_END  (LSA_ID_Info_Element_t)

static const
CSN_DESCR_BEGIN(LSA_ID_Info_t)
  M_REC_TARRAY (LSA_ID_Info_t, LSA_ID_Info_Elements, LSA_ID_Info_Element_t, Count_LSA_ID_Info_Element),
CSN_DESCR_END  (LSA_ID_Info_t)

static const
CSN_DESCR_BEGIN(LSA_Parameters_t)
  M_UINT       (LSA_Parameters_t,  NR_OF_FREQ_OR_CELLS,  5),
  M_VAR_TARRAY (LSA_Parameters_t, LSA_ID_Info, LSA_ID_Info_t, NR_OF_FREQ_OR_CELLS),
CSN_DESCR_END  (LSA_Parameters_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR98_t)
  M_NEXT_EXIST         (PMO_AdditionsR98_t, Exist_LSA_Parameters, 1),
  M_TYPE               (PMO_AdditionsR98_t, LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR98_t, Exist_AdditionsR99, 1),
  M_TYPE               (PMO_AdditionsR98_t, AdditionsR99, PMO_AdditionsR99_t),
CSN_DESCR_END          (PMO_AdditionsR98_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR98_t)
  M_NEXT_EXIST         (PCCO_AdditionsR98_t, Exist_LSA_Parameters, 1),
  M_TYPE               (PCCO_AdditionsR98_t, LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR98_t, Exist_AdditionsR99, 1),
  M_TYPE               (PCCO_AdditionsR98_t, AdditionsR99, PCCO_AdditionsR99_t),
CSN_DESCR_END          (PCCO_AdditionsR98_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_GSM_t)
  M_UINT               (Target_Cell_GSM_t,  IMMEDIATE_REL,  1),
  M_UINT               (Target_Cell_GSM_t,  ARFCN,  10),
  M_UINT               (Target_Cell_GSM_t,  BSIC,  6),
  M_TYPE               (Target_Cell_GSM_t, NC_Measurement_Parameters, NC_Measurement_Parameters_with_Frequency_List_t),
  M_NEXT_EXIST_OR_NULL (Target_Cell_GSM_t, Exist_AdditionsR98, 1),
  M_TYPE               (Target_Cell_GSM_t, AdditionsR98, PCCO_AdditionsR98_t),
CSN_DESCR_END          (Target_Cell_GSM_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_3G_AdditionsR8_t)
  M_NEXT_EXIST         (Target_Cell_3G_AdditionsR8_t, Exist_EUTRAN_Target_Cell, 1),
  M_TYPE               (Target_Cell_3G_AdditionsR8_t, EUTRAN_Target_Cell, EUTRAN_Target_Cell_t),
  M_NEXT_EXIST         (Target_Cell_3G_AdditionsR8_t, Exist_Individual_Priorities, 1),
  M_TYPE               (Target_Cell_3G_AdditionsR8_t, Individual_Priorities, Individual_Priorities_t),
CSN_DESCR_END          (Target_Cell_3G_AdditionsR8_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_3G_AdditionsR5_t)
  M_NEXT_EXIST         (Target_Cell_3G_AdditionsR5_t, Exist_G_RNTI_Extention, 1),
  M_UINT               (Target_Cell_3G_AdditionsR5_t,  G_RNTI_Extention,  4),
  M_NEXT_EXIST_OR_NULL (Target_Cell_3G_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE               (Target_Cell_3G_AdditionsR5_t, AdditionsR8, Target_Cell_3G_AdditionsR8_t),
CSN_DESCR_END          (Target_Cell_3G_AdditionsR5_t)

static const
CSN_DESCR_BEGIN(Target_Cell_3G_t)
  /* 00 -- Message escape */
  M_FIXED      (Target_Cell_3G_t, 2, 0x00),
  M_UINT       (Target_Cell_3G_t,  IMMEDIATE_REL,  1),
  M_NEXT_EXIST (Target_Cell_3G_t, Exist_FDD_Description, 1),
  M_TYPE       (Target_Cell_3G_t, FDD_Target_Cell, FDD_Target_Cell_t),
  M_NEXT_EXIST (Target_Cell_3G_t, Exist_TDD_Description, 1),
  M_TYPE       (Target_Cell_3G_t, TDD_Target_Cell, TDD_Target_Cell_t),
  M_NEXT_EXIST_OR_NULL (Target_Cell_3G_t, Exist_AdditionsR5, 1),
  M_TYPE       (Target_Cell_3G_t, AdditionsR5, Target_Cell_3G_AdditionsR5_t),
CSN_DESCR_END  (Target_Cell_3G_t)

static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Order_t)
  M_UINT       (Packet_Cell_Change_Order_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Cell_Change_Order_t,  PAGE_MODE,  2),

  M_TYPE       (Packet_Cell_Change_Order_t, ID, PacketCellChangeOrderID_t),

  M_UNION      (Packet_Cell_Change_Order_t, 2),
  M_TYPE       (Packet_Cell_Change_Order_t, u.Target_Cell_GSM, Target_Cell_GSM_t),
  M_TYPE       (Packet_Cell_Change_Order_t, u.Target_Cell_3G, Target_Cell_3G_t),

  M_PADDING_BITS(Packet_Cell_Change_Order_t),
CSN_DESCR_END  (Packet_Cell_Change_Order_t)

/*< Packet (Enhanced) Measurement Report message contents > */
static const
CSN_DESCR_BEGIN(BA_USED_t)
  M_UINT       (BA_USED_t,  BA_USED,  1),
  M_UINT       (BA_USED_t,  BA_USED_3G,  1),
CSN_DESCR_END  (BA_USED_t)

static const
CSN_DESCR_BEGIN(Serving_Cell_Data_t)
  M_UINT       (Serving_Cell_Data_t,  RXLEV_SERVING_CELL,  6),
  M_FIXED      (Serving_Cell_Data_t, 1, 0),
CSN_DESCR_END  (Serving_Cell_Data_t)

static const
CSN_DESCR_BEGIN(NC_Measurements_t)
  M_UINT       (NC_Measurements_t,  FREQUENCY_N,  6),

  M_NEXT_EXIST (NC_Measurements_t, Exist_BSIC_N, 1),
  M_UINT       (NC_Measurements_t,  BSIC_N,  6),
  M_UINT       (NC_Measurements_t,  RXLEV_N,  6),
CSN_DESCR_END  (NC_Measurements_t)

static const
CSN_DESCR_BEGIN(RepeatedInvalid_BSIC_Info_t)
  M_UINT       (RepeatedInvalid_BSIC_Info_t,  BCCH_FREQ_N,  5),
  M_UINT       (RepeatedInvalid_BSIC_Info_t,  BSIC_N,  6),
  M_UINT       (RepeatedInvalid_BSIC_Info_t,  RXLEV_N,  6),
CSN_DESCR_END  (RepeatedInvalid_BSIC_Info_t)

static const
CSN_DESCR_BEGIN(REPORTING_QUANTITY_Instance_t)
  M_NEXT_EXIST (REPORTING_QUANTITY_Instance_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT       (REPORTING_QUANTITY_Instance_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END  (REPORTING_QUANTITY_Instance_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Report_t)
  M_UINT       (NC_Measurement_Report_t,  NC_MODE,  1),
  M_TYPE       (NC_Measurement_Report_t, Serving_Cell_Data, Serving_Cell_Data_t),
  M_UINT       (NC_Measurement_Report_t,  NUMBER_OF_NC_MEASUREMENTS,  3),
  M_VAR_TARRAY (NC_Measurement_Report_t, NC_Measurements, NC_Measurements_t, NUMBER_OF_NC_MEASUREMENTS),
CSN_DESCR_END  (NC_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(ENH_NC_Measurement_Report_t)
  M_UINT       (ENH_NC_Measurement_Report_t,  NC_MODE,  1),
  M_UNION      (ENH_NC_Measurement_Report_t, 2),
  M_TYPE       (ENH_NC_Measurement_Report_t, u.BA_USED, BA_USED_t),
  M_UINT       (ENH_NC_Measurement_Report_t,  u.PSI3_CHANGE_MARK,  2),
  M_UINT       (ENH_NC_Measurement_Report_t,  PMO_USED,  1),
  M_UINT       (ENH_NC_Measurement_Report_t,  BSIC_Seen,  1),
  M_UINT       (ENH_NC_Measurement_Report_t,  SCALE,  1),
  M_NEXT_EXIST (ENH_NC_Measurement_Report_t, Exist_Serving_Cell_Data, 1),
  M_TYPE       (ENH_NC_Measurement_Report_t, Serving_Cell_Data, Serving_Cell_Data_t),
  M_REC_TARRAY (ENH_NC_Measurement_Report_t, RepeatedInvalid_BSIC_Info, RepeatedInvalid_BSIC_Info_t, Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST (ENH_NC_Measurement_Report_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY (ENH_NC_Measurement_Report_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END  (ENH_NC_Measurement_Report_t)


static const
CSN_DESCR_BEGIN(EXT_Measurement_Report_t)
  M_UINT       (EXT_Measurement_Report_t,  EXT_REPORTING_TYPE,  2),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Exist_I_LEVEL, 1),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[0].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[0].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[1].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[1].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[2].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[2].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[3].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[3].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[4].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[4].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[5].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[5].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[6].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[6].I_LEVEL,  6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[7].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[7].I_LEVEL,  6),

  M_UINT       (EXT_Measurement_Report_t,  NUMBER_OF_EXT_MEASUREMENTS,  5),
  M_VAR_TARRAY (EXT_Measurement_Report_t, EXT_Measurements, NC_Measurements_t, NUMBER_OF_EXT_MEASUREMENTS),
CSN_DESCR_END  (EXT_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (Measurements_3G_t)
  M_UINT          (Measurements_3G_t,  CELL_LIST_INDEX_3G,  7),
  M_UINT          (Measurements_3G_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END   (Measurements_3G_t)

static const
CSN_DESCR_BEGIN (EUTRAN_Measurement_Report_Body_t)
  M_UINT        (EUTRAN_Measurement_Report_Body_t,  EUTRAN_FREQUENCY_INDEX,  3),
  M_UINT        (EUTRAN_Measurement_Report_Body_t,  CELL_IDENTITY,  9),
  M_UINT        (EUTRAN_Measurement_Report_Body_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END   (EUTRAN_Measurement_Report_Body_t)

static const
CSN_DESCR_BEGIN (EUTRAN_Measurement_Report_t)
  M_UINT_OFFSET (EUTRAN_Measurement_Report_t, N_EUTRAN,  2, 1),
  M_VAR_TARRAY  (EUTRAN_Measurement_Report_t, Report, EUTRAN_Measurement_Report_Body_t, N_EUTRAN),
CSN_DESCR_END   (EUTRAN_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(UTRAN_CSG_Measurement_Report_t)
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  UTRAN_CGI,  28),
  M_NEXT_EXIST (UTRAN_CSG_Measurement_Report_t, Exist_PLMN_ID, 1),
  M_TYPE       (UTRAN_CSG_Measurement_Report_t,  Plmn_ID, PLMN_t),
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  CSG_ID,  27),
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  Access_Mode, 1),
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END  (UTRAN_CSG_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Measurement_Report_t)
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, EUTRAN_CGI,  28),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, Tracking_Area_Code,  16),
  M_NEXT_EXIST (EUTRAN_CSG_Measurement_Report_t, Exist_PLMN_ID, 1),
  M_TYPE       (EUTRAN_CSG_Measurement_Report_t,  Plmn_ID, PLMN_t),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, CSG_ID,  27),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, Access_Mode, 1),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, REPORTING_QUANTITY,  6),
CSN_DESCR_END  (EUTRAN_CSG_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR9_t)
  M_NEXT_EXIST  (PMR_AdditionsR9_t, Exist_UTRAN_CSG_Meas_Rpt, 1),
  M_TYPE        (PMR_AdditionsR9_t, UTRAN_CSG_Meas_Rpt, UTRAN_CSG_Measurement_Report_t),
  M_NEXT_EXIST  (PMR_AdditionsR9_t, Exist_EUTRAN_CSG_Meas_Rpt, 1),
  M_TYPE        (PMR_AdditionsR9_t, EUTRAN_CSG_Meas_Rpt, EUTRAN_CSG_Measurement_Report_t),
CSN_DESCR_END   (PMR_AdditionsR9_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR8_t)
  M_NEXT_EXIST  (PMR_AdditionsR8_t, Exist_EUTRAN_Meas_Rpt, 1),
  M_TYPE        (PMR_AdditionsR8_t, EUTRAN_Meas_Rpt, EUTRAN_Measurement_Report_t),
  M_NEXT_EXIST_OR_NULL(PMR_AdditionsR8_t, Exist_AdditionsR9, 1),
  M_TYPE        (PMR_AdditionsR8_t, AdditionsR9, PMR_AdditionsR9_t),
CSN_DESCR_END   (PMR_AdditionsR8_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR5_t)
  M_NEXT_EXIST  (PMR_AdditionsR5_t, Exist_GRNTI, 3),
  M_UINT        (PMR_AdditionsR5_t,  GRNTI,  4),
  M_NEXT_EXIST_OR_NULL (PMR_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE        (PMR_AdditionsR5_t, AdditionsR8, PMR_AdditionsR8_t),
CSN_DESCR_END   (PMR_AdditionsR5_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR99_t)
  M_NEXT_EXIST  (PMR_AdditionsR99_t, Exist_Info3G, 4),
  M_UNION       (PMR_AdditionsR99_t, 2),
  M_TYPE        (PMR_AdditionsR99_t, u.BA_USED, BA_USED_t),
  M_UINT        (PMR_AdditionsR99_t,  u.PSI3_CHANGE_MARK,  2),
  M_UINT        (PMR_AdditionsR99_t,  PMO_USED,  1),

  M_NEXT_EXIST  (PMR_AdditionsR99_t, Exist_MeasurementReport3G, 2),
  M_UINT_OFFSET (PMR_AdditionsR99_t, N_3G, 3, 1),   /* offset 1 */
  M_VAR_TARRAY_OFFSET  (PMR_AdditionsR99_t, Measurements_3G, Measurements_3G_t, N_3G),

  M_NEXT_EXIST_OR_NULL (PMR_AdditionsR99_t, Exist_AdditionsR5, 1),
  M_TYPE        (PMR_AdditionsR99_t, AdditionsR5, PMR_AdditionsR5_t),
CSN_DESCR_END   (PMR_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(EMR_ServingCell_t)
  /*CSN_MEMBER_BIT (EMR_ServingCell_t, DTX_USED),*/
  M_UINT         (EMR_ServingCell_t,  DTX_USED, 1),
  M_UINT         (EMR_ServingCell_t,  RXLEV_VAL,        6),
  M_UINT         (EMR_ServingCell_t,  RX_QUAL_FULL,     3),
  M_UINT         (EMR_ServingCell_t,  MEAN_BEP,         5),
  M_UINT         (EMR_ServingCell_t,  CV_BEP,           3),
  M_UINT         (EMR_ServingCell_t,  NBR_RCVD_BLOCKS,  5),
CSN_DESCR_END(EMR_ServingCell_t)

static const
CSN_DESCR_BEGIN   (EnhancedMeasurementReport_t)
  M_UINT          (EnhancedMeasurementReport_t,  RR_Short_PD,  1),
  M_UINT          (EnhancedMeasurementReport_t,  MESSAGE_TYPE,  5),
  M_UINT          (EnhancedMeasurementReport_t,  ShortLayer2_Header,  2),
  M_TYPE          (EnhancedMeasurementReport_t, BA_USED, BA_USED_t),
  M_UINT          (EnhancedMeasurementReport_t,  BSIC_Seen,  1),
  M_UINT          (EnhancedMeasurementReport_t,  SCALE,  1),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE          (EnhancedMeasurementReport_t, ServingCellData, EMR_ServingCell_t),
  M_REC_TARRAY    (EnhancedMeasurementReport_t, RepeatedInvalid_BSIC_Info, RepeatedInvalid_BSIC_Info_t,
                    Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY    (EnhancedMeasurementReport_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END     (EnhancedMeasurementReport_t)

static const
CSN_DESCR_BEGIN       (Packet_Measurement_Report_t)
  /* Mac header */
  M_UINT              (Packet_Measurement_Report_t,  PayloadType,  2),
  M_UINT              (Packet_Measurement_Report_t,  spare,  5),
  M_UINT              (Packet_Measurement_Report_t,  R,  1),
  M_UINT              (Packet_Measurement_Report_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_UINT              (Packet_Measurement_Report_t,  TLLI,  32),

  M_NEXT_EXIST        (Packet_Measurement_Report_t, Exist_PSI5_CHANGE_MARK, 1),
  M_UINT              (Packet_Measurement_Report_t,  PSI5_CHANGE_MARK,  2),

  M_UNION             (Packet_Measurement_Report_t, 2),
  M_TYPE              (Packet_Measurement_Report_t, u.NC_Measurement_Report, NC_Measurement_Report_t),
  M_TYPE              (Packet_Measurement_Report_t, u.EXT_Measurement_Report, EXT_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Measurement_Report_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Measurement_Report_t, AdditionsR99, PMR_AdditionsR99_t),

  M_PADDING_BITS      (Packet_Measurement_Report_t),
CSN_DESCR_END         (Packet_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (PEMR_AdditionsR9_t)
  M_NEXT_EXIST  (PEMR_AdditionsR9_t, Exist_UTRAN_CSG_Target_Cell, 1),
  M_TYPE        (PEMR_AdditionsR9_t, UTRAN_CSG_Target_Cell, UTRAN_CSG_Target_Cell_t),
  M_NEXT_EXIST  (PEMR_AdditionsR9_t, Exist_EUTRAN_CSG_Target_Cell, 1),
  M_TYPE        (PEMR_AdditionsR9_t, EUTRAN_CSG_Target_Cell, EUTRAN_CSG_Target_Cell_t),
CSN_DESCR_END   (PEMR_AdditionsR9_t)

static const
CSN_DESCR_BEGIN (Bitmap_Report_Quantity_t)
  M_NEXT_EXIST  (Bitmap_Report_Quantity_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT        (Bitmap_Report_Quantity_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END   (Bitmap_Report_Quantity_t)

static const
CSN_DESCR_BEGIN (PEMR_AdditionsR8_t)
  M_UINT_OFFSET (PEMR_AdditionsR8_t, BITMAP_LENGTH,  7, 1),
  M_VAR_TARRAY  (PEMR_AdditionsR8_t, Bitmap_Report_Quantity, Bitmap_Report_Quantity_t, BITMAP_LENGTH),
  M_NEXT_EXIST  (PEMR_AdditionsR8_t, Exist_EUTRAN_Meas_Rpt, 1),
  M_TYPE        (PEMR_AdditionsR8_t, EUTRAN_Meas_Rpt, EUTRAN_Measurement_Report_t),
  M_NEXT_EXIST_OR_NULL(PEMR_AdditionsR8_t, Exist_AdditionsR9, 1),
  M_TYPE        (PEMR_AdditionsR8_t, AdditionsR9, PEMR_AdditionsR9_t),
CSN_DESCR_END   (PEMR_AdditionsR8_t)

static const
CSN_DESCR_BEGIN (PEMR_AdditionsR5_t)
  M_NEXT_EXIST  (PEMR_AdditionsR5_t, Exist_GRNTI_Ext, 1),
  M_UINT        (PEMR_AdditionsR5_t,  GRNTI_Ext,  4),
  M_NEXT_EXIST_OR_NULL(PEMR_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE        (PEMR_AdditionsR5_t, AdditionsR8, PEMR_AdditionsR8_t),
CSN_DESCR_END   (PEMR_AdditionsR5_t)


static const
CSN_DESCR_BEGIN       (Packet_Enh_Measurement_Report_t)
  /* Mac header */
  M_UINT              (Packet_Enh_Measurement_Report_t,  PayloadType,  2),
  M_UINT              (Packet_Enh_Measurement_Report_t,  spare,  5),
  M_UINT              (Packet_Enh_Measurement_Report_t,  R,  1),
  M_UINT              (Packet_Enh_Measurement_Report_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_UINT              (Packet_Enh_Measurement_Report_t,  TLLI,  32),

  M_TYPE              (Packet_Enh_Measurement_Report_t, Measurements, ENH_NC_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Enh_Measurement_Report_t, Exist_AdditionsR5, 1),
  M_TYPE              (Packet_Enh_Measurement_Report_t, AdditionsR5, PEMR_AdditionsR5_t),

  M_PADDING_BITS(Packet_Enh_Measurement_Report_t),
CSN_DESCR_END         (Packet_Enh_Measurement_Report_t)

/*< Packet Measurement Order message contents >*/
static const
CSN_DESCR_BEGIN(EXT_Frequency_List_t)
  M_UINT       (EXT_Frequency_List_t,  START_FREQUENCY,  10),
  M_UINT       (EXT_Frequency_List_t,  NR_OF_FREQUENCIES,  5),
  M_UINT       (EXT_Frequency_List_t,  FREQ_DIFF_LENGTH,  3),

/* TBD: Count_FREQUENCY_DIFF
 * guint8 FREQUENCY_DIFF[31];
 * bit (FREQ_DIFF_LENGTH) * NR_OF_FREQUENCIES --> MAX is bit(7) * 31
 */
CSN_DESCR_END  (EXT_Frequency_List_t)

static const
CSN_DESCR_BEGIN        (Packet_Measurement_Order_t)
  M_UINT               (Packet_Measurement_Order_t,  MESSAGE_TYPE,  6),
  M_UINT               (Packet_Measurement_Order_t,  PAGE_MODE,  2),

  M_TYPE               (Packet_Measurement_Order_t, ID, PacketDownlinkID_t), /* reuse the PDA ID type */

  M_UINT               (Packet_Measurement_Order_t,  PMO_INDEX,  3),
  M_UINT               (Packet_Measurement_Order_t,  PMO_COUNT,  3),

  M_NEXT_EXIST         (Packet_Measurement_Order_t, Exist_NC_Measurement_Parameters, 1),
  M_TYPE               (Packet_Measurement_Order_t, NC_Measurement_Parameters, NC_Measurement_Parameters_with_Frequency_List_t),

  M_NEXT_EXIST         (Packet_Measurement_Order_t, Exist_EXT_Measurement_Parameters, 1),
  M_FIXED              (Packet_Measurement_Order_t, 2, 0x0),    /* EXT_Measurement_Parameters not handled */

  M_NEXT_EXIST_OR_NULL (Packet_Measurement_Order_t, Exist_AdditionsR98, 1),
  M_TYPE               (Packet_Measurement_Order_t, AdditionsR98, PMO_AdditionsR98_t),

  M_PADDING_BITS       (Packet_Measurement_Order_t),
CSN_DESCR_END          (Packet_Measurement_Order_t)

static const
CSN_DESCR_BEGIN(CCN_Measurement_Report_t)
  M_UINT       (CCN_Measurement_Report_t,  RXLEV_SERVING_CELL,  6),
  M_FIXED      (CCN_Measurement_Report_t, 1, 0),
  M_UINT       (CCN_Measurement_Report_t,  NUMBER_OF_NC_MEASUREMENTS,  3),
  M_VAR_TARRAY (CCN_Measurement_Report_t, NC_Measurements, NC_Measurements_t, NUMBER_OF_NC_MEASUREMENTS),
CSN_DESCR_END  (CCN_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(Target_Cell_GSM_Notif_t)
  M_UINT       (Target_Cell_GSM_Notif_t,  ARFCN,  10),
  M_UINT       (Target_Cell_GSM_Notif_t,  BSIC,  6),
CSN_DESCR_END  (Target_Cell_GSM_Notif_t)

static const
CSN_DESCR_BEGIN(FDD_Target_Cell_Notif_t)
  M_UINT       (FDD_Target_Cell_Notif_t,  FDD_ARFCN,  14),
  M_NEXT_EXIST (FDD_Target_Cell_Notif_t, Exist_Bandwith_FDD, 1),
  M_UINT       (FDD_Target_Cell_Notif_t,  BANDWITH_FDD,  3),
  M_UINT       (FDD_Target_Cell_Notif_t,  SCRAMBLING_CODE,  9),
CSN_DESCR_END  (FDD_Target_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(TDD_Target_Cell_Notif_t)
  M_UINT       (TDD_Target_Cell_Notif_t,  TDD_ARFCN,  14),
  M_NEXT_EXIST (TDD_Target_Cell_Notif_t, Exist_Bandwith_TDD, 1),
  M_UINT       (TDD_Target_Cell_Notif_t,  BANDWITH_TDD,  3),
  M_UINT       (TDD_Target_Cell_Notif_t,  CELL_PARAMETER,  7),
  M_UINT       (TDD_Target_Cell_Notif_t,  Sync_Case_TSTD,  1),
CSN_DESCR_END  (TDD_Target_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_3G_Notif_t)
  M_NEXT_EXIST (Target_Cell_3G_Notif_t, Exist_FDD_Description, 1),
  M_TYPE       (Target_Cell_3G_Notif_t, FDD_Target_Cell_Notif, FDD_Target_Cell_Notif_t),
  M_NEXT_EXIST (Target_Cell_3G_Notif_t, Exist_TDD_Description, 1),
  M_TYPE       (Target_Cell_3G_Notif_t, TDD_Target_Cell, TDD_Target_Cell_Notif_t),
  M_UINT       (Target_Cell_3G_Notif_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END  (Target_Cell_3G_Notif_t)

static const
CSN_DESCR_BEGIN(Target_EUTRAN_Cell_Notif_t)
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  EARFCN,  16),
  M_NEXT_EXIST (Target_EUTRAN_Cell_Notif_t, Exist_Measurement_Bandwidth, 1),
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  Measurement_Bandwidth,  3),
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  Physical_Layer_Cell_Identity,  9),
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  Reporting_Quantity,  6),
CSN_DESCR_END  (Target_EUTRAN_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(Eutran_Ccn_Measurement_Report_Cell_t)
  M_UINT       (Eutran_Ccn_Measurement_Report_Cell_t,  EUTRAN_FREQUENCY_INDEX,  3),
  M_UINT       (Eutran_Ccn_Measurement_Report_Cell_t,  CELL_IDENTITY,  9),
  M_UINT       (Eutran_Ccn_Measurement_Report_Cell_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END  (Eutran_Ccn_Measurement_Report_Cell_t)


static const
CSN_DESCR_BEGIN(Eutran_Ccn_Measurement_Report_t)
  M_UINT       (Eutran_Ccn_Measurement_Report_t,  ThreeG_BA_USED, 1),
  M_UINT_OFFSET(Eutran_Ccn_Measurement_Report_t,  N_EUTRAN,  2, 1),
  M_VAR_TARRAY (Eutran_Ccn_Measurement_Report_t,  Eutran_Ccn_Measurement_Report_Cell, Eutran_Ccn_Measurement_Report_Cell_t, N_EUTRAN),
CSN_DESCR_END  (Eutran_Ccn_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(Target_Cell_4G_Notif_t)
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_Arfcn, 2),
  M_UINT       (Target_Cell_4G_Notif_t,  Arfcn,  10),
  M_UINT       (Target_Cell_4G_Notif_t,  bsic,  6),
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_3G_Target_Cell, 1),
  M_TYPE       (Target_Cell_4G_Notif_t,  Target_Cell_3G_Notif, Target_Cell_3G_Notif_t),
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_Eutran_Target_Cell, 1),
  M_TYPE       (Target_Cell_4G_Notif_t,  Target_EUTRAN_Cell, Target_EUTRAN_Cell_Notif_t),
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_Eutran_Ccn_Measurement_Report, 1),
  M_TYPE       (Target_Cell_4G_Notif_t,  Eutran_Ccn_Measurement_Report, Eutran_Ccn_Measurement_Report_t),
CSN_DESCR_END  (Target_Cell_4G_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_CSG_Notif_t)
  M_FIXED      (Target_Cell_CSG_Notif_t, 1, 0x00),
  M_UNION      (Target_Cell_CSG_Notif_t, 2),
  M_TYPE       (Target_Cell_CSG_Notif_t, u.UTRAN_CSG_Measurement_Report, UTRAN_CSG_Measurement_Report_t),
  M_TYPE       (Target_Cell_CSG_Notif_t, u.EUTRAN_CSG_Measurement_Report, EUTRAN_CSG_Measurement_Report_t),
  M_NEXT_EXIST (Target_Cell_CSG_Notif_t, Exist_Eutran_Ccn_Measurement_Report, 1),
  M_TYPE       (Target_Cell_CSG_Notif_t,  Eutran_Ccn_Measurement_Report, Eutran_Ccn_Measurement_Report_t),
CSN_DESCR_END  (Target_Cell_CSG_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Other_RAT_2_Notif_t)
  /* 110 vs 1110 */
  M_UNION      (Target_Other_RAT_2_Notif_t, 2),
  M_TYPE       (Target_Other_RAT_2_Notif_t, u.Target_Cell_4G_Notif, Target_Cell_4G_Notif_t),
  M_TYPE       (Target_Other_RAT_2_Notif_t, u.Target_Cell_CSG_Notif, Target_Cell_CSG_Notif_t),
CSN_DESCR_END  (Target_Other_RAT_2_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Other_RAT_Notif_t)
  /* 10 vs 110 */
  M_UNION      (Target_Other_RAT_Notif_t, 2),
  M_TYPE       (Target_Other_RAT_Notif_t, u.Target_Cell_3G_Notif, Target_Cell_3G_Notif_t),
  M_TYPE       (Target_Other_RAT_Notif_t, u.Target_Other_RAT_2_Notif, Target_Other_RAT_2_Notif_t),
CSN_DESCR_END  (Target_Other_RAT_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_t)
  /* 0 vs 10 */
  M_UNION      (Target_Cell_t, 2),
  M_TYPE       (Target_Cell_t, u.Target_Cell_GSM_Notif, Target_Cell_GSM_Notif_t),
  M_TYPE       (Target_Cell_t, u.Target_Other_RAT_Notif, Target_Other_RAT_Notif_t),
CSN_DESCR_END  (Target_Cell_t)

static const
CSN_DESCR_BEGIN (PCCN_AdditionsR6_t)
  M_NEXT_EXIST  (PCCN_AdditionsR6_t, Exist_BA_USED_3G, 1),
  M_UINT        (PCCN_AdditionsR6_t,  BA_USED_3G,  1),

  M_UINT_OFFSET (PCCN_AdditionsR6_t, N_3G, 3, 1),   /* offset 1 */
  M_VAR_TARRAY_OFFSET (PCCN_AdditionsR6_t, Measurements_3G, Measurements_3G_t, N_3G),
CSN_DESCR_END   (PCCN_AdditionsR6_t)

/*< Packet Cell Change Notification message contents > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Notification_t)
  /* Mac header */
  M_UINT              (Packet_Cell_Change_Notification_t,  PayloadType,  2),
  M_UINT              (Packet_Cell_Change_Notification_t,  spare,  5),
  M_UINT              (Packet_Cell_Change_Notification_t,  R,  1),
  M_UINT              (Packet_Cell_Change_Notification_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_TYPE              (Packet_Cell_Change_Notification_t, Global_TFI, Global_TFI_t),
  M_TYPE              (Packet_Cell_Change_Notification_t, Target_Cell, Target_Cell_t),

  M_UNION             (Packet_Cell_Change_Notification_t, 2),
  M_UINT              (Packet_Cell_Change_Notification_t,  u.BA_IND,  1),
  M_UINT              (Packet_Cell_Change_Notification_t,  u.PSI3_CHANGE_MARK,  2),

  M_UINT              (Packet_Cell_Change_Notification_t,  PMO_USED,  1),
  M_UINT              (Packet_Cell_Change_Notification_t,  PCCN_SENDING,  1),
  M_TYPE              (Packet_Cell_Change_Notification_t, CCN_Measurement_Report, CCN_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Cell_Change_Notification_t, Exist_AdditionsR6, 1),
  M_TYPE              (Packet_Cell_Change_Notification_t, AdditionsR6, PCCN_AdditionsR6_t),

  M_PADDING_BITS(Packet_Cell_Change_Notification_t),
CSN_DESCR_END  (Packet_Cell_Change_Notification_t)

/*< Packet Cell Change Continue message contents > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Continue_t)
  M_UINT       (Packet_Cell_Change_Continue_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Cell_Change_Continue_t,  PAGE_MODE,  2),
  M_FIXED      (Packet_Cell_Change_Continue_t, 1, 0x00),
  M_TYPE       (Packet_Cell_Change_Continue_t, Global_TFI, Global_TFI_t),

  M_NEXT_EXIST (Packet_Cell_Change_Continue_t, Exist_ID, 3),
  M_UINT       (Packet_Cell_Change_Continue_t,  ARFCN, 10),
  M_UINT       (Packet_Cell_Change_Continue_t,  BSIC,  6),
  M_UINT       (Packet_Cell_Change_Continue_t,  CONTAINER_ID,  2),

  M_PADDING_BITS(Packet_Cell_Change_Continue_t),
CSN_DESCR_END  (Packet_Cell_Change_Continue_t)

/*< Packet Neighbour Cell Data message contents > */
static const
CSN_DESCR_BEGIN(PNCD_Container_With_ID_t)
  M_UINT       (PNCD_Container_With_ID_t,  ARFCN, 10),
  M_UINT       (PNCD_Container_With_ID_t,  BSIC,  6),
  M_UINT_ARRAY (PNCD_Container_With_ID_t, CONTAINER, 8, 17),/* 8*17 bits */
CSN_DESCR_END  (PNCD_Container_With_ID_t)

static const
CSN_DESCR_BEGIN(PNCD_Container_Without_ID_t)
  M_UINT_ARRAY (PNCD_Container_Without_ID_t, CONTAINER, 8, 19),/* 8*19 bits */
CSN_DESCR_END  (PNCD_Container_Without_ID_t)

static const
CSN_ChoiceElement_t PNCDContainer[] =
{
  {1, 0x0, 0, M_TYPE(PNCDContainer_t, u.PNCD_Container_Without_ID, PNCD_Container_Without_ID_t)},
  {1, 0x1, 0, M_TYPE(PNCDContainer_t, u.PNCD_Container_With_ID, PNCD_Container_With_ID_t)},
};

static const
CSN_DESCR_BEGIN(PNCDContainer_t)
  M_CHOICE     (PNCDContainer_t, UnionType, PNCDContainer, ElementsOf(PNCDContainer)),
CSN_DESCR_END  (PNCDContainer_t)

static const
CSN_DESCR_BEGIN(Packet_Neighbour_Cell_Data_t)
  M_UINT       (Packet_Neighbour_Cell_Data_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Neighbour_Cell_Data_t,  PAGE_MODE,  2),
  M_FIXED      (Packet_Neighbour_Cell_Data_t, 1, 0x00),
  M_TYPE       (Packet_Neighbour_Cell_Data_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Neighbour_Cell_Data_t,  CONTAINER_ID,  2),
  M_UINT       (Packet_Neighbour_Cell_Data_t,  spare,  1),
  M_UINT       (Packet_Neighbour_Cell_Data_t,  CONTAINER_INDEX,  5),

  M_TYPE       (Packet_Neighbour_Cell_Data_t, Container, PNCDContainer_t),
  M_PADDING_BITS(Packet_Neighbour_Cell_Data_t),
CSN_DESCR_END  (Packet_Neighbour_Cell_Data_t)

/*< Packet Serving Cell Data message contents > */
static const
CSN_DESCR_BEGIN(Packet_Serving_Cell_Data_t)
  M_UINT       (Packet_Serving_Cell_Data_t,  MESSAGE_TYPE,  6),
  M_UINT       (Packet_Serving_Cell_Data_t,  PAGE_MODE,  2),
  M_FIXED      (Packet_Serving_Cell_Data_t, 1, 0x00),
  M_TYPE       (Packet_Serving_Cell_Data_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Serving_Cell_Data_t,  spare,  4),
  M_UINT       (Packet_Serving_Cell_Data_t,  CONTAINER_INDEX,  5),
  M_UINT_ARRAY (Packet_Serving_Cell_Data_t, CONTAINER, 8, 19),/* 8*19 bits */
  M_PADDING_BITS(Packet_Serving_Cell_Data_t),
CSN_DESCR_END  (Packet_Serving_Cell_Data_t)


/* Enhanced Measurement Report */
static const
CSN_DESCR_BEGIN (ServingCellData_t)
  M_UINT        (ServingCellData_t,  RXLEV_SERVING_CELL,  6),
  M_FIXED       (ServingCellData_t, 1, 0),
CSN_DESCR_END   (ServingCellData_t)

static const
CSN_DESCR_BEGIN (Repeated_Invalid_BSIC_Info_t)
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  BCCH_FREQ_NCELL,  5),
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  BSIC,  6),
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  RXLEV_NCELL,  5),
CSN_DESCR_END   (Repeated_Invalid_BSIC_Info_t)

static const
CSN_DESCR_BEGIN (REPORTING_QUANTITY_t)
  M_NEXT_EXIST  (REPORTING_QUANTITY_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT        (REPORTING_QUANTITY_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END   (REPORTING_QUANTITY_t)


static const
CSN_DESCR_BEGIN (NC_MeasurementReport_t)
  M_UINT        (NC_MeasurementReport_t, NC_MODE, 1),
  M_UNION       (NC_MeasurementReport_t, 2),
  M_TYPE        (NC_MeasurementReport_t, u.BA_USED, BA_USED_t),
  M_UINT        (NC_MeasurementReport_t, u.PSI3_CHANGE_MARK,  2),
  M_UINT        (NC_MeasurementReport_t, PMO_USED, 1),
  M_UINT        (NC_MeasurementReport_t, SCALE, 1),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE        (NC_MeasurementReport_t, ServingCellData, ServingCellData_t),

  M_REC_TARRAY  (NC_MeasurementReport_t, Repeated_Invalid_BSIC_Info, Repeated_Invalid_BSIC_Info_t, Count_Repeated_Invalid_BSIC_Info),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_Repeated_REPORTING_QUANTITY, 1),
  M_VAR_TARRAY  (NC_MeasurementReport_t, Repeated_REPORTING_QUANTITY, REPORTING_QUANTITY_t, Count_Repeated_Reporting_Quantity),
CSN_DESCR_END   (NC_MeasurementReport_t)



/*< Packet Handover Command message content > */
static const
CSN_DESCR_BEGIN (GlobalTimeslotDescription_t)
  M_UNION       (GlobalTimeslotDescription_t, 2),
  M_UINT        (GlobalTimeslotDescription_t,  u.MS_TimeslotAllocation,  8),
  M_TYPE        (GlobalTimeslotDescription_t, u.Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END   (GlobalTimeslotDescription_t)

static const
CSN_DESCR_BEGIN (PHO_DownlinkAssignment_t)
  M_UINT        (PHO_DownlinkAssignment_t,  TimeslotAllocation,  8),
  M_UINT        (PHO_DownlinkAssignment_t,  PFI,  7),
  M_UINT        (PHO_DownlinkAssignment_t,  RLC_Mode, 1),
  M_UINT        (PHO_DownlinkAssignment_t,  TFI_Assignment,  5),
  M_UINT        (PHO_DownlinkAssignment_t,  ControlACK, 1),

  M_NEXT_EXIST  (PHO_DownlinkAssignment_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (PHO_DownlinkAssignment_t,  EGPRS_WindowSize,  5),
CSN_DESCR_END   (PHO_DownlinkAssignment_t)

static const
CSN_DESCR_BEGIN (PHO_USF_1_7_t)
  M_NEXT_EXIST  (PHO_USF_1_7_t, Exist_USF, 1),
  M_UINT        (PHO_USF_1_7_t,  USF,  3),
CSN_DESCR_END   (PHO_USF_1_7_t)

static const
CSN_DESCR_BEGIN       (USF_AllocationArray_t)
  M_UINT              (USF_AllocationArray_t,  USF_0,  3),
  M_VAR_TARRAY_OFFSET (USF_AllocationArray_t, USF_1_7, PHO_USF_1_7_t, NBR_OfAllocatedTimeslots),
CSN_DESCR_END         (USF_AllocationArray_t)

static const
CSN_DESCR_BEGIN  (PHO_UplinkAssignment_t)
  M_UINT         (PHO_UplinkAssignment_t,  PFI,  7),
  M_UINT          (PHO_UplinkAssignment_t,  RLC_Mode, 1),
  M_UINT         (PHO_UplinkAssignment_t,  TFI_Assignment,  5),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_ChannelCodingCommand, 1),
  M_UINT         (PHO_UplinkAssignment_t,  ChannelCodingCommand,  2),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_EGPRS_ChannelCodingCommand, 1),
  M_UINT         (PHO_UplinkAssignment_t,  EGPRS_ChannelCodingCommand,  4),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_EGPRS_WindowSize, 1),
  M_UINT         (PHO_UplinkAssignment_t,  EGPRS_WindowSize,  5),

  M_UINT          (PHO_UplinkAssignment_t,  USF_Granularity, 1),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_TBF_TimeslotAllocation, 1),
  M_LEFT_VAR_BMP (PHO_UplinkAssignment_t, TBF_TimeslotAllocation, u.USF_AllocationArray.NBR_OfAllocatedTimeslots, 0),

  M_UNION        (PHO_UplinkAssignment_t, 2),
  M_UINT         (PHO_UplinkAssignment_t,  u.USF_SingleAllocation,  3),
  M_TYPE         (PHO_UplinkAssignment_t, u.USF_AllocationArray, USF_AllocationArray_t),
CSN_DESCR_END    (PHO_UplinkAssignment_t)

static const
CSN_DESCR_BEGIN (GlobalTimeslotDescription_UA_t)
  M_TYPE        (GlobalTimeslotDescription_UA_t, GlobalTimeslotDescription, GlobalTimeslotDescription_t),
  M_NEXT_EXIST  (GlobalTimeslotDescription_UA_t, Exist_PHO_UA, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */

  M_TYPE        (GlobalTimeslotDescription_UA_t, PHO_UA, PHO_UplinkAssignment_t),
  M_FIXED       (GlobalTimeslotDescription_UA_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (GlobalTimeslotDescription_UA_t)

static const
CSN_DESCR_BEGIN (PHO_GPRS_t)
  M_NEXT_EXIST  (PHO_GPRS_t, Exist_ChannelCodingCommand, 1),
  M_UINT        (PHO_GPRS_t,  ChannelCodingCommand,  2),

  M_NEXT_EXIST  (PHO_GPRS_t, Exist_GlobalTimeslotDescription_UA, 1),
  M_TYPE        (PHO_GPRS_t, GTD_UA, GlobalTimeslotDescription_UA_t),

  M_NEXT_EXIST  (PHO_GPRS_t, Exist_DownlinkAssignment, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */
  M_TYPE        (PHO_GPRS_t, DownlinkAssignment, PHO_DownlinkAssignment_t),
  M_FIXED       (PHO_GPRS_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (PHO_GPRS_t)

static const
CSN_DESCR_BEGIN (EGPRS_Description_t)
  M_NEXT_EXIST  (EGPRS_Description_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (EGPRS_Description_t,  EGPRS_WindowSize,  5),

  M_UINT        (EGPRS_Description_t,  LinkQualityMeasurementMode,  2),
  M_NEXT_EXIST  (EGPRS_Description_t, Exist_BEP_Period2, 1),
  M_UINT        (EGPRS_Description_t,  BEP_Period2,  4),
CSN_DESCR_END   (EGPRS_Description_t)

static const
CSN_DESCR_BEGIN (DownlinkTBF_t)
  M_NEXT_EXIST  (DownlinkTBF_t, Exist_EGPRS_Description, 1),
  M_TYPE        (DownlinkTBF_t, EGPRS_Description, EGPRS_Description_t),

  M_NEXT_EXIST  (DownlinkTBF_t, Exist_DownlinkAssignment, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */
  M_TYPE        (DownlinkTBF_t, DownlinkAssignment, PHO_DownlinkAssignment_t),
  M_FIXED       (DownlinkTBF_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (DownlinkTBF_t)

static const
CSN_DESCR_BEGIN (PHO_EGPRS_t)
  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (PHO_EGPRS_t,  EGPRS_WindowSize,  5),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_EGPRS_ChannelCodingCommand, 1),
  M_UINT        (PHO_EGPRS_t,  EGPRS_ChannelCodingCommand,  4),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_BEP_Period2, 1),
  M_UINT        (PHO_EGPRS_t,  BEP_Period2,  4),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_GlobalTimeslotDescription_UA, 1),
  M_TYPE        (PHO_EGPRS_t, GTD_UA, GlobalTimeslotDescription_UA_t),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_DownlinkTBF, 1),
  M_TYPE        (PHO_EGPRS_t, DownlinkTBF, DownlinkTBF_t),
CSN_DESCR_END   (PHO_EGPRS_t)

static const
CSN_DESCR_BEGIN(PHO_TimingAdvance_t)
  M_TYPE       (PHO_TimingAdvance_t, GlobalPacketTimingAdvance, Global_Packet_Timing_Advance_t),
  M_NEXT_EXIST (PHO_TimingAdvance_t, Exist_PacketExtendedTimingAdvance, 1),
  M_UINT       (PHO_TimingAdvance_t,  PacketExtendedTimingAdvance,  2),
CSN_DESCR_END  (PHO_TimingAdvance_t)

static const
CSN_DESCR_BEGIN(NAS_Container_For_PS_HO_t)
  M_UINT         (NAS_Container_For_PS_HO_t,  NAS_ContainerLength, 7),
  M_UINT         (NAS_Container_For_PS_HO_t,  Spare_1a, 1),
  M_UINT         (NAS_Container_For_PS_HO_t,  Spare_1b, 1),
  M_UINT         (NAS_Container_For_PS_HO_t,  Spare_1c, 1),
  M_UINT         (NAS_Container_For_PS_HO_t,  Old_XID, 1),
  M_UINT         (NAS_Container_For_PS_HO_t,  Spare_1e, 1),
  M_UINT         (NAS_Container_For_PS_HO_t,  Type_of_Ciphering_Algo, 3),
  M_UINT         (NAS_Container_For_PS_HO_t,  IOV_UI_value,  32),
CSN_DESCR_END  (NAS_Container_For_PS_HO_t)

static const
CSN_DESCR_BEGIN(PS_HandoverTo_UTRAN_Payload_t)
  M_UINT       (PS_HandoverTo_UTRAN_Payload_t,  RRC_ContainerLength,  8),
  M_VAR_ARRAY  (PS_HandoverTo_UTRAN_Payload_t, RRC_Container, RRC_ContainerLength, 0),
CSN_DESCR_END  (PS_HandoverTo_UTRAN_Payload_t)


static const
CSN_DESCR_BEGIN(PHO_RadioResources_t)
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_HandoverReference, 1),
  M_UINT       (PHO_RadioResources_t,  HandoverReference,  8),

  M_UINT       (PHO_RadioResources_t,  ARFCN,  10),
  M_UINT       (PHO_RadioResources_t,  SI,  2),
  M_UINT        (PHO_RadioResources_t,  NCI, 1),
  M_UINT       (PHO_RadioResources_t,  BSIC,  6),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Active, 1),
  M_UINT        (PHO_RadioResources_t,  CCN_Active, 1),

  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Active_3G, 1),
  M_UINT        (PHO_RadioResources_t,  CCN_Active_3G, 1),

  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Support_Description, 1),
  M_TYPE       (PHO_RadioResources_t, CCN_Support_Description, CCN_Support_Description_t),

  M_TYPE       (PHO_RadioResources_t, Frequency_Parameters, Frequency_Parameters_t),
  M_UINT       (PHO_RadioResources_t,  NetworkControlOrder,  2),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_PHO_TimingAdvance, 1),
  M_TYPE       (PHO_RadioResources_t, PHO_TimingAdvance, PHO_TimingAdvance_t),

  M_UINT        (PHO_RadioResources_t,  Extended_Dynamic_Allocation, 1),
  M_UINT        (PHO_RadioResources_t,  RLC_Reset, 1),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_PO_PR, 2),
  M_UINT       (PHO_RadioResources_t,  PO,  4),
  M_UINT        (PHO_RadioResources_t,  PR_Mode, 1),


  M_NEXT_EXIST (PHO_RadioResources_t, Exist_UplinkControlTimeslot, 1),
  M_UINT       (PHO_RadioResources_t,  UplinkControlTimeslot,  3),

  M_UNION      (PHO_RadioResources_t, 2),
  M_TYPE       (PHO_RadioResources_t, u.PHO_GPRS_Mode, PHO_GPRS_t),
  M_TYPE       (PHO_RadioResources_t, u.PHO_EGPRS_Mode, PHO_EGPRS_t),
CSN_DESCR_END  (PHO_RadioResources_t)

static const
CSN_DESCR_BEGIN(PS_HandoverTo_A_GB_ModePayload_t)
  M_FIXED      (PS_HandoverTo_A_GB_ModePayload_t, 2, 0x00), /* For future extension to enum. */
  M_TYPE       (PS_HandoverTo_A_GB_ModePayload_t, PHO_RadioResources, PHO_RadioResources_t),

  M_NEXT_EXIST (PS_HandoverTo_A_GB_ModePayload_t, Exist_NAS_Container, 1),
  M_TYPE       (PS_HandoverTo_A_GB_ModePayload_t, NAS_Container, NAS_Container_For_PS_HO_t),
CSN_DESCR_END  (PS_HandoverTo_A_GB_ModePayload_t)

static const
CSN_DESCR_BEGIN(Packet_Handover_Command_t)
  M_UINT       (Packet_Handover_Command_t,  MessageType,  6),
  M_UINT       (Packet_Handover_Command_t,  PageMode,  2),

  M_FIXED      (Packet_Handover_Command_t, 1, 0x00), /* 0 fixed */
  M_TYPE       (Packet_Handover_Command_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Handover_Command_t,  ContainerID,  2),

  M_UNION      (Packet_Handover_Command_t, 4),
  M_TYPE       (Packet_Handover_Command_t, u.PS_HandoverTo_A_GB_ModePayload, PS_HandoverTo_A_GB_ModePayload_t),
  M_TYPE       (Packet_Handover_Command_t, u.PS_HandoverTo_UTRAN_Payload, PS_HandoverTo_UTRAN_Payload_t),
  CSN_ERROR    (Packet_Handover_Command_t, "10 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (Packet_Handover_Command_t, "11 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_PADDING_BITS(Packet_Handover_Command_t),
CSN_DESCR_END  (Packet_Handover_Command_t)

/*< End Packet Handover Command >*/

/*< Packet Physical Information message content > */

static const
CSN_DESCR_BEGIN(Packet_PhysicalInformation_t)
  M_UINT       (Packet_PhysicalInformation_t,  MessageType,  6),
  M_UINT       (Packet_PhysicalInformation_t,  PageMode,  2),

  M_TYPE       (Packet_PhysicalInformation_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_PhysicalInformation_t,  TimingAdvance,  8),
  M_PADDING_BITS(Packet_PhysicalInformation_t),
CSN_DESCR_END  (Packet_PhysicalInformation_t)

/*< End Packet Physical Information > */


/*< ADDITIONAL MS RADIO ACCESS CAPABILITIES content > */
static const
CSN_ChoiceElement_t AdditionalMsRadAccessCapID[] =
{
  {1, 0,    0, M_TYPE(AdditionalMsRadAccessCapID_t, u.Global_TFI, Global_TFI_t)},
  {1, 0x01, 0, M_UINT(AdditionalMsRadAccessCapID_t, u.TLLI, 32)},
};

static const
CSN_DESCR_BEGIN(AdditionalMsRadAccessCapID_t)
  M_CHOICE     (AdditionalMsRadAccessCapID_t, UnionType, AdditionalMsRadAccessCapID, ElementsOf(AdditionalMsRadAccessCapID)),
CSN_DESCR_END  (AdditionalMsRadAccessCapID_t)


static const
CSN_DESCR_BEGIN       (Additional_MS_Rad_Access_Cap_t)
  /* Mac header */
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  PayloadType,  2),
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  spare,  5),
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  R,  1),
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  MESSAGE_TYPE,  6),
  /* Mac header */

  M_TYPE              (Additional_MS_Rad_Access_Cap_t,  ID, AdditionalMsRadAccessCapID_t),
  M_TYPE              (Additional_MS_Rad_Access_Cap_t,  MS_Radio_Access_capability, MS_Radio_Access_capability_t),
  M_PADDING_BITS      (Additional_MS_Rad_Access_Cap_t),
CSN_DESCR_END         (Additional_MS_Rad_Access_Cap_t)


/*< End  ADDITIONAL MS RADIO ACCESS CAPABILITIES > */


/*< Packet Pause content > */

static const
CSN_DESCR_BEGIN       (Packet_Pause_t)
  M_UINT              (Packet_Pause_t,  MESSAGE_TYPE,  2),
  M_UINT              (Packet_Pause_t,  TLLI, 32),
  M_BITMAP            (Packet_Pause_t,  RAI, 48),
  M_PADDING_BITS      (Packet_Pause_t),
CSN_DESCR_END         (Packet_Pause_t)


/*< End Packet Pause > */


/*< Packet System Information Type 1 message content >*/
CSN_DESCR_BEGIN(PSI1_AdditionsR6_t)
  M_UINT       (PSI1_AdditionsR6_t, LB_MS_TXPWR_MAX_CCH, 5),
CSN_DESCR_END  (PSI1_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (PSI1_AdditionsR99_t)
  M_UINT               (PSI1_AdditionsR99_t,  MSCR,  1),
  M_UINT               (PSI1_AdditionsR99_t,  SGSNR,  1),
  M_UINT               (PSI1_AdditionsR99_t,  BandIndicator,  1),
  M_NEXT_EXIST_OR_NULL (PSI1_AdditionsR99_t, Exist_AdditionsR6, 1),
  M_TYPE               (PSI1_AdditionsR99_t, AdditionsR6, PSI1_AdditionsR6_t),
CSN_DESCR_END          (PSI1_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(PCCCH_Organization_t)
  M_UINT       (PCCCH_Organization_t,  BS_PCC_REL,  1),
  M_UINT       (PCCCH_Organization_t,  BS_PBCCH_BLKS,  2),
  M_UINT       (PCCCH_Organization_t,  BS_PAG_BLKS_RES,  4),
  M_UINT       (PCCCH_Organization_t,  BS_PRACH_BLKS,  4),
CSN_DESCR_END  (PCCCH_Organization_t)


static const
CSN_DESCR_BEGIN(PSI1_t)
  M_UINT               (PSI1_t,  MESSAGE_TYPE,  6),
  M_UINT               (PSI1_t,  PAGE_MODE,  2),

  M_UINT               (PSI1_t,  PBCCH_CHANGE_MARK,  3),
  M_UINT               (PSI1_t,  PSI_CHANGE_FIELD,  4),
  M_UINT               (PSI1_t,  PSI1_REPEAT_PERIOD,  4),
  M_UINT               (PSI1_t,  PSI_COUNT_LR,  6),

  M_NEXT_EXIST         (PSI1_t, Exist_PSI_COUNT_HR, 1),
  M_UINT               (PSI1_t,  PSI_COUNT_HR,  4),

  M_UINT               (PSI1_t,  MEASUREMENT_ORDER,  1),
  M_TYPE               (PSI1_t,  GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE               (PSI1_t,  PRACH_Control, PRACH_Control_t),
  M_TYPE               (PSI1_t,  PCCCH_Organization, PCCCH_Organization_t),
  M_TYPE               (PSI1_t,  Global_Power_Control_Parameters, Global_Power_Control_Parameters_t),
  M_UINT               (PSI1_t,  PSI_STATUS_IND,  1),

  M_NEXT_EXIST_OR_NULL (PSI1_t, Exist_AdditionsR99, 1),
  M_TYPE               (PSI1_t,  AdditionsR99, PSI1_AdditionsR99_t),

  M_PADDING_BITS(PSI1_t),
CSN_DESCR_END  (PSI1_t)
/*< End Packet System Information Type 1 message content >*/


/*< Packet System Information Type 2 message content >*/

static const
CSN_DESCR_BEGIN(LAI_t)
  M_TYPE       (LAI_t,  PLMN, PLMN_t),
  M_UINT       (LAI_t,  LAC,  16),
CSN_DESCR_END  (LAI_t)

static const
CSN_DESCR_BEGIN(Cell_Identification_t)
  M_TYPE       (Cell_Identification_t,  LAI, LAI_t),
  M_UINT       (Cell_Identification_t,  RAC,  8),
  M_UINT       (Cell_Identification_t,  Cell_Identity,  16),
CSN_DESCR_END  (Cell_Identification_t)

static const
CSN_DESCR_BEGIN(Non_GPRS_Cell_Options_t)
  M_UINT        (Non_GPRS_Cell_Options_t,  ATT, 1),

  M_NEXT_EXIST (Non_GPRS_Cell_Options_t, Exist_T3212, 1),
  M_UINT       (Non_GPRS_Cell_Options_t,  T3212, 8),

  M_UINT       (Non_GPRS_Cell_Options_t,  NECI, 1),
  M_UINT       (Non_GPRS_Cell_Options_t,  PWRC, 1),
  M_UINT       (Non_GPRS_Cell_Options_t,  DTX, 2),
  M_UINT       (Non_GPRS_Cell_Options_t,  RADIO_LINK_TIMEOUT, 4),
  M_UINT       (Non_GPRS_Cell_Options_t,  BS_AG_BLKS_RES, 3),
  M_UINT       (Non_GPRS_Cell_Options_t,  CCCH_CONF, 3),
  M_UINT       (Non_GPRS_Cell_Options_t,  BS_PA_MFRMS, 3),
  M_UINT       (Non_GPRS_Cell_Options_t,  MAX_RETRANS, 2),
  M_UINT       (Non_GPRS_Cell_Options_t,  TX_INTEGER, 4),
  M_UINT       (Non_GPRS_Cell_Options_t,  EC, 1),
  M_UINT       (Non_GPRS_Cell_Options_t,  MS_TXPWR_MAX_CCCH, 5),

  M_NEXT_EXIST (Non_GPRS_Cell_Options_t, Exist_Extension_Bits, 1),
  M_TYPE       (Non_GPRS_Cell_Options_t,  Extension_Bits, Extension_Bits_t),
CSN_DESCR_END  (Non_GPRS_Cell_Options_t)

static const
CSN_DESCR_BEGIN(Reference_Frequency_t)
  M_UINT(Reference_Frequency_t, NUMBER, 4),
  M_UINT_OFFSET(Reference_Frequency_t, Length, 4, 3),
  M_VAR_ARRAY  (Reference_Frequency_t, Contents[0], Length, 0),
CSN_DESCR_END  (Reference_Frequency_t)

static const
CSN_DESCR_BEGIN(PSI2_MA_t)
  M_UINT(PSI2_MA_t, NUMBER, 4),
  M_TYPE(PSI2_MA_t, Mobile_Allocation, GPRS_Mobile_Allocation_t),
CSN_DESCR_END  (PSI2_MA_t)

static const
CSN_DESCR_BEGIN(Non_Hopping_PCCCH_Carriers_t)
  M_UINT(Non_Hopping_PCCCH_Carriers_t, ARFCN, 10),
  M_UINT(Non_Hopping_PCCCH_Carriers_t, TIMESLOT_ALLOCATION, 8),
CSN_DESCR_END  (Non_Hopping_PCCCH_Carriers_t)

static const
CSN_DESCR_BEGIN(NonHoppingPCCCH_t)
  M_REC_TARRAY (NonHoppingPCCCH_t, Carriers, Non_Hopping_PCCCH_Carriers_t, Count_Carriers),
CSN_DESCR_END  (NonHoppingPCCCH_t)

static const
CSN_DESCR_BEGIN(Hopping_PCCCH_Carriers_t)
  M_UINT(Hopping_PCCCH_Carriers_t, MAIO, 6),
  M_UINT(Hopping_PCCCH_Carriers_t, TIMESLOT_ALLOCATION, 8),
CSN_DESCR_END  (Hopping_PCCCH_Carriers_t)

static const
CSN_DESCR_BEGIN(HoppingPCCCH_t)
  M_UINT(HoppingPCCCH_t, MA_NUMBER, 4),
  M_REC_TARRAY (HoppingPCCCH_t, Carriers, Hopping_PCCCH_Carriers_t, Count_Carriers),
CSN_DESCR_END  (HoppingPCCCH_t)

static const
CSN_DESCR_BEGIN(PCCCH_Description_t)
  M_UINT(PCCCH_Description_t, TSC, 3),
  M_UNION     (PCCCH_Description_t, 2),
  M_TYPE      (PCCCH_Description_t, u.NonHopping, NonHoppingPCCCH_t),
  M_TYPE      (PCCCH_Description_t, u.Hopping, HoppingPCCCH_t),
CSN_DESCR_END  (PCCCH_Description_t)

static const
CSN_DESCR_BEGIN(PSI2_t)
  M_UINT       (PSI2_t,  MESSAGE_TYPE,  6),
  M_UINT       (PSI2_t,  PAGE_MODE,  2),

  M_UINT       (PSI2_t,  CHANGE_MARK,  2),
  M_UINT       (PSI2_t,  INDEX,  3),
  M_UINT       (PSI2_t,  COUNT,  3),

  M_NEXT_EXIST (PSI2_t, Exist_Cell_Identification, 1),
  M_TYPE       (PSI2_t,  Cell_Identification, Cell_Identification_t),

  M_NEXT_EXIST (PSI2_t, Exist_Non_GPRS_Cell_Options, 1),
  M_TYPE       (PSI2_t,  Non_GPRS_Cell_Options, Non_GPRS_Cell_Options_t),

  M_REC_TARRAY (PSI2_t, Reference_Frequency, Reference_Frequency_t, Count_Reference_Frequency),
  M_TYPE       (PSI2_t,  Cell_Allocation, Cell_Allocation_t),
  M_REC_TARRAY (PSI2_t, GPRS_MA, PSI2_MA_t, Count_GPRS_MA),
  M_REC_TARRAY (PSI2_t, PCCCH_Description, PCCCH_Description_t, Count_PCCCH_Description),
  M_PADDING_BITS(PSI2_t),
CSN_DESCR_END  (PSI2_t)
/*< End Packet System Information Type 2 message content >*/



/*< Packet System Information Type 3 message content >*/
static const
CSN_DESCR_BEGIN(Serving_Cell_params_t)
  M_UINT       (Serving_Cell_params_t,  CELL_BAR_ACCESS_2, 1),
  M_UINT       (Serving_Cell_params_t,  EXC_ACC, 1),
  M_UINT       (Serving_Cell_params_t,  GPRS_RXLEV_ACCESS_MIN, 6),
  M_UINT       (Serving_Cell_params_t,  GPRS_MS_TXPWR_MAX_CCH, 5),
  M_NEXT_EXIST (Serving_Cell_params_t, Exist_HCS, 1),
  M_TYPE       (Serving_Cell_params_t,  HCS, HCS_t),
  M_UINT       (Serving_Cell_params_t,  MULTIBAND_REPORTING, 2),
CSN_DESCR_END  (Serving_Cell_params_t)


static const
CSN_DESCR_BEGIN(Gen_Cell_Sel_t)
  M_UINT       (Gen_Cell_Sel_t,  GPRS_CELL_RESELECT_HYSTERESIS, 3),
  M_UINT       (Gen_Cell_Sel_t,  C31_HYST, 1),
  M_UINT       (Gen_Cell_Sel_t,  C32_QUAL, 1),
  M_FIXED      (Gen_Cell_Sel_t, 1, 0x01),

  M_NEXT_EXIST (Gen_Cell_Sel_t, Exist_T_RESEL, 1),
  M_UINT       (Gen_Cell_Sel_t,  T_RESEL, 3),

  M_NEXT_EXIST (Gen_Cell_Sel_t, Exist_RA_RESELECT_HYSTERESIS, 1),
  M_UINT       (Gen_Cell_Sel_t,  RA_RESELECT_HYSTERESIS, 3),
CSN_DESCR_END  (Gen_Cell_Sel_t)


static const
CSN_DESCR_BEGIN(COMPACT_Cell_Sel_t)
  M_UINT       (COMPACT_Cell_Sel_t,  bsic, 6),
  M_UINT       (COMPACT_Cell_Sel_t,  CELL_BAR_ACCESS_2, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  EXC_ACC, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  SAME_RA_AS_SERVING_CELL, 1),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GPRS_RXLEV_ACCESS_MIN, 2),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_RXLEV_ACCESS_MIN, 6),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_MS_TXPWR_MAX_CCH, 5),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GPRS_TEMPORARY_OFFSET, 2),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_TEMPORARY_OFFSET, 3),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_PENALTY_TIME, 5),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_RESELECT_OFFSET, 5),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_Hcs_Parm, 1),
  M_TYPE       (COMPACT_Cell_Sel_t,  HCS_Param, HCS_t),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_TIME_GROUP, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  TIME_GROUP, 2),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GUAR_CONSTANT_PWR_BLKS, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  GUAR_CONSTANT_PWR_BLKS, 2),
CSN_DESCR_END  (COMPACT_Cell_Sel_t)

static const
CSN_DESCR_BEGIN(COMPACT_Neighbour_Cell_Param_Remaining_t)
  /* this FREQ_DIFF_LENGTH is not initialised, it should be the SAME as COMPACT_Neighbour_Cell_Param_t.FREQ_DIFF_LENGTH.
  * So it is buggy, but there is no way to handle it. Same issue is in Cell_Selection_Params_With_FreqDiff_t.FREQ_DIFF_LENGTH.
  */
  M_VAR_BITMAP (COMPACT_Neighbour_Cell_Param_Remaining_t,  FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_TYPE       (COMPACT_Neighbour_Cell_Param_Remaining_t,  COMPACT_Cell_Sel_Remain_Cells, COMPACT_Cell_Sel_t),
CSN_DESCR_END  (COMPACT_Neighbour_Cell_Param_Remaining_t)


static const
CSN_DESCR_BEGIN(COMPACT_Neighbour_Cell_Param_t)
  M_UINT       (COMPACT_Neighbour_Cell_Param_t,  START_FREQUENCY, 10),
  M_TYPE       (COMPACT_Neighbour_Cell_Param_t,  COMPACT_Cell_Sel, COMPACT_Cell_Sel_t),
  M_UINT       (COMPACT_Neighbour_Cell_Param_t,  NR_OF_REMAINING_CELLS, 4),
  M_UINT_OFFSET(COMPACT_Neighbour_Cell_Param_t,  FREQ_DIFF_LENGTH, 3, 1),
  M_VAR_TARRAY (COMPACT_Neighbour_Cell_Param_t,  COMPACT_Neighbour_Cell_Param_Remaining, COMPACT_Neighbour_Cell_Param_Remaining_t, NR_OF_REMAINING_CELLS),
CSN_DESCR_END  (COMPACT_Neighbour_Cell_Param_t)


static const
CSN_DESCR_BEGIN(COMPACT_Info_t)
  M_TYPE       (COMPACT_Info_t,  Cell_Identification, Cell_Identification_t),
  M_REC_TARRAY (COMPACT_Info_t,  COMPACT_Neighbour_Cell_Param, COMPACT_Neighbour_Cell_Param_t, COMPACT_Neighbour_Cell_Param_Count),
CSN_DESCR_END  (COMPACT_Info_t)


static const
CSN_DESCR_BEGIN(PSI3_AdditionR4_t)
  M_NEXT_EXIST (PSI3_AdditionR4_t, Exist_CCN_Support_Desc, 1),
  M_TYPE       (PSI3_AdditionR4_t,  CCN_Support_Desc, CCN_Support_Description_t),
CSN_DESCR_END  (PSI3_AdditionR4_t)


static const
CSN_DESCR_BEGIN(PSI3_AdditionR99_t)
  M_FIXED      (PSI3_AdditionR99_t, 2, 0x00),
  M_NEXT_EXIST (PSI3_AdditionR99_t, Exist_COMPACT_Info, 1),
  M_TYPE       (PSI3_AdditionR99_t,  COMPACT_Info, COMPACT_Info_t),
  M_FIXED      (PSI3_AdditionR99_t, 1, 0x00),
  M_NEXT_EXIST (PSI3_AdditionR99_t, Exist_AdditionR4, 1),
  M_TYPE       (PSI3_AdditionR99_t,  AdditionR4, PSI3_AdditionR4_t),
CSN_DESCR_END  (PSI3_AdditionR99_t)


static const
CSN_DESCR_BEGIN(PSI3_AdditionR98_t)
  M_TYPE       (PSI3_AdditionR98_t,  Scell_LSA_ID_Info, LSA_ID_Info_t),

  M_NEXT_EXIST (PSI3_AdditionR98_t, Exist_LSA_Parameters, 1),
  M_TYPE       (PSI3_AdditionR98_t,  LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST (PSI3_AdditionR98_t, Exist_AdditionR99, 1),
  M_TYPE       (PSI3_AdditionR98_t,  AdditionR99, PSI3_AdditionR99_t),
CSN_DESCR_END  (PSI3_AdditionR98_t)


static const
CSN_DESCR_BEGIN(PSI3_t)
  M_UINT       (PSI3_t,  MESSAGE_TYPE,  6),
  M_UINT       (PSI3_t,  PAGE_MODE,  2),
  M_UINT       (PSI3_t,  CHANGE_MARK,  2),
  M_UINT       (PSI3_t,  BIS_COUNT,  4),
  M_TYPE       (PSI3_t,  Serving_Cell_params, Serving_Cell_params_t),
  M_TYPE       (PSI3_t,  General_Cell_Selection, Gen_Cell_Sel_t),
  M_TYPE       (PSI3_t,  NeighbourCellList, NeighbourCellList_t),

  M_NEXT_EXIST (PSI3_t, Exist_AdditionR98, 1),
  M_TYPE       (PSI3_t,  AdditionR98, PSI3_AdditionR98_t),

  M_PADDING_BITS(PSI3_t),
CSN_DESCR_END  (PSI3_t)
/*< End Packet System Information Type 3 message content >*/


/*< Packet System Information Type 5 message content >*/
static const
CSN_DESCR_BEGIN(MeasurementParams_t)
  M_NEXT_EXIST (MeasurementParams_t, Exist_MULTI_BAND_REPORTING, 1),
  M_UINT       (MeasurementParams_t,  MULTI_BAND_REPORTING,  2),

  M_NEXT_EXIST (MeasurementParams_t, Exist_SERVING_BAND_REPORTING, 1),
  M_UINT       (MeasurementParams_t,  SERVING_BAND_REPORTING,  2),

  M_NEXT_EXIST (MeasurementParams_t, Exist_SCALE_ORD, 1),
  M_UINT       (MeasurementParams_t,  SCALE_ORD,  2),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold900, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold900, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold1800, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold1800, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold400, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold400, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold1900, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold1900, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold850, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold850, OffsetThreshold_t),
CSN_DESCR_END  (MeasurementParams_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams3G_PSI5_t)
  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existRepParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  RepQuantFDD,  1),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  MultiratReportingFDD,  2),

  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existReportingParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingOffsetFDD,  3),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingThresholdFDD,  3),

  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existMultiratReportingTDD, 1),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  MultiratReportingTDD,  2),

  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existOffsetThresholdTDD, 2),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingOffsetTDD,  3),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingThresholdTDD,  3),
CSN_DESCR_END  (GPRSMeasurementParams3G_PSI5_t)

static const
CSN_DESCR_BEGIN(ENH_Reporting_Parameters_t)
  M_UINT       (ENH_Reporting_Parameters_t,  REPORT_TYPE,  1),
  M_UINT       (ENH_Reporting_Parameters_t,  REPORTING_RATE,  1),
  M_UINT       (ENH_Reporting_Parameters_t,  INVALID_BSIC_REPORTING,  1),

  M_NEXT_EXIST (ENH_Reporting_Parameters_t, Exist_NCC_PERMITTED, 1),
  M_UINT       (ENH_Reporting_Parameters_t,  NCC_PERMITTED,  8),

  M_NEXT_EXIST (ENH_Reporting_Parameters_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Reporting_Parameters_t, GPRSMeasurementParams, MeasurementParams_t),

  M_NEXT_EXIST (ENH_Reporting_Parameters_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Reporting_Parameters_t, GPRSMeasurementParams3G, GPRSMeasurementParams3G_PSI5_t),
CSN_DESCR_END  (ENH_Reporting_Parameters_t)

static const
CSN_DESCR_BEGIN(PSI5_AdditionsR7)
  M_NEXT_EXIST (PSI5_AdditionsR7, Exist_OffsetThreshold_700, 1),
  M_TYPE       (PSI5_AdditionsR7,  OffsetThreshold_700, OffsetThreshold_t),

  M_NEXT_EXIST (PSI5_AdditionsR7, Exist_OffsetThreshold_810, 1),
  M_TYPE       (PSI5_AdditionsR7,  OffsetThreshold_810, OffsetThreshold_t),
CSN_DESCR_END  (PSI5_AdditionsR7)

static const
CSN_DESCR_BEGIN(PSI5_AdditionsR5)
  M_NEXT_EXIST (PSI5_AdditionsR5, Exist_GPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE       (PSI5_AdditionsR5,  GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),

  M_NEXT_EXIST (PSI5_AdditionsR5, Exist_AdditionsR7, 1),
  M_TYPE       (PSI5_AdditionsR5,  AdditionsR7, PSI5_AdditionsR7),
CSN_DESCR_END  (PSI5_AdditionsR5)

static const
CSN_DESCR_BEGIN(PSI5_AdditionsR99)
  M_NEXT_EXIST (PSI5_AdditionsR99, Exist_ENH_Reporting_Param, 1),
  M_TYPE       (PSI5_AdditionsR99,  ENH_Reporting_Param, ENH_Reporting_Parameters_t),

  M_NEXT_EXIST (PSI5_AdditionsR99, Exist_AdditionsR5, 1),
  M_TYPE       (PSI5_AdditionsR99,  AdditionisR5, PSI5_AdditionsR5),
CSN_DESCR_END  (PSI5_AdditionsR99)

static const
CSN_DESCR_BEGIN(PSI5_t)
  M_UINT       (PSI5_t,  MESSAGE_TYPE,  6),
  M_UINT       (PSI5_t,  PAGE_MODE,  2),
  M_UINT       (PSI5_t,  CHANGE_MARK,  2),
  M_UINT       (PSI5_t,  INDEX,  3),
  M_UINT       (PSI5_t,  COUNT,  3),

  M_NEXT_EXIST (PSI5_t, Eixst_NC_Meas_Param, 1),
  M_TYPE       (PSI5_t,  NC_Meas_Param, NC_Measurement_Parameters_t),

  M_FIXED      (PSI5_t, 1, 0x00),

  M_NEXT_EXIST (PSI5_t, Exist_AdditionsR99, 1),
  M_TYPE       (PSI5_t,  AdditionsR99, PSI5_AdditionsR99),

  M_PADDING_BITS(PSI5_t),
CSN_DESCR_END  (PSI5_t)
/*< End Packet System Information Type 5 message content >*/


/*< Packet System Information Type 13 message content >*/
static const
CSN_DESCR_BEGIN(PSI13_AdditionsR6)
  M_NEXT_EXIST (PSI13_AdditionsR6, Exist_LB_MS_TXPWR_MAX_CCH, 1),
  M_UINT       (PSI13_AdditionsR6,  LB_MS_TXPWR_MAX_CCH,  5),
  M_UINT       (PSI13_AdditionsR6,  SI2n_SUPPORT,  2),
CSN_DESCR_END  (PSI13_AdditionsR6)

static const
CSN_DESCR_BEGIN(PSI13_AdditionsR4)
  M_UINT       (PSI13_AdditionsR4,  SI_STATUS_IND,  1),
  M_NEXT_EXIST (PSI13_AdditionsR4, Exist_AdditionsR6, 1),
  M_TYPE       (PSI13_AdditionsR4,  AdditionsR6, PSI13_AdditionsR6),
CSN_DESCR_END  (PSI13_AdditionsR4)

static const
CSN_DESCR_BEGIN(PSI13_AdditionR99)
  M_UINT       (PSI13_AdditionR99,  SGSNR,  1),
  M_NEXT_EXIST (PSI13_AdditionR99, Exist_AdditionsR4, 1),
  M_TYPE       (PSI13_AdditionR99,  AdditionsR4, PSI13_AdditionsR4),
CSN_DESCR_END  (PSI13_AdditionR99)

static const
CSN_DESCR_BEGIN(PSI13_t)
  M_UINT       (PSI13_t,  MESSAGE_TYPE,  6),
  M_UINT       (PSI13_t,  PAGE_MODE,  2),
  M_UINT       (PSI13_t,  BCCH_CHANGE_MARK,  3),
  M_UINT       (PSI13_t,  SI_CHANGE_FIELD,  4),

  M_NEXT_EXIST (PSI13_t, Exist_MA, 2),
  M_UINT       (PSI13_t,  SI13_CHANGE_MARK,  2),
  M_TYPE       (PSI13_t,  GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),

  M_UNION      (PSI13_t, 2),
  M_TYPE       (PSI13_t, u.PBCCH_Not_present, PBCCH_Not_present_t),
  M_TYPE       (PSI13_t, u.PBCCH_present, PBCCH_present_t),

  M_NEXT_EXIST (PSI13_t, Exist_AdditionsR99, 1),
  M_TYPE       (PSI13_t,  AdditionsR99, PSI13_AdditionR99),

  M_PADDING_BITS(PSI13_t),
CSN_DESCR_END  (PSI13_t)
/*< End Packet System Information Type 13 message content >*/

/* SI1_RestOctet_t */

static const
CSN_DESCR_BEGIN  (SI1_RestOctet_t)
  M_NEXT_EXIST_LH(SI1_RestOctet_t, Exist_NCH_Position, 1),
  M_UINT         (SI1_RestOctet_t,  NCH_Position,  5),

  M_UINT_LH      (SI1_RestOctet_t,  BandIndicator,  1),
CSN_DESCR_END    (SI1_RestOctet_t)

/* SI3_Rest_Octet_t */
static const
CSN_DESCR_BEGIN(Selection_Parameters_t)
  M_UINT       (Selection_Parameters_t,  CBQ,  1),
  M_UINT       (Selection_Parameters_t,  CELL_RESELECT_OFFSET,  6),
  M_UINT       (Selection_Parameters_t,  TEMPORARY_OFFSET,  3),
  M_UINT       (Selection_Parameters_t,  PENALTY_TIME,  5),
CSN_DESCR_END  (Selection_Parameters_t)

static const
CSN_DESCR_BEGIN  (SI3_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI3_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI3_Rest_Octet_t,  Power_Offset,  2),

  M_UINT_LH      (SI3_Rest_Octet_t,  System_Information_2ter_Indicator,  1),
  M_UINT_LH      (SI3_Rest_Octet_t,  Early_Classmark_Sending_Control,  1),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_WHERE, 1),
  M_UINT         (SI3_Rest_Octet_t,  WHERE,  3),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI3_Rest_Octet_t,  RA_COLOUR,  3),
  M_UINT         (SI3_Rest_Octet_t,  SI13_POSITION,  1),

  M_UINT_LH      (SI3_Rest_Octet_t,  ECS_Restriction3G,  1),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, ExistSI2quaterIndicator, 1),
  M_UINT         (SI3_Rest_Octet_t,  SI2quaterIndicator,  1),
CSN_DESCR_END    (SI3_Rest_Octet_t)

static const
CSN_DESCR_BEGIN  (SI4_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI4_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI4_Rest_Octet_t,  Power_Offset,  2),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI4_Rest_Octet_t,  RA_COLOUR,  3),
  M_UINT         (SI4_Rest_Octet_t,  SI13_POSITION,  1),
CSN_DESCR_END    (SI4_Rest_Octet_t)

/* SI6_RestOctet_t */

static const
CSN_DESCR_BEGIN(PCH_and_NCH_Info_t)
  M_UINT       (PCH_and_NCH_Info_t,  PagingChannelRestructuring,  1),
  M_UINT       (PCH_and_NCH_Info_t,  NLN_SACCH,  2),

  M_NEXT_EXIST (PCH_and_NCH_Info_t, Exist_CallPriority, 1),
  M_UINT       (PCH_and_NCH_Info_t,  CallPriority,  3),

  M_UINT       (PCH_and_NCH_Info_t,  NLN_Status,  1),
CSN_DESCR_END  (PCH_and_NCH_Info_t)

static const
CSN_DESCR_BEGIN  (SI6_RestOctet_t)
  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_PCH_and_NCH_Info, 1),
  M_TYPE         (SI6_RestOctet_t, PCH_and_NCH_Info, PCH_and_NCH_Info_t),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_VBS_VGCS_Options, 1),
  M_UINT         (SI6_RestOctet_t,  VBS_VGCS_Options,  2),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_DTM_Support, 2),
  M_UINT         (SI6_RestOctet_t,  RAC,  8),
  M_UINT         (SI6_RestOctet_t,  MAX_LAPDm,  3),

  M_UINT_LH      (SI6_RestOctet_t,  BandIndicator,  1),
CSN_DESCR_END    (SI6_RestOctet_t)


// ----------------------------------------------------------------------------
// osmo-pcu RLCMAC APIs
// ----------------------------------------------------------------------------
static const struct value_string rlcmac_ul_msg_names[] = {
        { MT_PACKET_CELL_CHANGE_FAILURE,        "Pkt Cell Change Failure" },
        { MT_PACKET_CONTROL_ACK,                "Pkt Control Ack" },
        { MT_PACKET_DOWNLINK_ACK_NACK ,         "Pkt DL ACK/NACK" },
        { MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK, "Pkt UL Dummy Ctrl Block" },
        { MT_PACKET_MEASUREMENT_REPORT,         "Pkt Meas Report" },
        { MT_PACKET_RESOURCE_REQUEST,           "Pkt Resource Req" },
        { MT_PACKET_MOBILE_TBF_STATUS,          "Pkt Mobile TBF Status" },
        { MT_PACKET_PSI_STATUS,                 "Pkt PSI Status" },
        { MT_EGPRS_PACKET_DOWNLINK_ACK_NACK,    "EGPRS Pkt DL ACK/NACK" },
        { MT_PACKET_PAUSE,                      "Pkt Pause" },
        { MT_PACKET_ENHANCED_MEASUREMENT_REPORT,"Pkt Enchanced Meas Report" },
        { MT_ADDITIONAL_MS_RAC,                 "Additional MS RAC" },
        { MT_PACKET_CELL_CHANGE_NOTIFICATION,   "Pkt Cell Changte Notification" },
        { MT_PACKET_SI_STATUS,                  "Pkt SI Status" },
        { MT_ENHANCED_MEASUREMENT_REPORT,       "Enchanced Meas Report" },
        { 0, NULL }
};

static const struct value_string rlcmac_dl_msg_names[] = {
        { MT_PACKET_CELL_CHANGE_ORDER,            "Pkt Cell Change Order" },
        { MT_PACKET_DOWNLINK_ASSIGNMENT,          "Pkt DL ASS" },
        { MT_PACKET_MEASUREMENT_ORDER,            "Pkt Meas Order" },
        { MT_PACKET_POLLING_REQ,                  "Pkt Polling Req" },
        { MT_PACKET_POWER_CONTROL_TIMING_ADVANCE, "Pkt PWR CTRL TA" },
        { MT_PACKET_QUEUEING_NOTIFICATION,        "Pkt Queueing Notification" },
        { MT_PACKET_TIMESLOT_RECONFIGURE,         "Pkt TS Reconf" },
        { MT_PACKET_TBF_RELEASE,                  "Pkt TBF Release" },
        { MT_PACKET_UPLINK_ACK_NACK,              "Pkt UL ACK/NACK" },
        { MT_PACKET_UPLINK_ASSIGNMENT,            "Pkt UL ASS" },
        { MT_PACKET_CELL_CHANGE_CONTINUE,         "Pkt Cell Change Continue" },
        { MT_PACKET_NEIGHBOUR_CELL_DATA,          "Pkt Neightbour Cell Data" },
        { MT_PACKET_SERVING_CELL_DATA,            "Pkt Serving Cell Data" },
        { MT_PACKET_HANDOVER_COMMAND,             "Pkt Handover Cmd" },
        { MT_PACKET_PHYSICAL_INFORMATION,         "Pkt Physical Info" },
        { MT_PACKET_ACCESS_REJECT,                "Pkt Access Reject" },
        { MT_PACKET_PAGING_REQUEST,               "Pkt Paging Request" },
        { MT_PACKET_PDCH_RELEASE,                 "Pkt PDCH Release" },
        { MT_PACKET_PRACH_PARAMETERS,             "Pkt PRACH Params" },
        { MT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK, "Pkt DL Dummy Ctrl Block" },
        { MT_PACKET_SYSTEM_INFO_6,                "Pkt SI 6" },
        { MT_PACKET_SYSTEM_INFO_1,                "Pkt SI 1" },
        { MT_PACKET_SYSTEM_INFO_2,                "Pkt SI 2" },
        { MT_PACKET_SYSTEM_INFO_3,                "Pkt SI 3" },
        { MT_PACKET_SYSTEM_INFO_3_BIS,            "Pkt SI 3bis" },
        { MT_PACKET_SYSTEM_INFO_4,                "Pkt SI 4" },
        { MT_PACKET_SYSTEM_INFO_5,                "Pkt SI 5" },
        { MT_PACKET_SYSTEM_INFO_13,               "Pkt SI 13" },
        { MT_PACKET_SYSTEM_INFO_7,                "Pkt SI 7" },
        { MT_PACKET_SYSTEM_INFO_8,                "Pkt SI 8" },
        { MT_PACKET_SYSTEM_INFO_14,               "Pkt SI 14" },
        { MT_PACKET_SYSTEM_INFO_3_TER,            "Pkt SI 3ter" },
        { MT_PACKET_SYSTEM_INFO_3_QUATER,         "Pkt SI 3quater" },
        { MT_PACKET_SYSTEM_INFO_15,               "Pkt SI 15" },
        { 0, NULL }
};

/* Returns 0 on success, negative on error. */
int decode_gsm_rlcmac_uplink(bitvec * vector, RlcMacUplink_t * data)
{
  csnStream_t      ar;
  int ret;
  unsigned readIndex = 0;
  guint8 payload_type = bitvec_read_field(vector, &readIndex, 2);
  const char *msg_type_name;

  if (payload_type == PAYLOAD_TYPE_DATA)
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: DATA (0), not implemented\n");
    return CSN_ERROR_GENERAL;
  }
  else if (payload_type == PAYLOAD_TYPE_RESERVED)
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: RESERVED (3)\n");
    return CSN_ERROR_GENERAL;
  }

  data->NrOfBits = 23 * 8;
  csnStreamInit(&ar, 0, data->NrOfBits);
  readIndex += 6;
  data->u.MESSAGE_TYPE = bitvec_read_field(vector, &readIndex, 6);
  readIndex = 0;

  /* recursive csnStreamDecoder call uses LOGPC everywhere, so we need to start the log somewhere... */
  msg_type_name = get_value_string(rlcmac_ul_msg_names, data->u.MESSAGE_TYPE);
  LOGP(DCSN1, LOGL_INFO, "csnStreamDecoder (type: %s (%d)): ",
       msg_type_name, data->u.MESSAGE_TYPE);
  switch (data->u.MESSAGE_TYPE)
  {
    case MT_PACKET_CELL_CHANGE_FAILURE:
    {
      /*
       * data is the pointer to the unpack struct that hold the unpack value
       * CSNDESCR is an array that holds the different element types
       * ar is the csn context holding the bitcount, offset and output
       */
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Cell_Change_Failure_t), vector, &readIndex, &data->u.Packet_Cell_Change_Failure);
      break;
    }
    case MT_PACKET_CONTROL_ACK:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Control_Acknowledgement_t), vector, &readIndex, &data->u.Packet_Control_Acknowledgement);
      break;
    }
    case MT_PACKET_DOWNLINK_ACK_NACK:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Downlink_Ack_Nack_t), vector, &readIndex, &data->u.Packet_Downlink_Ack_Nack);
      break;
    }
    case MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Uplink_Dummy_Control_Block_t), vector, &readIndex, &data->u.Packet_Uplink_Dummy_Control_Block);
      break;
    }
    case MT_PACKET_MEASUREMENT_REPORT:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Measurement_Report_t), vector, &readIndex, &data->u.Packet_Measurement_Report);
      break;
    }
    case MT_PACKET_RESOURCE_REQUEST:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Resource_Request_t), vector, &readIndex, &data->u.Packet_Resource_Request);
      break;
    }

    case MT_PACKET_MOBILE_TBF_STATUS:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Mobile_TBF_Status_t), vector, &readIndex, &data->u.Packet_Mobile_TBF_Status);
      break;
    }
    case MT_PACKET_PSI_STATUS:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_PSI_Status_t), vector, &readIndex, &data->u.Packet_PSI_Status);
      break;
    }
    case MT_EGPRS_PACKET_DOWNLINK_ACK_NACK:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(EGPRS_PD_AckNack_t), vector, &readIndex, &data->u.Egprs_Packet_Downlink_Ack_Nack);
      break;
    }
    case MT_PACKET_PAUSE:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Pause_t), vector, &readIndex, &data->u.Packet_Pause);
      break;
    }
    case MT_PACKET_ENHANCED_MEASUREMENT_REPORT:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Enh_Measurement_Report_t), vector, &readIndex, &data->u.Packet_Enh_Measurement_Report);
      break;
    }
    case MT_ADDITIONAL_MS_RAC:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Additional_MS_Rad_Access_Cap_t), vector, &readIndex, &data->u.Additional_MS_Rad_Access_Cap);
      break;
    }
    case MT_PACKET_CELL_CHANGE_NOTIFICATION:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Cell_Change_Notification_t), vector, &readIndex, &data->u.Packet_Cell_Change_Notification);
      break;
    }
    case MT_PACKET_SI_STATUS:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_SI_Status_t), vector, &readIndex, &data->u.Packet_SI_Status);
      break;
    }
    default:
      ret = -1;
      break;
  }

  /* recursive csnStreamDecoder call uses LOGPC everywhere without trailing
     newline, so as a caller we are responisble for submitting it */
  LOGPC(DCSN1, LOGL_INFO, "\n");

  if (ret > 0) {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "%s: Got %d remaining bits unhandled by decoder at the end of bitvec\n", msg_type_name, ret);
    ret = 0;
  }

  return ret;
}

/* Returns 0 on success, negative on error. */
int decode_gsm_rlcmac_downlink(bitvec * vector, RlcMacDownlink_t * data)
{
  csnStream_t  ar;
  /* See RLC/MAC downlink control block structure in TS 44.060 / 10.3.1 */
  gint bit_offset = 0;
  gint bit_length;
  unsigned readIndex = 0;
  int ret;
  const char *msg_type_name;

  data->PAYLOAD_TYPE = bitvec_read_field(vector, &readIndex, 2);
  data->RRBP = bitvec_read_field(vector, &readIndex, 2);
  data->SP = bitvec_read_field(vector, &readIndex, 1);
  data->USF = bitvec_read_field(vector, &readIndex, 3);

  if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_DATA)
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: DATA (0), not implemented\n");
    return CSN_ERROR_GENERAL;
  }
  else if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_RESERVED)
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: RESERVED (3)\n");
    return CSN_ERROR_GENERAL;
  }
  /* We can decode the message */
  else
  {
    /* First print the message type and create a tree item */
    bit_offset = 8;
    if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_CTRL_OPT_OCTET)
    {
      data->RBSN = bitvec_read_field(vector, &readIndex, 1);
      data->RTI = bitvec_read_field(vector, &readIndex, 5);
      data->FS = bitvec_read_field(vector, &readIndex, 1);
      data->AC = bitvec_read_field(vector, &readIndex, 1);
      bit_offset += 8;
      if (data->AC == 1)
      {
	data->PR = bitvec_read_field(vector, &readIndex, 2);
	data->TFI = bitvec_read_field(vector, &readIndex, 5);
	data->D = bitvec_read_field(vector, &readIndex, 1);
        bit_offset += 8;
      }
      if ((data->RBSN == 1) && (data->FS == 0))
      {
	data->RBSNe = bitvec_read_field(vector, &readIndex, 3);
	data->FSe = bitvec_read_field(vector, &readIndex, 1);
	data->spare = bitvec_read_field(vector, &readIndex, 4);
        bit_offset += 8;
      }
    }
    data->u.MESSAGE_TYPE = bitvec_read_field(vector, &readIndex, 6);
  }

  /* Initialize the contexts */
  bit_length = 23*8 - bit_offset;
  data->NrOfBits = bit_length;
  readIndex = bit_offset;

  csnStreamInit(&ar, bit_offset, bit_length);

  /* recursive csnStreamDecoder call uses LOGPC everywhere, so we need to start the log somewhere... */
  msg_type_name = get_value_string(rlcmac_dl_msg_names, data->u.MESSAGE_TYPE);
  LOGP(DCSN1, LOGL_INFO, "csnStreamDecoder (type: %s (%d): ",
       msg_type_name, data->u.MESSAGE_TYPE);

  switch (data->u.MESSAGE_TYPE)
  {
    case MT_PACKET_ACCESS_REJECT:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Access_Reject_t), vector, &readIndex, &data->u.Packet_Access_Reject);
      break;
    }
    case MT_PACKET_CELL_CHANGE_ORDER:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Cell_Change_Order_t), vector, &readIndex, &data->u.Packet_Cell_Change_Order);
      break;
    }
    case MT_PACKET_CELL_CHANGE_CONTINUE:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Cell_Change_Continue_t), vector, &readIndex, &data->u.Packet_Cell_Change_Continue);
      break;
    }
    case MT_PACKET_DOWNLINK_ASSIGNMENT:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Downlink_Assignment_t), vector, &readIndex, &data->u.Packet_Downlink_Assignment);
      break;
    }
    case MT_PACKET_MEASUREMENT_ORDER:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Measurement_Order_t), vector, &readIndex, &data->u.Packet_Measurement_Order);
      break;
    }
    case MT_PACKET_NEIGHBOUR_CELL_DATA:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Neighbour_Cell_Data_t), vector, &readIndex, &data->u.Packet_Neighbour_Cell_Data);
      break;
    }
    case MT_PACKET_SERVING_CELL_DATA:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Serving_Cell_Data_t), vector, &readIndex, &data->u.Packet_Serving_Cell_Data);
      break;
    }
    case MT_PACKET_PAGING_REQUEST:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Paging_Request_t), vector, &readIndex, &data->u.Packet_Paging_Request);
      break;
    }
    case MT_PACKET_PDCH_RELEASE:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_PDCH_Release_t), vector, &readIndex, &data->u.Packet_PDCH_Release);
      break;
    }
    case MT_PACKET_POLLING_REQ:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Polling_Request_t), vector, &readIndex, &data->u.Packet_Polling_Request);
      break;
    }
    case MT_PACKET_POWER_CONTROL_TIMING_ADVANCE:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Power_Control_Timing_Advance_t), vector, &readIndex, &data->u.Packet_Power_Control_Timing_Advance);
      break;
    }
    case MT_PACKET_PRACH_PARAMETERS:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_PRACH_Parameters_t), vector, &readIndex, &data->u.Packet_PRACH_Parameters);
      break;
    }
    case MT_PACKET_QUEUEING_NOTIFICATION:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Queueing_Notification_t), vector, &readIndex, &data->u.Packet_Queueing_Notification);
      break;
    }
    case MT_PACKET_TIMESLOT_RECONFIGURE:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Timeslot_Reconfigure_t), vector, &readIndex, &data->u.Packet_Timeslot_Reconfigure);
      break;
    }
    case MT_PACKET_TBF_RELEASE:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_TBF_Release_t), vector, &readIndex, &data->u.Packet_TBF_Release);
      break;
    }
    case MT_PACKET_UPLINK_ACK_NACK:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Uplink_Ack_Nack_t), vector, &readIndex, &data->u.Packet_Uplink_Ack_Nack);
      break;
    }
    case MT_PACKET_UPLINK_ASSIGNMENT:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Uplink_Assignment_t), vector, &readIndex, &data->u.Packet_Uplink_Assignment);
      break;
    }
    case MT_PACKET_HANDOVER_COMMAND:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Handover_Command_t), vector, &readIndex, &data->u.Packet_Handover_Command);
      break;
    }
    case MT_PACKET_PHYSICAL_INFORMATION:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_PhysicalInformation_t), vector, &readIndex, &data->u.Packet_Handover_Command);
      break;
    }
    case MT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(Packet_Downlink_Dummy_Control_Block_t), vector, &readIndex, &data->u.Packet_Downlink_Dummy_Control_Block);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_1:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(PSI1_t), vector, &readIndex, &data->u.PSI1);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_2:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(PSI2_t), vector, &readIndex, &data->u.PSI2);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_3:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(PSI3_t), vector, &readIndex, &data->u.PSI3);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_5:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(PSI5_t), vector, &readIndex, &data->u.PSI5);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_13:
    {
      ret = csnStreamDecoder(&ar, CSNDESCR(PSI13_t), vector, &readIndex, &data->u.PSI13);
      break;
    }
    default:
      ret = CSN_ERROR_GENERAL;
      break;
  }

  /* recursive csnStreamDecoder call uses LOGPC everywhere without trailing
     newline, so as a caller we are responisble for submitting it */
  LOGPC(DCSN1, LOGL_INFO, "\n");

  if (ret > 0) {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "%s: Got %d remaining bits unhandled by decoder at the end of bitvec\n", msg_type_name, ret);
    ret = 0;
  }

  return ret;
}

/* Returns 0 on success, negative on error. */
int encode_gsm_rlcmac_uplink(bitvec * vector, RlcMacUplink_t * data)
{
  csnStream_t      ar;
  unsigned writeIndex = 0;
  int ret;
  const char *msg_type_name;

  data->NrOfBits = 23 * 8;
  csnStreamInit(&ar, 0, data->NrOfBits);
  writeIndex = 0;

  /* recursive csnStreamEncoder call uses LOGPC everywhere, so we need to start the log somewhere... */
  msg_type_name = get_value_string(rlcmac_ul_msg_names, data->u.MESSAGE_TYPE);
  LOGP(DCSN1, LOGL_INFO, "csnStreamEncoder (type: %s (%d)): ",
       msg_type_name, data->u.MESSAGE_TYPE);
  switch (data->u.MESSAGE_TYPE)
  {
    case MT_PACKET_CELL_CHANGE_FAILURE:
    {
      /*
       * data is the pointer to the unpack struct that hold the unpack value
       * CSNDESCR is an array that holds the different element types
       * ar is the csn context holding the bitcount, offset and output
       */
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Cell_Change_Failure_t), vector, &writeIndex, &data->u.Packet_Cell_Change_Failure);
      break;
    }
    case MT_PACKET_CONTROL_ACK:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Control_Acknowledgement_t), vector, &writeIndex, &data->u.Packet_Control_Acknowledgement);
      break;
    }
    case MT_PACKET_DOWNLINK_ACK_NACK:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Downlink_Ack_Nack_t), vector, &writeIndex, &data->u.Packet_Downlink_Ack_Nack);
      break;
    }
    case MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Uplink_Dummy_Control_Block_t), vector, &writeIndex, &data->u.Packet_Uplink_Dummy_Control_Block);
      break;
    }
    case MT_PACKET_MEASUREMENT_REPORT:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Measurement_Report_t), vector, &writeIndex, &data->u.Packet_Measurement_Report);
      break;
    }
    case MT_PACKET_RESOURCE_REQUEST:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Resource_Request_t), vector, &writeIndex, &data->u.Packet_Resource_Request);
      break;
    }

    case MT_PACKET_MOBILE_TBF_STATUS:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Mobile_TBF_Status_t), vector, &writeIndex, &data->u.Packet_Mobile_TBF_Status);
      break;
    }
    case MT_PACKET_PSI_STATUS:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_PSI_Status_t), vector, &writeIndex, &data->u.Packet_PSI_Status);
      break;
    }
    case MT_EGPRS_PACKET_DOWNLINK_ACK_NACK:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(EGPRS_PD_AckNack_t), vector, &writeIndex, &data->u.Egprs_Packet_Downlink_Ack_Nack);
      break;
    }
    case MT_PACKET_PAUSE:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Pause_t), vector, &writeIndex, &data->u.Packet_Pause);
      break;
    }
    case MT_PACKET_ENHANCED_MEASUREMENT_REPORT:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Enh_Measurement_Report_t), vector, &writeIndex, &data->u.Packet_Enh_Measurement_Report);
      break;
    }
    case MT_ADDITIONAL_MS_RAC:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Additional_MS_Rad_Access_Cap_t), vector, &writeIndex, &data->u.Additional_MS_Rad_Access_Cap);
      break;
    }
    case MT_PACKET_CELL_CHANGE_NOTIFICATION:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Cell_Change_Notification_t), vector, &writeIndex, &data->u.Packet_Cell_Change_Notification);
      break;
    }
    case MT_PACKET_SI_STATUS:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_SI_Status_t), vector, &writeIndex, &data->u.Packet_SI_Status);
      break;
    }
    default:
      ret = CSN_ERROR_GENERAL;
      break;
  }

  /* recursive csnStreamDecoder call uses LOGPC everywhere without trailing
     newline, so as a caller we are responisble for submitting it */
  LOGPC(DCSN1, LOGL_INFO, "\n");

  if (ret > 0 || ret == CSN_ERROR_NEED_MORE_BITS_TO_UNPACK) {
    LOGP(DRLCMACDATA, LOGL_ERROR, "Failed to encode an Uplink block: not enough bits "
                                  "in the output buffer (rc=%d)\n", ret);
    ret = CSN_ERROR_NEED_MORE_BITS_TO_UNPACK;
  }

  return ret;
}

/* Returns 0 on success, negative on error. */
int encode_gsm_rlcmac_downlink(bitvec * vector, RlcMacDownlink_t * data)
{
  csnStream_t  ar;
  int ret;
  const char *msg_type_name;
  /* See RLC/MAC downlink control block structure in TS 44.060 / 10.3.1 */
  gint bit_offset = 0;
  gint bit_length;
  unsigned writeIndex = 0;

  if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_DATA)
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: DATA (0), not implemented\n");
    return CSN_ERROR_GENERAL;
  }
  else if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_RESERVED)
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: RESERVED (3)\n");
    return CSN_ERROR_GENERAL;
  }
  /* We can decode the message */
  else
  {
    /* First print the message type and create a tree item */
    bitvec_write_field(vector, &writeIndex, data->PAYLOAD_TYPE, 2);
    bitvec_write_field(vector, &writeIndex, data->RRBP, 2);
    bitvec_write_field(vector, &writeIndex, data->SP, 1);
    bitvec_write_field(vector, &writeIndex, data->USF, 3);
    bit_offset = 8;
    if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_CTRL_OPT_OCTET)
    {
      bitvec_write_field(vector, &writeIndex, data->RBSN, 1);
      bitvec_write_field(vector, &writeIndex, data->RTI, 5);
      bitvec_write_field(vector, &writeIndex, data->FS, 1);
      bitvec_write_field(vector, &writeIndex, data->AC, 1);
      bit_offset += 8;
      if (data->AC == 1)
      {
	bitvec_write_field(vector, &writeIndex, data->PR, 2);
	bitvec_write_field(vector, &writeIndex, data->TFI, 5);
	bitvec_write_field(vector, &writeIndex, data->D, 1);
        bit_offset += 8;
      }
      if ((data->RBSN == 1) && (data->FS == 0))
      {
	bitvec_write_field(vector, &writeIndex, data->RBSNe, 3);
	bitvec_write_field(vector, &writeIndex, data->FSe, 1);
	bitvec_write_field(vector, &writeIndex, data->spare, 4);
        bit_offset += 8;
      }
    }
  }

  /* Initialize the contexts */
  bit_length = 23*8 - bit_offset;
  data->NrOfBits = bit_length;

  csnStreamInit(&ar, bit_offset, bit_length);


  /* recursive csnStreamEncoder call uses LOGPC everywhere, so we need to start the log somewhere... */
  msg_type_name = get_value_string(rlcmac_dl_msg_names, data->u.MESSAGE_TYPE);
  LOGP(DCSN1, LOGL_INFO, "csnStreamEncoder (type: %s (%d)): ",
       msg_type_name, data->u.MESSAGE_TYPE);
  switch (data->u.MESSAGE_TYPE)
  {
    case MT_PACKET_ACCESS_REJECT:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Access_Reject_t), vector, &writeIndex, &data->u.Packet_Access_Reject);
      break;
    }
    case MT_PACKET_CELL_CHANGE_ORDER:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Cell_Change_Order_t), vector, &writeIndex, &data->u.Packet_Cell_Change_Order);
      break;
    }
    case MT_PACKET_CELL_CHANGE_CONTINUE:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Cell_Change_Continue_t), vector, &writeIndex, &data->u.Packet_Cell_Change_Continue);
      break;
    }
    case MT_PACKET_DOWNLINK_ASSIGNMENT:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Downlink_Assignment_t), vector, &writeIndex, &data->u.Packet_Downlink_Assignment);
      break;
    }
    case MT_PACKET_MEASUREMENT_ORDER:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Measurement_Order_t), vector, &writeIndex, &data->u.Packet_Measurement_Order);
      break;
    }
    case MT_PACKET_NEIGHBOUR_CELL_DATA:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Neighbour_Cell_Data_t), vector, &writeIndex, &data->u.Packet_Neighbour_Cell_Data);
      break;
    }
    case MT_PACKET_SERVING_CELL_DATA:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Serving_Cell_Data_t), vector, &writeIndex, &data->u.Packet_Serving_Cell_Data);
      break;
    }
    case MT_PACKET_PAGING_REQUEST:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Paging_Request_t), vector, &writeIndex, &data->u.Packet_Paging_Request);
      break;
    }
    case MT_PACKET_PDCH_RELEASE:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_PDCH_Release_t), vector, &writeIndex, &data->u.Packet_PDCH_Release);
      break;
    }
    case MT_PACKET_POLLING_REQ:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Polling_Request_t), vector, &writeIndex, &data->u.Packet_Polling_Request);
      break;
    }
    case MT_PACKET_POWER_CONTROL_TIMING_ADVANCE:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Power_Control_Timing_Advance_t), vector, &writeIndex, &data->u.Packet_Power_Control_Timing_Advance);
      break;
    }
    case MT_PACKET_PRACH_PARAMETERS:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_PRACH_Parameters_t), vector, &writeIndex, &data->u.Packet_PRACH_Parameters);
      break;
    }
    case MT_PACKET_QUEUEING_NOTIFICATION:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Queueing_Notification_t), vector, &writeIndex, &data->u.Packet_Queueing_Notification);
      break;
    }
    case MT_PACKET_TIMESLOT_RECONFIGURE:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Timeslot_Reconfigure_t), vector, &writeIndex, &data->u.Packet_Timeslot_Reconfigure);
      break;
    }
    case MT_PACKET_TBF_RELEASE:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_TBF_Release_t), vector, &writeIndex, &data->u.Packet_TBF_Release);
      break;
    }
    case MT_PACKET_UPLINK_ACK_NACK:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Uplink_Ack_Nack_t), vector, &writeIndex, &data->u.Packet_Uplink_Ack_Nack);
      break;
    }
    case MT_PACKET_UPLINK_ASSIGNMENT:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Uplink_Assignment_t), vector, &writeIndex, &data->u.Packet_Uplink_Assignment);
      break;
    }
    case MT_PACKET_HANDOVER_COMMAND:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Handover_Command_t), vector, &writeIndex, &data->u.Packet_Handover_Command);
      break;
    }
    case MT_PACKET_PHYSICAL_INFORMATION:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_PhysicalInformation_t), vector, &writeIndex, &data->u.Packet_Handover_Command);
      break;
    }
    case MT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(Packet_Downlink_Dummy_Control_Block_t), vector, &writeIndex, &data->u.Packet_Downlink_Dummy_Control_Block);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_1:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(PSI1_t), vector, &writeIndex, &data->u.PSI1);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_2:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(PSI2_t), vector, &writeIndex, &data->u.PSI2);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_3:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(PSI3_t), vector, &writeIndex, &data->u.PSI3);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_5:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(PSI5_t), vector, &writeIndex, &data->u.PSI5);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_13:
    {
      ret = csnStreamEncoder(&ar, CSNDESCR(PSI13_t), vector, &writeIndex, &data->u.PSI13);
      break;
    }
    default:
      ret = -1;
      break;
  }

  /* recursive csnStreamDecoder call uses LOGPC everywhere without trailing
     newline, so as a caller we are responisble for submitting it */
  LOGPC(DCSN1, LOGL_INFO, "\n");

  if (ret > 0 || ret == CSN_ERROR_NEED_MORE_BITS_TO_UNPACK) {
    LOGP(DRLCMACDATA, LOGL_ERROR, "Failed to encode a Downlink block: not enough bits "
                                  "in the output buffer (rc=%d)\n", ret);
    ret = CSN_ERROR_NEED_MORE_BITS_TO_UNPACK;
  }

  return ret;
}

void decode_gsm_rlcmac_uplink_data(bitvec * vector, RlcMacUplinkDataBlock_t * data)
{
  unsigned readIndex = 0;
  //unsigned dataLen = 0;
  guint8 payload_type = bitvec_read_field(vector, &readIndex, 2);
  if (payload_type == PAYLOAD_TYPE_DATA)
  {
    readIndex = 0;
    // MAC header
    data->PAYLOAD_TYPE = bitvec_read_field(vector, &readIndex, 2);
    data->CV = bitvec_read_field(vector, &readIndex, 4);
    data->SI = bitvec_read_field(vector, &readIndex, 1);
    data->R = bitvec_read_field(vector, &readIndex, 1);
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "PAYLOAD_TYPE = %u ", (unsigned)(data->PAYLOAD_TYPE));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "CV = %u ", (unsigned)(data->CV));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "SI = %u ", (unsigned)(data->SI));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "R = %u ", (unsigned)(data->R));
    // Octet 1
    data->spare = bitvec_read_field(vector, &readIndex, 1);
    data->PI = bitvec_read_field(vector, &readIndex, 1);
    data->TFI = bitvec_read_field(vector, &readIndex, 5);
    data->TI = bitvec_read_field(vector, &readIndex, 1);
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "spare = %u ", (unsigned)(data->spare));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "PI = %u ", (unsigned)(data->PI));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "TFI = %u ", (unsigned)(data->TFI));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "TI = %u ", (unsigned)(data->TI));

    // Octet 2
    data->BSN = bitvec_read_field(vector, &readIndex, 7);
    data->E_1 = bitvec_read_field(vector, &readIndex, 1);
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "BSN = %u ", (unsigned)(data->BSN));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "E_1 = %u ", (unsigned)(data->E_1));


    if(data->E_1 == 0) // Extension octet follows immediately
    {
      // Octet 3 (optional)
      unsigned i = 0;
      do
      {
	data->LENGTH_INDICATOR[i] = bitvec_read_field(vector, &readIndex, 6);
	data->M[i] = bitvec_read_field(vector, &readIndex, 1);
	data->E[i] = bitvec_read_field(vector, &readIndex, 1);
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "LENGTH_INDICATOR[%u] = %u ", i, (unsigned)(data->LENGTH_INDICATOR[i]));
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "M[%u] = %u ", i, (unsigned)(data->M[i]));
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "E[%u] = %u ", i, (unsigned)(data->E[i]));
        i++;
      } while((data->M[i-1] == 1)&&(data->E[i-1] == 0));
    }
    if(data->TI == 1) // TLLI field is present
    {
      data->TLLI = bitvec_read_field(vector, &readIndex, 32);
      LOGPC(DRLCMACDATA, LOGL_NOTICE, "TLLI = %08x ", data->TLLI);
      if (data->PI == 1) // PFI is present if TI field indicates presence of TLLI
      {
	data->PFI = bitvec_read_field(vector, &readIndex, 7);
	data->E_2 = bitvec_read_field(vector, &readIndex, 1);
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "PFI = %u ", (unsigned)(data->PFI));
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "E_2 = %u ", (unsigned)(data->E_2));
      }
    }
    unsigned dataLen = 23 - readIndex/8;
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "DATA[%u] = ", dataLen);
    assert(dataLen <= 20);
    for (unsigned i = 0; i < dataLen; i++)
    {
      data->RLC_DATA[i] = bitvec_read_field(vector, &readIndex, 8);
      LOGPC(DRLCMACDATA, LOGL_NOTICE, "%02x", (unsigned)(data->RLC_DATA[i]));
    }
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "\n");
  }
  else
  {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "Payload Type: RESERVED (3)\n");
    return;
  }
}

void encode_gsm_rlcmac_downlink_data(bitvec * vector, RlcMacDownlinkDataBlock_t * data)
{
  unsigned writeIndex = 0;

  if (data->PAYLOAD_TYPE == PAYLOAD_TYPE_DATA)
  {
    // MAC header
    bitvec_write_field(vector, &writeIndex, data->PAYLOAD_TYPE, 2);
    bitvec_write_field(vector, &writeIndex, data->RRBP, 2);
    bitvec_write_field(vector, &writeIndex, data->SP, 1);
    bitvec_write_field(vector, &writeIndex, data->USF, 3);
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "PAYLOAD_TYPE = %u ", (unsigned)(data->PAYLOAD_TYPE));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "RRBP = %u ", (unsigned)(data->RRBP));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "SP = %u ", (unsigned)(data->SP));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "USF = %u ", (unsigned)(data->USF));

    // Octet 1
    bitvec_write_field(vector, &writeIndex, data->PR, 2);
    bitvec_write_field(vector, &writeIndex, data->TFI, 5);
    bitvec_write_field(vector, &writeIndex, data->FBI, 1);
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "PR = %u ", (unsigned)(data->PR));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "TFI = %u ", (unsigned)(data->TFI));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "FBI = %u ", (unsigned)(data->FBI));

    // Octet 2
    bitvec_write_field(vector, &writeIndex, data->BSN, 7);
    bitvec_write_field(vector, &writeIndex, data->E_1, 1);
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "BSN = %u ", (unsigned)(data->BSN));
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "E_1 = %u ", (unsigned)(data->E_1));

    // Octet 3 (optional)
    if(data->E_1 == 0)
    {
      unsigned i = 0;
      do
      {
	bitvec_write_field(vector, &writeIndex, data->LENGTH_INDICATOR[i], 6);
	bitvec_write_field(vector, &writeIndex, data->M[i], 1);
	bitvec_write_field(vector, &writeIndex, data->E[i], 1);
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "LENGTH_INDICATOR[%u] = %u ", i, (unsigned)(data->LENGTH_INDICATOR[i]));
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "M[%u] = %u ", i, (unsigned)(data->M[i]));
        LOGPC(DRLCMACDATA, LOGL_NOTICE, "E[%u] = %u ", i, (unsigned)(data->E[i]));
        i++;
      }
      while ((data->M[i-1] == 1) && (data->E[i-1] == 0));
    }
    unsigned dataNumOctets = 23 - writeIndex/8;
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "DATA[%u] = ", dataNumOctets);
    assert(dataNumOctets <= 20);
    for (unsigned i = 0; i < dataNumOctets; i++)
    {
      bitvec_write_field(vector, &writeIndex, data->RLC_DATA[i], 8);
      LOGPC(DRLCMACDATA, LOGL_NOTICE, "%02x", (unsigned)(data->RLC_DATA[i]));
    }
    LOGPC(DRLCMACDATA, LOGL_NOTICE, "\n");
  }
}

int decode_gsm_ra_cap(bitvec * vector, MS_Radio_Access_capability_t *data)
{
  csnStream_t      ar;
  int ret;
  unsigned readIndex = 0;

  csnStreamInit(&ar, 0, 8 * vector->data_len);

  /* recursive csnStreamEncoder call uses LOGPC everywhere, so we need to start the log somewhere... */
  LOGP(DCSN1, LOGL_INFO, "csnStreamDecoder (RAcap): ");
  ret = csnStreamDecoder(&ar, CSNDESCR(MS_Radio_Access_capability_t), vector, &readIndex, data);

  /* recursive csnStreamDecoder call uses LOGPC everywhere without trailing
     newline, so as a caller we are responisble for submitting it */
  LOGPC(DCSN1, LOGL_INFO, "\n");

  if (ret > 0) {
    LOGP(DRLCMACDATA, LOGL_NOTICE, "RAcap: Got %d remaining bits unhandled by decoder at the end of bitvec\n", ret);
    ret = 0;
  }
  return ret;
}

/* This function is not actually used by osmo-pcu itself, and only needed for
 * the RLCMAC unit test. Having it here is better than making the internal
 * CSN.1 definitions (in particular, MS_Radio_Access_capability_t) non-static. */
int encode_gsm_ra_cap(bitvec *vector, MS_Radio_Access_capability_t *data)
{
  unsigned writeIndex = 0;
  csnStream_t ar;
  int ret;

  csnStreamInit(&ar, 0, vector->data_len * 8);

  /* recursive csnStreamEncoder call uses LOGPC everywhere, so we need to start the log somewhere... */
  LOGP(DCSN1, LOGL_INFO, "csnStreamEncoder (RAcap): ");
  ret = csnStreamEncoder(&ar, CSNDESCR(MS_Radio_Access_capability_t), vector, &writeIndex, data);
  LOGPC(DCSN1, LOGL_INFO, "\n");

  if (ret > 0 || ret == CSN_ERROR_NEED_MORE_BITS_TO_UNPACK) {
    LOGP(DRLCMACDATA, LOGL_ERROR, "Failed to encode MS RA Capability IE: not enough bits "
                                  "in the output buffer (rc=%d)\n", ret);
    ret = CSN_ERROR_NEED_MORE_BITS_TO_UNPACK;
  }

  return ret;
}
