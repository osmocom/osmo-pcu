/* RLCMACTest.cpp
 *
 * Copyright (C) 2011 Ivan Klyuchnikov
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



//#include <BitVector.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <assert.h>
#include "csn1.h"
#include "gsm_rlcmac.h"
#include "gprs_rlcmac.h"
#include "decoding.h"

extern "C" {
extern const struct log_info gprs_log_info;
#include "pcu_vty.h"
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
}
using namespace std;

void *tall_pcu_ctx;

void printSizeofRLCMAC()
{
	printf("*** %s ***\n", __func__);
	cout << "sizeof RlcMacUplink_t                       " << sizeof(RlcMacUplink_t) << endl;
	cout << "sizeof Packet_Cell_Change_Failure_t         " << sizeof(Packet_Cell_Change_Failure_t) << endl;
	cout << "sizeof Packet_Control_Acknowledgement_t     " << sizeof(Packet_Control_Acknowledgement_t) << endl;
	cout << "sizeof Packet_Downlink_Ack_Nack_t           " << sizeof(Packet_Downlink_Ack_Nack_t) << endl;
	cout << "sizeof EGPRS_PD_AckNack_t		     " << sizeof(EGPRS_PD_AckNack_t) << endl;
	cout << "sizeof Packet_Uplink_Dummy_Control_Block_t  " << sizeof(Packet_Uplink_Dummy_Control_Block_t) << endl;
	cout << "sizeof Packet_Measurement_Report_t          " << sizeof(Packet_Measurement_Report_t) << endl;
	cout << "sizeof Packet_Resource_Request_t            " << sizeof(Packet_Resource_Request_t) << endl;
	cout << "sizeof Packet_Mobile_TBF_Status_t           " << sizeof(Packet_Mobile_TBF_Status_t) << endl;
	cout << "sizeof Packet_PSI_Status_t                  " << sizeof(Packet_PSI_Status_t) << endl;
	cout << "sizeof Packet_Enh_Measurement_Report_t      " << sizeof(Packet_Enh_Measurement_Report_t) << endl;
	cout << "sizeof Packet_Cell_Change_Notification_t    " << sizeof(Packet_Cell_Change_Notification_t) << endl;
	cout << "sizeof Packet_SI_Status_t                   " << sizeof(Packet_SI_Status_t) << endl;
	cout << "sizeof Additional_MS_Rad_Access_Cap_t       " << sizeof(Additional_MS_Rad_Access_Cap_t) << endl;
	cout << "sizeof Packet_Pause_t                       " << sizeof(Packet_Pause_t) << endl;

	cout << "sizeof RlcMacDownlink_t                       " << sizeof(RlcMacDownlink_t) << endl;
	cout << "sizeof Packet_Access_Reject_t                 " << sizeof(Packet_Access_Reject_t) << endl;
	cout << "sizeof Packet_Cell_Change_Order_t             " << sizeof(Packet_Cell_Change_Order_t) << endl;
	cout << "sizeof Packet_Downlink_Assignment_t           " << sizeof(Packet_Downlink_Assignment_t) << endl;
	cout << "sizeof Packet_Neighbour_Cell_Data_t           " << sizeof(Packet_Neighbour_Cell_Data_t) << endl;
	cout << "sizeof Packet_Serving_Cell_Data_t             " << sizeof(Packet_Serving_Cell_Data_t) << endl;
	cout << "sizeof Packet_Paging_Request_t                " << sizeof(Packet_Paging_Request_t) << endl;
	cout << "sizeof Packet_PDCH_Release_t                  " << sizeof(Packet_PDCH_Release_t) << endl;
	cout << "sizeof Packet_Polling_Request_t               " << sizeof(Packet_Polling_Request_t) << endl;
	cout << "sizeof Packet_Power_Control_Timing_Advance_t  " << sizeof(Packet_Power_Control_Timing_Advance_t) << endl;
	cout << "sizeof Packet_PRACH_Parameters_t              " << sizeof(Packet_PRACH_Parameters_t) << endl;
	cout << "sizeof Packet_Queueing_Notification_t         " << sizeof(Packet_Queueing_Notification_t) << endl;
	cout << "sizeof Packet_Timeslot_Reconfigure_t          " << sizeof(Packet_Timeslot_Reconfigure_t) << endl;
	cout << "sizeof Packet_TBF_Release_t                   " << sizeof(Packet_TBF_Release_t) << endl;
	cout << "sizeof Packet_Uplink_Ack_Nack_t               " << sizeof(Packet_Uplink_Ack_Nack_t) << endl;
	cout << "sizeof Packet_Uplink_Assignment_t             " << sizeof(Packet_Uplink_Assignment_t) << endl;
	cout << "sizeof Packet_Cell_Change_Continue_t          " << sizeof(Packet_Cell_Change_Continue_t) << endl;
	cout << "sizeof Packet_Handover_Command_t              " << sizeof(Packet_Handover_Command_t) << endl;
	cout << "sizeof Packet_PhysicalInformation_t           " << sizeof(Packet_PhysicalInformation_t) << endl;
	cout << "sizeof Packet_Downlink_Dummy_Control_Block_t  " << sizeof(Packet_Downlink_Dummy_Control_Block_t) << endl;
	cout << "sizeof PSI1_t                " << sizeof(PSI1_t) << endl;
	cout << "sizeof PSI2_t                " << sizeof(PSI2_t) << endl;
	cout << "sizeof PSI3_t                " << sizeof(PSI3_t) << endl;
	cout << "sizeof PSI3_BIS_t            " << sizeof(PSI3_BIS_t) << endl;
	cout << "sizeof PSI4_t                " << sizeof(PSI4_t) << endl;
	cout << "sizeof PSI13_t               " << sizeof(PSI13_t) << endl;
	cout << "sizeof PSI5_t                " << sizeof(PSI5_t) << endl;
}

void testRlcMacDownlink(void *test_ctx)
{
	printf("*** %s ***\n", __func__);

	int rc;
	struct bitvec *resultVector = bitvec_alloc(23, test_ctx);
	bitvec_unhex(resultVector, DUMMY_VEC);

	std::string testData[] = {
	"4e082500e3f1a81d080820800b2b2b2b2b2b2b2b2b2b2b", // Packet Downlink Assignment
	"48282407a6a07422720100032b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Assignment
	"47240c00400000000000000079eb2ac9402b2b2b2b2b2b", // Packet Uplink Ack Nack
	"47283c367513ba333004242b2b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Assignment
	"400820001a3904df0680efb3300b2b2b2b2b2b2b2b2b2b", // Packet Downlink Assignment (EGPRS)
	"40284f0000001009810c826f4406809dcecb2b2b2b2b2b", // Packet Uplink Assignment (EGPRS)
	"4024030f2f0000000087b0042b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Ack Nack (EGPRS)
	"4913e00850884013a8048b2b2b2b2b2b2b2b2b2b2b2b2b", // Polling Request (malformed)
	"412430007fffffffffffffffefd19c7ba12b2b2b2b2b2b", // Packet Uplink Ack Nack?
	"41942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // System Info 13?
	};

	int testDataSize = sizeof(testData)/sizeof(testData[0]);

	cout << " DOWNLINK " << endl;
	for (int i = 0; i < testDataSize; i++)
	{
		cout << "vector1 = " << testData[i] << endl;
		bitvec *vector = bitvec_alloc(23, test_ctx);
		bitvec_unhex(vector, testData[i].c_str());

		RlcMacDownlink_t data;
		memset(&data, 0, sizeof(data));
		cout << "=========Start DECODE===========" << endl;
		rc = decode_gsm_rlcmac_downlink(vector, &data);
		cout << "+++++++++Finish DECODE ("<< rc <<")++++++++++" << endl;
		cout << "=========Start ENCODE=============" << endl;
		rc = encode_gsm_rlcmac_downlink(resultVector, &data);
		cout << "+++++++++Finish ENCODE ("<< rc <<")+++++++++++" << endl;
		cout << "vector1 = " << osmo_hexdump(vector->data, 23) << endl;
		cout << "vector2 = " << osmo_hexdump(resultVector->data, 23) << endl;
		if (memcmp(vector->data, resultVector->data, 23) == 0)
			cout << "vector1 == vector2 : TRUE" << endl;
		else
			cout << "vector1 == vector2 : FALSE" << endl;
		bitvec_unhex(resultVector, DUMMY_VEC);
		bitvec_free(vector);
	}

	bitvec_free(resultVector);
}


void testRlcMacUplink(void *test_ctx)
{
	printf("*** %s ***\n", __func__);

	int rc;
	struct bitvec *resultVector = bitvec_alloc(23, test_ctx);
	bitvec_unhex(resultVector, DUMMY_VEC);

	std::string testData[] = {
	"400e1e61d11d2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Dummy Control Block
	"400b8020000000000000002480e0032b2b2b2b2b2b2b2b", // Packet Downlink Ack/Nack
	"4016713dc094270ca2ae57ef909006aa0fc0001f80222b", // Packet Resource Request
	"40200ffc0021ec010b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // EPDAN
	"400a9020000000000000003010012a0800132b2b2b2b2b", // Packet Downlink Ack/Nack ?
	};

	int testDataSize = sizeof(testData)/sizeof(testData[0]);


	cout << " UPLINK " << endl;
	for (int i = 0; i < testDataSize; i++)
	{
		cout << "vector1 = " << testData[i] << endl;
		bitvec *vector = bitvec_alloc(23, test_ctx);
		bitvec_unhex(vector, testData[i].c_str());

		RlcMacUplink_t data;
		memset(&data, 0, sizeof(data));
		cout << "=========Start DECODE===========" << endl;
		rc = decode_gsm_rlcmac_uplink(vector, &data);
		cout << "+++++++++Finish DECODE ("<< rc << ")++++++++++" << endl;
		cout << "=========Start ENCODE=============" << endl;
		rc = encode_gsm_rlcmac_uplink(resultVector, &data);
		cout << "+++++++++Finish ENCODE ("<< rc <<")+++++++++++" << endl;
		cout << "vector1 = " << osmo_hexdump(vector->data, 23) << endl;
		cout << "vector2 = " << osmo_hexdump(resultVector->data, 23) << endl;
		if (memcmp(vector->data, resultVector->data, 23) == 0)
			cout << "vector1 == vector2 : TRUE" << endl;
		else
			cout << "vector1 == vector2 : FALSE" << endl;
		bitvec_unhex(resultVector, DUMMY_VEC);
		bitvec_free(vector);
	}

	bitvec_free(resultVector);
}

void testCsnLeftAlignedVarBmpBounds(void *test_ctx)
{
	printf("*** %s ***\n", __func__);

	struct msgb *m = msgb_alloc(80, "test");
	static uint8_t exp[] = { 0x7f, 0xff, 0xff, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	bitvec *vector = bitvec_alloc(23, test_ctx);
	int rc;

	bitvec_unhex(vector, "40200bffd161003e0e519ffffffb800000000000000000");
	RlcMacUplink_t data;
	memset(&data, 0, sizeof(data));

	EGPRS_AckNack_Desc_t *urbb =
		&data.u.Egprs_Packet_Downlink_Ack_Nack.EGPRS_AckNack.Desc;
	rc = decode_gsm_rlcmac_uplink(vector, &data);
	OSMO_ASSERT(rc == 0);

	memcpy(msgb_put(m, 13), urbb->URBB, 13);
	if (!msgb_eq_data_print(m, exp, 13))
		printf("%s failed!\n", __func__);
	msgb_free(m);
}

void testRAcap(void *test_ctx)
{
	printf("*** %s ***\n", __func__);
	MS_Radio_Access_capability_t data;
	memset(&data, 0, sizeof(data));
	bitvec *vector = bitvec_alloc(23, test_ctx);
	int rc;
/*
	MS RA capability 1
	    0001 .... = Access Technology Type: GSM E --note that GSM E covers GSM P (1)
	    .... 0010  101. .... = Length in bits: 0x15 (21)
	    ...0 01.. RF Power Capability, GMSK Power Class: Not specified (1)
	    A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
	    .... ...1 = Controlled early Classmark Sending: Implemented
	    0... .... = Pseudo Synchronisation: Not Present
	    .0.. .... = Voice Group Call Service: no VGCS capability or no notifications wanted
	    ..0. .... = Voice Broadcast Service: no VBS capability or no notifications wanted
	    ...1 .... = Multislot capability struct: Present
	    .... ..00  011. .... = GPRS multislot class: Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1 (3)
	    ...0 .... = GPRS Extended Dynamic Allocation Capability: Not Implemented
*/
	bitvec_unhex(vector, "12a5146200");

	rc = decode_gsm_ra_cap(vector, &data);
	printf("decode_gsm_ra_cap fails? %s\n", rc !=0 ? "yes" : "no");
#if 0
	/* FIXME: OS#1525, OS#3499: csn1 fails to parse this MS RA Cap IE value */
	assert (rc == 0);

	/* Make sure there's 1 value (currently fails due to failed decoding) */
	osmo_assert(cap->Count_MS_RA_capability_value == 1);

	/* Make sure MS multislot class is parsed correctly (currently fails due
	   to failed decoding and count being 0) */
	uint8_t ms_class = Decoding::get_ms_class_by_capability(&data);
	assert(ms_class == 3);
#endif
}

int main(int argc, char *argv[])
{
	void *ctx = talloc_named_const(NULL, 1, "RLCMACTest");
	osmo_init_logging2(ctx, &gprs_log_info);
	log_parse_category_mask(osmo_stderr_target, "DPCU,3:DLGLOBAL,1:");

	//printSizeofRLCMAC();
	testRlcMacDownlink(ctx);
	testRlcMacUplink(ctx);
	testCsnLeftAlignedVarBmpBounds(ctx);
	testRAcap(ctx);
	talloc_free(ctx);
}
