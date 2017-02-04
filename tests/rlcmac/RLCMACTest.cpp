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
#include "csn1.h"
#include "gsm_rlcmac.h"
extern "C" {
extern const struct log_info gprs_log_info;
#include "pcu_vty.h"
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
}
using namespace std;

void printSizeofRLCMAC()
{
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
	cout << "sizeof Packet_Measurement_Order_Reduced_t     " << sizeof(Packet_Measurement_Order_Reduced_t) << endl;
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
	struct bitvec *resultVector = bitvec_alloc(23, test_ctx);
	bitvec_unhex(resultVector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	std::string testData[] = {
	"4e082500e3f1a81d080820800b2b2b2b2b2b2b2b2b2b2b", // Packet Downlink Assignment
	"48282407a6a07422720100032b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Assignment
	"47240c00400000000000000079eb2ac9402b2b2b2b2b2b", // Packet Uplink Ack Nack
	"47283c367513ba333004242b2b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Assignment
	"400820001a3904df0680efb3300b2b2b2b2b2b2b2b2b2b", // Packet Downlink Assignment (EGPRS)
	"40284f0000001009810c826f4406809dcecb2b2b2b2b2b", // Packet Uplink Assignment (EGPRS)
	"4024030f2f0000000087b0042b2b2b2b2b2b2b2b2b2b2b"  // Packet Uplink Ack Nack (EGPRS)
	"4913e00850884013a8048b2b2b2b2b2b2b2b2b2b2b2b2b"
	"412430007fffffffffffffffefd19c7ba12b2b2b2b2b2b"
	"41942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	};

	int testDataSize = sizeof(testData)/sizeof(testData[0]);

	cout << " DOWNLINK " << endl;
	for (int i = 0; i < testDataSize; i++)
	{
		bitvec *vector = bitvec_alloc(23, test_ctx);
		bitvec_unhex(vector, testData[i].c_str());
		cout << "vector1 = ";
		for (int i = 0; i < 23; i++)
		{
			cout << hex << (unsigned)*(vector->data + i);
		}
		cout << endl;
		RlcMacDownlink_t * data = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
		cout << "=========Start DECODE===========" << endl;
		decode_gsm_rlcmac_downlink(vector, data);
		cout << "+++++++++Finish DECODE++++++++++" << endl;
		cout << "=========Start ENCODE=============" << endl;
		encode_gsm_rlcmac_downlink(resultVector, data);
		cout << "+++++++++Finish ENCODE+++++++++++" << endl;
		cout << "vector1 = ";
		for (int i = 0; i < 23; i++)
		{
			cout << (unsigned)*(vector->data + i);
		}
		cout << endl;
		cout << "vector2 = ";
		for (int i = 0; i < 23; i++)
		{
			cout << (unsigned)*(resultVector->data + i);
		}
		cout << endl;
		if (memcmp(vector->data, resultVector->data, 23) == 0)
		{
			cout << "vector1 == vector2 : TRUE" << endl;
		}
		else
		{
			cout << "vector1 == vector2 : FALSE" << endl;
		}
		bitvec_unhex(resultVector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
		bitvec_free(vector);
		free(data);
	}

	bitvec_free(resultVector);
}


void testRlcMacUplink(void *test_ctx)
{
	struct bitvec *resultVector = bitvec_alloc(23, test_ctx);
	bitvec_unhex(resultVector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	std::string testData[] = {
	"400e1e61d11d2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Dummy Control Block
	"400b8020000000000000002480e0032b2b2b2b2b2b2b2b", // Packet Downlink Ack/Nack
	"4016713dc094270ca2ae57ef909006aa0fc0001f80222b", // Packet Resource Request
	"40200ffc0021ec010b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // EPDAN
	"400a9020000000000000003010012a0800132b2b2b2b2b"
	};

	int testDataSize = sizeof(testData)/sizeof(testData[0]);


	cout << " UPLINK " << endl;
	for (int i = 0; i < testDataSize; i++)
	{
		bitvec *vector = bitvec_alloc(23, test_ctx);
		bitvec_unhex(vector, testData[i].c_str());
		cout << "vector1 = ";
		for (int i = 0; i < 23; i++)
		{
			cout << hex << (unsigned)*(vector->data + i);
		}
		cout << endl;
		RlcMacUplink_t * data = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
		cout << "=========Start DECODE===========" << endl;
		decode_gsm_rlcmac_uplink(vector, data);
		cout << "+++++++++Finish DECODE++++++++++" << endl;
		cout << "=========Start ENCODE=============" << endl;
		encode_gsm_rlcmac_uplink(resultVector, data);
		cout << "+++++++++Finish ENCODE+++++++++++" << endl;
		cout << "vector1 = ";
		for (int i = 0; i < 23; i++)
		{
			cout << (unsigned)*(vector->data + i);
		}
		cout << endl;
		cout << "vector2 = ";
		for (int i = 0; i < 23; i++)
		{
			cout << (unsigned)*(resultVector->data + i);
		}
		cout << endl;
		if (memcmp(vector->data, resultVector->data, 23) == 0)
		{
			cout << "vector1 == vector2 : TRUE" << endl;
		}
		else
		{
			cout << "vector1 == vector2 : FALSE" << endl;
		}
		bitvec_unhex(resultVector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
		bitvec_free(vector);
		free(data);
	}

	bitvec_free(resultVector);
}

void testCsnLeftAlignedVarBmpBounds(void *test_ctx)
{
	bitvec *vector = bitvec_alloc(23, test_ctx);

	bitvec_unhex(vector, "40200bffd161003e0e519ffffffb800000000000000000");
	RlcMacUplink_t data;

	EGPRS_AckNack_Desc_t *urbb =
		&data.u.Egprs_Packet_Downlink_Ack_Nack.EGPRS_AckNack.Desc;
	decode_gsm_rlcmac_uplink(vector, &data);

	OSMO_ASSERT(!strcmp(osmo_hexdump(urbb->URBB, 13),
			    "7f ff ff ee 00 00 00 00 00 00 00 00 00 "));
}

int main(int argc, char *argv[])
{
	void *ctx = talloc_named_const(NULL, 1, "RLCMACTest");
	osmo_init_logging(&gprs_log_info);

	//printSizeofRLCMAC();
	testRlcMacDownlink(ctx);
	testRlcMacUplink(ctx);
	testCsnLeftAlignedVarBmpBounds(ctx);
	talloc_free(ctx);
}
