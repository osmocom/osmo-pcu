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
#include "csn1.h"
#include "gsm_rlcmac.h"
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

void testRlcMacDownlink()
{
	BitVector resultVector(23*8);
	resultVector.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	std::string testData[] = {
	"4e082500e3f1a81d080820800b2b2b2b2b2b2b2b2b2b2b", // Packet Downlink Assignment
	"48282407a6a074227201000b2b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Assignment
	"47240c00400000000000000079eb2ac9402b2b2b2b2b2b", // Packet Uplink Ack Nack
	"47283c367513ba333004242b2b2b2b2b2b2b2b2b2b2b2b"  // Packet Uplink Assignment
	};

	int testDataSize = sizeof(testData)/sizeof(testData[0]);
	BitVector vector[testDataSize];

	unsigned char origin[23];
	unsigned char result[23];

	cout << " DOWNLINK " << endl;
	for (int i = 0; i < testDataSize; i++)
	{
		vector[i].resize(23*8);
		vector[i].unhex(testData[i].c_str());
		RlcMacDownlink_t * data = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
		cout << "=========Start DECODE===========" << endl;
		decode_gsm_rlcmac_downlink(&vector[i], data);
		cout << "+++++++++Finish DECODE++++++++++" << endl;
		cout << "=========Start ENCODE=============" << endl;
		encode_gsm_rlcmac_downlink(&resultVector, data);
		cout << "+++++++++Finish ENCODE+++++++++++" << endl;
		cout << "vector1 = " <<  vector[i] << endl;
		cout << "vector2 = " <<  resultVector << endl;
		vector[i].pack(origin);
		resultVector.pack(result);
		if (memcmp(origin, result, 23) == 0)
		{
			cout << "vector1 == vector2 : TRUE" << endl;
		}
		else
		{
			cout << "vector1 == vector2 : FALSE" << endl;
		}
		resultVector.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
		free(data);
	}
}


void testRlcMacUplink()
{
	BitVector resultVector(23*8);
	resultVector.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	std::string testData[] = {
	"400e1e61d11f2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // Packet Uplink Dummy Control Block
	"400b8020000000000000002480e00b2b2b2b2b2b2b2b2b", // Packet Downlink Ack/Nack
	"4016713dc094270ca2ae57ef909006aa0fc0001f80222b"  // Packet Resource Request
	};

	int testDataSize = sizeof(testData)/sizeof(testData[0]);
	BitVector vector[testDataSize];

	unsigned char origin[23];
	unsigned char result[23];

	cout << " UPLINK " << endl;
	for (int i = 0; i < testDataSize; i++)
	{
		vector[i].resize(23*8);
		vector[i].unhex(testData[i].c_str());
		RlcMacUplink_t * data = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
		cout << "=========Start DECODE===========" << endl;
		decode_gsm_rlcmac_uplink(&vector[i], data);
		cout << "+++++++++Finish DECODE++++++++++" << endl;
		cout << "=========Start ENCODE=============" << endl;
		encode_gsm_rlcmac_uplink(&resultVector, data);
		cout << "+++++++++Finish ENCODE+++++++++++" << endl;
		cout << "vector1 = " <<  vector[i] << endl;
		cout << "vector2 = " <<  resultVector << endl;
		vector[i].pack(origin);
		resultVector.pack(result);
		if (memcmp(origin, result, 23) == 0)
		{
			cout << "vector1 == vector2 : TRUE" << endl;
		}
		else
		{
			cout << "vector1 == vector2 : FALSE" << endl;
		}
		resultVector.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
		free(data);
	}
}

int main(int argc, char *argv[])
{
	//printSizeofRLCMAC();
	testRlcMacDownlink();
	testRlcMacUplink();

}
