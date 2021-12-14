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
 */



//#include <BitVector.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <assert.h>
#include "gprs_rlcmac.h"
#include "decoding.h"

extern "C" {
#include "pcu_vty.h"
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

#include "csn1.h"
#include "gsm_rlcmac.h"
}
using namespace std;

#include "gprs_debug.h"

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
	"40883c1493120000000012002b2b2b2b2b2b2b2b2b2b2b", // Pkt Paging Request (OS#4838)
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
	"401673c87f24af2632b25964200600000091000b780080", // Packet Resource Request (from keith)
	"40200ffc0021ec010b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", // EPDAN
	"400a9020000000000000003010012a0800132b2b2b2b2b", // Packet Downlink Ack/Nack ?

	/* Packet Resource Request (see OS#4955, mistakes in 3GPP TS 44.060) */
	"4117ea1b903eaeb2686564b2330820078000102b2b2b2b",
	"40167e49f7f8ef2632b2596620060000806d00541c0080",
	"4017787174d92eba686564b2ccc30800a000040b2b2b2b",
	"4017e5b2cd5a2eca68655e44aec84880139300412b2b2b",
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

extern "C" {
int encode_gsm_ra_cap(struct bitvec *vector, MS_Radio_Access_capability_t * data);
}

void testRAcap(void *test_ctx)
{
        printf("*** %s ***\n", __func__);
        MS_Radio_Access_capability_t data;
        memset(&data, 0, sizeof(data));
        bitvec *bv_dec = bitvec_alloc(23, test_ctx);
        bitvec *bv_enc = bitvec_alloc(23, test_ctx);
        unsigned int len_dec, len_enc;
        int rc;
/*
MS RA capability 1
    0001 .... = Access Technology Type: GSM E --note that GSM E covers GSM P (1)
    .... 0011  011. .... = Length in bits: 0x1b (27)
    ...0 01.. RF Power Capability, GMSK Power Class: Not specified (1)
    A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
    .... ...1 = Controlled early Classmark Sending: Implemented
    0... .... = Pseudo Synchronisation: Not Present
    .0.. .... = Voice Group Call Service: no VGCS capability or no notifications wanted
    ..0. .... = Voice Broadcast Service: no VBS capability or no notifications wanted
    ...1 .... = Multislot capability struct: Present
        HSCSD multislot class: Bits are not available (0)
        SMS_VALUE (Switch-Measure-Switch): Bits are not available (0)
        ECSD multislot class: Bits are not available (0)
        DTM GPRS Multi Slot Class: Bits are not available (0)
    .... ..00  011. .... = GPRS multislot class: Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1 (3)
    ...0 .... = GPRS Extended Dynamic Allocation Capability: Not Implemented
    .... ...0  0011 .... = EGPRS multislot class: Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1 (3)
    .... 0... = EGPRS Extended Dynamic Allocation Capability: Not Implemented
*/
        bitvec_unhex(bv_dec, "1365146230");

        printf("=== Test decoding of MS RA Capability ===\n");
        rc = decode_gsm_ra_cap(bv_dec, &data);
        OSMO_ASSERT(rc == 0);

        /* Make sure there's 1 value (currently fails due to failed decoding) */
        OSMO_ASSERT(data.Count_MS_RA_capability_value == 1);

        /* Make sure GPRS / EGPRS multislot class is parsed correctly */
        printf("GPRS multislot class = %u\n", get_ms_class_by_capability(&data));
        printf("EGPRS multislot class = %u\n", get_egprs_ms_class_by_capability(&data));

        /* Test encoding of decoded MS RA Capability */
        printf("=== Test encoding of MS RA Capability ===\n");
        rc = encode_gsm_ra_cap(bv_enc, &data);
        printf("encode_gsm_ra_cap() returns %d\n", rc);

        bv_dec->cur_bit = 4;
        len_dec = bitvec_get_uint(bv_dec, 7);
        bv_enc->cur_bit = 4;
        len_enc = bitvec_get_uint(bv_enc, 7);

        /* NOTE: vector2 is expected to be different because there is actually no
         * way to distinguish between NULL and 0 in MS_Radio_Access_capability_t.
         * The difference is in length indicator: 27 bits vs 65 bits. */
        printf("vector1 (len_ind=%u) = %s\n", len_dec, osmo_hexdump(bv_dec->data, bv_dec->data_len));
        printf("vector2 (len_ind=%u) = %s\n", len_enc, osmo_hexdump(bv_enc->data, bv_enc->data_len));

        /* Mangle the length indicator (set it to 21) */
        unsigned int writeIndex = 4;
        rc = bitvec_write_field(bv_dec, &writeIndex, 21, 7);
        OSMO_ASSERT(rc == 0);

        /* Make sure decoding attempt fails */
        printf("=== Test decoding of a malformed vector (short length indicator) ===\n");
        rc = decode_gsm_ra_cap(bv_dec, &data);
        printf("decode_gsm_ra_cap() returns %d\n", rc);
}

void testMalformedRAcap(void *test_ctx)
{
	printf("*** %s ***\n", __func__);
	MS_Radio_Access_capability_t data;
	memset(&data, 0, sizeof(data));
	bitvec *bv_dec = bitvec_alloc(23, test_ctx);
	int rc;
/*
	MS RA capability 1
	    0001 .... = Access Technology Type: GSM E --note that GSM E covers GSM P (1)
	    .... 0011  101. .... = Length in bits: 0x1d (29)
	    ...0 01.. RF Power Capability, GMSK Power Class: Not specified (1)
	    A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
	    .... ...1 = Controlled early Classmark Sending: Implemented
	    0... .... = Pseudo Synchronisation: Not Present
	    .0.. .... = Voice Group Call Service: no VGCS capability or no notifications wanted
	    ..0. .... = Voice Broadcast Service: no VBS capability or no notifications wanted
	    ...1 .... = Multislot capability struct: Present
	    .... ..00  011. .... = GPRS multislot class: Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1 (3)
	    ...0 .... = GPRS Extended Dynamic Allocation Capability: Not Implemented

	It doesn't show up in wireshark's tree above because specific parser is
	used, but this RA Cap bitstream has Exist_EGPRS_multislot_class = 1 but
	it provides no struct with the expected data (malformed, generated
	erroneusly through TTCN3). The CSN.1 dceoder should ideally return an
	error here, but it doesn't (it returns a >0 value which we convert to 0
	in decode_gsm_ra_cap()).
*/
	bitvec_unhex(bv_dec, "13a5146200");

	printf("=== Test decoding of MS RA Capability ===\n");
	rc = decode_gsm_ra_cap(bv_dec, &data);
	printf("decode_gsm_ra_cap() returns %d\n", rc);
	OSMO_ASSERT(rc == 0);

	/* For sake of completeness, check if the decoder could find 1 value
	  before failing to decode it */
	OSMO_ASSERT(data.Count_MS_RA_capability_value == 1);

	bitvec_free(bv_dec);
}

/* Reproduce crash from ticket OS#4463 */
void testRAcap2(void *test_ctx)
{
	printf("*** %s ***\n", __func__);
	MS_Radio_Access_capability_t data;
	memset(&data, 0, sizeof(data));
	bitvec *bv_dec = bitvec_alloc(23, test_ctx);
	int rc;
/*
MS Radio Access Capability
    Element ID: 0x13
    1... .... = ext: 1
    Length: 23
    ------------------------------------------- Hex bitstream starts here:
    MS RA capability 1
        0001 .... = Access Technology Type: GSM E --note that GSM E covers GSM P (1)
        .... 1001  001. .... = Length in bits: 0x49 (73)
        ...1 00.. RF Power Capability, GMSK Power Class: 2 W (33 dBm) (4)
        A5 Bits: A5 bits follow (1)
        A5/1: encryption algorithm available (1)
        A5/2: encryption algorithm not available (0)
        A5/3: encryption algorithm available (1)
        A5/4: encryption algorithm not available (0)
        A5/5: encryption algorithm not available (0)
        A5/6: encryption algorithm not available (0)
        A5/7: encryption algorithm not available (0)
        .... ..1. = Controlled early Classmark Sending: Implemented
        .... ...1 = Pseudo Synchronisation: Present
        0... .... = Voice Group Call Service: no VGCS capability or no notifications wanted
        .0.. .... = Voice Broadcast Service: no VBS capability or no notifications wanted
        ..1. .... = Multislot capability struct: Present
            HSCSD multislot class: Bits are not available (0)
            .... 0111 = SMS_VALUE (Switch-Measure-Switch): 8/4 timeslot (~1154 microseconds) (7)
            0001 .... = (SM_VALUE) Switch-Measure: 2/4 timeslot (~288 microseconds) (1)
            ECSD multislot class: Bits are not available (0)
            .... ...0 = Single Slot DTM: Not supported
            1... .... = DTM EGPRS Multi Slot Class: Present
        .... .011  00.. .... = GPRS multislot class: Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1 (12)
        ..1. .... = GPRS Extended Dynamic Allocation Capability: Implemented
        .... ..01  100. .... = EGPRS multislot class: Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1 (12)
        ...1 .... = EGPRS Extended Dynamic Allocation Capability: Implemented
        .... .11. = DTM GPRS Multi Slot Class: Multislot class 11 supported (3)
        .11. .... = DTM EGPRS Multi Slot Class: Multislot class 11 supported (3)
        ...1 .... = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        .... ..0. = COMPACT Interference Measurement Capability: Not Implemented
        .... ...1 = Revision Level Indicator: The ME is Release '99 onwards
        0... .... = UMTS FDD Radio Access Technology Capability: Not supported
        .0.. .... = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        ..0. .... = CDMA 2000 Radio Access Technology Capability: Not supported
        ...0 .... = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        .... 1... = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        .... ..0. = Modulation based multislot class support: Not supported
        High Multislot Capability: Bits are not available (0)
        0... .... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 3 (3)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 3 (3)
        .... .0.. = Multiple TBF Capability: Not supported
        .... ..01 = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance - phase I supported (1)
        1... .... = Extended RLC/MAC Control Message Segmentation Capability: Supported
        .1.. .... = DTM Enhancements Capability: The mobile station supports enhanced DTM CS establishment and enhanced DTM CS release procedures
        ...0 .... = PS Handover Capability: Not supported
    MS RA capability 2
        .... .011  1... .... = Access Technology Type: GSM 850 (7)
        .010 0010 = Length in bits: 0x22 (34)
        100. .... RF Power Capability, GMSK Power Class: 2 W (33 dBm) (4)
        A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
        .... 1... = Controlled early Classmark Sending: Implemented
        .... .1.. = Pseudo Synchronisation: Present
        .... ..0. = Voice Group Call Service: no VGCS capability or no notifications wanted
        .... ...0 = Voice Broadcast Service: no VBS capability or no notifications wanted
        0... .... = Multislot capability struct: Not Present
        .1.. .... = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        .... 0... = COMPACT Interference Measurement Capability: Not Implemented
        .... .1.. = Revision Level Indicator: The ME is Release '99 onwards
        .... ..0. = UMTS FDD Radio Access Technology Capability: Not supported
        .... ...0 = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        0... .... = CDMA 2000 Radio Access Technology Capability: Not supported
        .0.. .... = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        ..1. .... = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        .... 0... = Modulation based multislot class support: Not supported
        High Multislot Capability: Bits are not available (0)
        .... ..0. = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 3 (3)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 3 (3)
        ...0 .... = Multiple TBF Capability: Not supported
        .... 01.. = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance - phase I supported (1)
        .... ..1. = Extended RLC/MAC Control Message Segmentation Capability: Supported
        .... ...1 = DTM Enhancements Capability: The mobile station supports enhanced DTM CS establishment and enhanced DTM CS release procedures
        .0.. .... = PS Handover Capability: Not supported
    MS RA capability 3
        ...0 011. = Access Technology Type: GSM 1800 (3)
        .... ...0  1000 10.. = Length in bits: 0x22 (34)
        .... ..00  1... .... RF Power Capability, GMSK Power Class: 1 W (30 dBm) (1)
        A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
        ..1. .... = Controlled early Classmark Sending: Implemented
        ...1 .... = Pseudo Synchronisation: Present
        .... 0... = Voice Group Call Service: no VGCS capability or no notifications wanted
        .... .0.. = Voice Broadcast Service: no VBS capability or no notifications wanted
        .... ..0. = Multislot capability struct: Not Present
        .... ...1 = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        ..0. .... = COMPACT Interference Measurement Capability: Not Implemented
        ...1 .... = Revision Level Indicator: The ME is Release '99 onwards
        .... 0... = UMTS FDD Radio Access Technology Capability: Not supported
        .... .0.. = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        .... ..0. = CDMA 2000 Radio Access Technology Capability: Not supported
        .... ...0 = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        1... .... = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        ..0. .... = Modulation based multislot class support: Not supported
        High Multislot Capability: Bits are not available (0)
        .... 0... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 3 (3)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 3 (3)
        .0.. .... = Multiple TBF Capability: Not supported
        ..01 .... = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance - phase I supported (1)
        .... 1... = Extended RLC/MAC Control Message Segmentation Capability: Supported
        .... .1.. = DTM Enhancements Capability: The mobile station supports enhanced DTM CS establishment and enhanced DTM CS release procedures
        .... ...0 = PS Handover Capability: Not supported
*/
	bitvec_unhex(bv_dec, "1933432b37159ef90879cba28c6421e72688b190879c00");

	printf("=== Test decoding of multi-band MS RA Capability ===\n");
	rc = decode_gsm_ra_cap(bv_dec, &data);
	printf("decode_gsm_ra_cap() returns %d\n", rc);
	OSMO_ASSERT(rc == 0);

	/* Make sure there's 3 values */
	OSMO_ASSERT(data.Count_MS_RA_capability_value == 3);

	/* Make sure GPRS / EGPRS multislot class is parsed correctly */
	printf("GPRS multislot class = %u\n", get_ms_class_by_capability(&data));
	printf("EGPRS multislot class = %u\n", get_egprs_ms_class_by_capability(&data));

	bitvec_free(bv_dec);
}

/* RAcap larger than 23 bytes */
void testRAcap3(void *test_ctx)
{
	printf("*** %s ***\n", __func__);
	MS_Radio_Access_capability_t data;
	memset(&data, 0, sizeof(data));
	bitvec *bv_dec = bitvec_alloc(31, test_ctx);
	int rc;
/*
MS Radio Access Capability
    Element ID: 0x13
    1... .... = ext: 1
    Length: 31
    ------------------------------------------- Hex bitstream starts here:
    MS RA capability 1
        0001 .... = Access Technology Type: GSM E --note that GSM E covers GSM P (1)
        .... 1010  111. .... = Length in bits: 0x57 (87)
        ...1 00.. RF Power Capability, GMSK Power Class: 2 W (33 dBm) (4)
        A5 Bits: A5 bits follow (1)
        A5/1: encryption algorithm available (1)
        A5/2: encryption algorithm not available (0)
        A5/3: encryption algorithm available (1)
        A5/4: encryption algorithm not available (0)
        A5/5: encryption algorithm not available (0)
        A5/6: encryption algorithm not available (0)
        A5/7: encryption algorithm not available (0)
        .... ..1. = Controlled early Classmark Sending: Implemented
        .... ...1 = Pseudo Synchronisation: Present
        0... .... = Voice Group Call Service: no VGCS capability or no notifications wanted
        .0.. .... = Voice Broadcast Service: no VBS capability or no notifications wanted
        ..1. .... = Multislot capability struct: Present
            HSCSD multislot class: Bits are not available (0)
            SMS_VALUE (Switch-Measure-Switch): Bits are not available (0)
            ECSD multislot class: Bits are not available (0)
            DTM GPRS Multi Slot Class: Bits are not available (0)
        .... .011  00.. .... = GPRS multislot class: Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1 (12)
        ..1. .... = GPRS Extended Dynamic Allocation Capability: Implemented
        .... ..01  100. .... = EGPRS multislot class: Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1 (12)
        ...1 .... = EGPRS Extended Dynamic Allocation Capability: Implemented
        .... .1.. = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        0... .... = COMPACT Interference Measurement Capability: Not Implemented
        .1.. .... = Revision Level Indicator: The ME is Release '99 onwards
        ..0. .... = UMTS FDD Radio Access Technology Capability: Not supported
        ...0 .... = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        .... 0... = CDMA 2000 Radio Access Technology Capability: Not supported
        .... .0.. = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        .... ..1. = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        0... .... = Modulation based multislot class support: Not supported
        High Multislot Capability: 0x00 (0) - This field effect all other multislot fields. To understand the value please read TS 24.008 5.6.0 Release 5 Chap 10.5.5.12 Page 406
        .... 0... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 0 (0)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 0 (0)
        .0.. .... = Multiple TBF Capability: Not supported
        ..01 .... = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance - phase I supported (1)
        .... 0... = Extended RLC/MAC Control Message Segmentation Capability: Not supported
        .... .0.. = DTM Enhancements Capability: The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures
        .... ...0 = PS Handover Capability: Not supported
        0... .... = DTM Handover Capability: Not supported
        ..0. .... = Flexible Timeslot Assignment: Not supported
        ...0 .... = GAN PS Handover Capability: Not supported
        .... 0... = RLC Non-persistent Mode: Not supported
        .... .0.. = Reduced Latency Capability: Not supported
        .... ..00 = Uplink EGPRS2: The mobile station does not support either EGPRS2-A or EGPRS2-B in the uplink (0)
        00.. .... = Downlink EGPRS2: The mobile station does not support either EGPRS2-A or EGPRS2-B in the downlink (0)
        ..0. .... = E-UTRA FDD support: Not supported
        ...0 .... = E-UTRA TDD support: Not supported
        .... 00.. = GERAN to E-UTRA support in GERAN packet transfer mode: None (0)
        .... ..0. = Priority-based reselection support: Not supported
        0... .... = Indication of Upper Layer PDU Start Capability for RLC UM: Not supported
        .0.. .... = Enhanced Multiplexing for Single TBF Capability: Not supported
        ..0. .... = Multiple TTI Capability: Not supported
        ...0 .... = Reporting of UTRAN CSG cells in packet transfer mode: Not supported
        .... 0... = Reporting of E-UTRAN CSG cells in packet transfer mode: Not supported
        .... .0.. = Dynamic Timeslot Reduction Capability: Not supported
        .... ..0. = Enhanced Multiplexing for Single RLC Entity Capability: Not supported
        .... ...0 = Fast Downlink Frequency Switching Capability: Not supported
        01.. .... = TIGHTER Capability: TIGHTER supported for speech and signalling channels only (1)
    MS RA capability 2
        ...0 111. = Access Technology Type: GSM 850 (7)
        .... ...0  1111 10.. = Length in bits: 0x3e (62)
        .... ..10  0... .... RF Power Capability, GMSK Power Class: 2 W (33 dBm) (4)
        A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
        ..1. .... = Controlled early Classmark Sending: Implemented
        ...1 .... = Pseudo Synchronisation: Present
        .... 0... = Voice Group Call Service: no VGCS capability or no notifications wanted
        .... .0.. = Voice Broadcast Service: no VBS capability or no notifications wanted
        .... ..0. = Multislot capability struct: Not Present
        .... ...1 = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        ..0. .... = COMPACT Interference Measurement Capability: Not Implemented
        ...1 .... = Revision Level Indicator: The ME is Release '99 onwards
        .... 0... = UMTS FDD Radio Access Technology Capability: Not supported
        .... .0.. = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        .... ..0. = CDMA 2000 Radio Access Technology Capability: Not supported
        .... ...0 = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        1... .... = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        ..0. .... = Modulation based multislot class support: Not supported
        High Multislot Capability: 0x00 (0) - This field effect all other multislot fields. To understand the value please read TS 24.008 5.6.0 Release 5 Chap 10.5.5.12 Page 406
        .... ..0. = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 0 (0)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 0 (0)
        ...0 .... = Multiple TBF Capability: Not supported
        .... 01.. = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance - phase I supported (1)
        .... ..0. = Extended RLC/MAC Control Message Segmentation Capability: Not supported
        .... ...0 = DTM Enhancements Capability: The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures
        .0.. .... = PS Handover Capability: Not supported
        ..0. .... = DTM Handover Capability: Not supported
        .... 0... = Flexible Timeslot Assignment: Not supported
        .... .0.. = GAN PS Handover Capability: Not supported
        .... ..0. = RLC Non-persistent Mode: Not supported
        .... ...0 = Reduced Latency Capability: Not supported
        00.. .... = Uplink EGPRS2: The mobile station does not support either EGPRS2-A or EGPRS2-B in the uplink (0)
        ..00 .... = Downlink EGPRS2: The mobile station does not support either EGPRS2-A or EGPRS2-B in the downlink (0)
        .... 0... = E-UTRA FDD support: Not supported
        .... .0.. = E-UTRA TDD support: Not supported
        .... ..00 = GERAN to E-UTRA support in GERAN packet transfer mode: None (0)
        0... .... = Priority-based reselection support: Not supported
        ..0. .... = Indication of Upper Layer PDU Start Capability for RLC UM: Not supported
        ...0 .... = Enhanced Multiplexing for Single TBF Capability: Not supported
        .... 0... = Multiple TTI Capability: Not supported
        .... .0.. = Reporting of UTRAN CSG cells in packet transfer mode: Not supported
        .... ..0. = Reporting of E-UTRAN CSG cells in packet transfer mode: Not supported
        .... ...0 = Dynamic Timeslot Reduction Capability: Not supported
        0... .... = Enhanced Multiplexing for Single RLC Entity Capability: Not supported
        .0.. .... = Fast Downlink Frequency Switching Capability: Not supported
        ..01 .... = TIGHTER Capability: TIGHTER supported for speech and signalling channels only (1)
    MS RA capability 3
        .... .010  0... .... = Access Technology Type: GSM 1900 (4)
        .011 1110 = Length in bits: 0x3e (62)
        001. .... RF Power Capability, GMSK Power Class: 1 W (30 dBm) (1)
        A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
        .... 1... = Controlled early Classmark Sending: Implemented
        .... .1.. = Pseudo Synchronisation: Present
        .... ..0. = Voice Group Call Service: no VGCS capability or no notifications wanted
        .... ...0 = Voice Broadcast Service: no VBS capability or no notifications wanted
        0... .... = Multislot capability struct: Not Present
        .1.. .... = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        .... 0... = COMPACT Interference Measurement Capability: Not Implemented
        .... .1.. = Revision Level Indicator: The ME is Release '99 onwards
        .... ..0. = UMTS FDD Radio Access Technology Capability: Not supported
        .... ...0 = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        0... .... = CDMA 2000 Radio Access Technology Capability: Not supported
        .0.. .... = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        ..1. .... = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        .... 0... = Modulation based multislot class support: Not supported
        High Multislot Capability: 0x00 (0) - This field effect all other multislot fields. To understand the value please read TS 24.008 5.6.0 Release 5 Chap 10.5.5.12 Page 406
        0... .... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 0 (0)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 0 (0)
        .... .0.. = Multiple TBF Capability: Not supported
        .... ..01 = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance - phase I supported (1)
        0... .... = Extended RLC/MAC Control Message Segmentation Capability: Not supported
        .0.. .... = DTM Enhancements Capability: The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures
        ...0 .... = PS Handover Capability: Not supported
        .... 0... = DTM Handover Capability: Not supported
        .... ..0. = Flexible Timeslot Assignment: Not supported
        .... ...0 = GAN PS Handover Capability: Not supported
        0... .... = RLC Non-persistent Mode: Not supported
        .0.. .... = Reduced Latency Capability: Not supported
        ..00 .... = Uplink EGPRS2: The mobile station does not support either EGPRS2-A or EGPRS2-B in the uplink (0)
        .... 00.. = Downlink EGPRS2: The mobile station does not support either EGPRS2-A or EGPRS2-B in the downlink (0)
        .... ..0. = E-UTRA FDD support: Not supported
        .... ...0 = E-UTRA TDD support: Not supported
        00.. .... = GERAN to E-UTRA support in GERAN packet transfer mode: None (0)
        ..0. .... = Priority-based reselection support: Not supported
        .... 0... = Indication of Upper Layer PDU Start Capability for RLC UM: Not supported
        .... .0.. = Enhanced Multiplexing for Single TBF Capability: Not supported
        .... ..0. = Multiple TTI Capability: Not supported
        .... ...0 = Reporting of UTRAN CSG cells in packet transfer mode: Not supported
        0... .... = Reporting of E-UTRAN CSG cells in packet transfer mode: Not supported
        .0.. .... = Dynamic Timeslot Reduction Capability: Not supported
        ..0. .... = Enhanced Multiplexing for Single RLC Entity Capability: Not supported
        ...0 .... = Fast Downlink Frequency Switching Capability: Not supported
        .... 01.. = TIGHTER Capability: TIGHTER supported for speech and signalling channels only (1)
*/
	bitvec_unhex(bv_dec, "1af3432b25964240100000006efa319090040000001a3e2c64240100000004");

	printf("=== Test decoding of MS RA Capability 3===\n");
	rc = decode_gsm_ra_cap(bv_dec, &data);
	printf("decode_gsm_ra_cap() returns %d\n", rc);
	OSMO_ASSERT(rc == 0);

	/* Make sure there's 3 values */
	OSMO_ASSERT(data.Count_MS_RA_capability_value == 3);

	/* Make sure GPRS / EGPRS multislot class is parsed correctly */
	printf("GPRS multislot class = %u\n", get_ms_class_by_capability(&data));
	printf("EGPRS multislot class = %u\n", get_egprs_ms_class_by_capability(&data));

	bitvec_free(bv_dec);
}

/* RAcap larger than 23 bytes */
void testRAcap4(void *test_ctx)
{
	printf("*** %s ***\n", __func__);
	MS_Radio_Access_capability_t data;
	memset(&data, 0, sizeof(data));
	bitvec *bv_dec = bitvec_alloc(22, test_ctx);
	int rc;

/*
MS Radio Access Capability
    Element ID: 0x13
    1... .... = ext: 1
    Length: 22
    ------------------------------------------- Hex bitstream starts here:
    MS RA capability 1
        0001 .... = Access Technology Type: GSM E --note that GSM E covers GSM P (1)
        .... 0111  101. .... = Length in bits: 0x3d (61)
        ...1 00.. RF Power Capability, GMSK Power Class: 2 W (33 dBm) (4)
        A5 Bits: A5 bits follow (1)
        A5/1: encryption algorithm available (1)
        A5/2: encryption algorithm not available (0)
        A5/3: encryption algorithm available (1)
        A5/4: encryption algorithm not available (0)
        A5/5: encryption algorithm not available (0)
        A5/6: encryption algorithm not available (0)
        A5/7: encryption algorithm not available (0)
        .... ..1. = Controlled early Classmark Sending: Implemented
        .... ...1 = Pseudo Synchronisation: Present
        0... .... = Voice Group Call Service: no VGCS capability or no notifications wanted
        .0.. .... = Voice Broadcast Service: no VBS capability or no notifications wanted
        ..1. .... = Multislot capability struct: Present
            HSCSD multislot class: Bits are not available (0)
            SMS_VALUE (Switch-Measure-Switch): Bits are not available (0)
            ECSD multislot class: Bits are not available (0)
            DTM GPRS Multi Slot Class: Bits are not available (0)
        .... .011  00.. .... = GPRS multislot class: Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1 (12)
        ..1. .... = GPRS Extended Dynamic Allocation Capability: Implemented
        .... ..01  100. .... = EGPRS multislot class: Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1 (12)
        ...1 .... = EGPRS Extended Dynamic Allocation Capability: Implemented
        .... .1.. = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        0... .... = COMPACT Interference Measurement Capability: Not Implemented
        .1.. .... = Revision Level Indicator: The ME is Release '99 onwards
        ..1. .... = UMTS FDD Radio Access Technology Capability: Supported
        ...0 .... = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        .... 0... = CDMA 2000 Radio Access Technology Capability: Not supported
        .... .0.. = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        .... ..1. = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        0... .... = Modulation based multislot class support: Not supported
        High Multislot Capability: Bits are not available (0)
        ..0. .... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 0 (0)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 0 (0)
        .... ...0 = Multiple TBF Capability: Not supported
        00.. .... = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance not supported (0)
        ..0. .... = Extended RLC/MAC Control Message Segmentation Capability: Not supported
        ...0 .... = DTM Enhancements Capability: The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures
        .... .0.. = PS Handover Capability: Not supported
        .... ..0. = DTM Handover Capability: Not supported
    MS RA capability 2
        .001 1... = Access Technology Type: GSM 1800 (3)
        .... .010  0100 .... = Length in bits: 0x24 (36)
        .... 001. RF Power Capability, GMSK Power Class: 1 W (30 dBm) (1)
        A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
        1... .... = Controlled early Classmark Sending: Implemented
        .1.. .... = Pseudo Synchronisation: Present
        ..0. .... = Voice Group Call Service: no VGCS capability or no notifications wanted
        ...0 .... = Voice Broadcast Service: no VBS capability or no notifications wanted
        .... 0... = Multislot capability struct: Not Present
        .... .1.. = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        0... .... = COMPACT Interference Measurement Capability: Not Implemented
        .1.. .... = Revision Level Indicator: The ME is Release '99 onwards
        ..1. .... = UMTS FDD Radio Access Technology Capability: Supported
        ...0 .... = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        .... 0... = CDMA 2000 Radio Access Technology Capability: Not supported
        .... .0.. = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        .... ..1. = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        0... .... = Modulation based multislot class support: Not supported
        High Multislot Capability: Bits are not available (0)
        ..0. .... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 0 (0)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 0 (0)
        .... ...0 = Multiple TBF Capability: Not supported
        00.. .... = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance not supported (0)
        ..0. .... = Extended RLC/MAC Control Message Segmentation Capability: Not supported
        ...0 .... = DTM Enhancements Capability: The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures
        .... .0.. = PS Handover Capability: Not supported
        .... ..0. = DTM Handover Capability: Not supported
    MS RA capability 3
        .011 1... = Access Technology Type: GSM 850 (7)
        .... .010  0100 .... = Length in bits: 0x24 (36)
        .... 100. RF Power Capability, GMSK Power Class: 2 W (33 dBm) (4)
        A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (0)
        1... .... = Controlled early Classmark Sending: Implemented
        .1.. .... = Pseudo Synchronisation: Present
        ..0. .... = Voice Group Call Service: no VGCS capability or no notifications wanted
        ...0 .... = Voice Broadcast Service: no VBS capability or no notifications wanted
        .... 0... = Multislot capability struct: Not Present
        .... .1.. = 8PSK Power Capability Bits: Present
        8PSK Power Capability: Power class E2 (2)
        0... .... = COMPACT Interference Measurement Capability: Not Implemented
        .1.. .... = Revision Level Indicator: The ME is Release '99 onwards
        ..1. .... = UMTS FDD Radio Access Technology Capability: Supported
        ...0 .... = UMTS 3.84 Mcps TDD Radio Access Technology Capability: Not supported
        .... 0... = CDMA 2000 Radio Access Technology Capability: Not supported
        .... .0.. = UMTS 1.28 Mcps TDD Radio Access Technology Capability: Not supported
        .... ..1. = GERAN Feature Package 1: Supported
        Extended DTM EGPRS Multi Slot Class: Bits are not available (0)
        0... .... = Modulation based multislot class support: Not supported
        High Multislot Capability: Bits are not available (0)
        ..0. .... = GERAN Iu mode: Not supported
        GMSK Multislot Power Profile: GMSK_MULTISLOT_POWER_PROFILE 0 (0)
        8-PSK Multislot Power Profile: 8-PSK_MULTISLOT_POWER_PROFILE 0 (0)
        .... ...0 = Multiple TBF Capability: Not supported
        00.. .... = Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance not supported (0)
        ..0. .... = Extended RLC/MAC Control Message Segmentation Capability: Not supported
        ...0 .... = DTM Enhancements Capability: The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures
        .... .0.. = PS Handover Capability: Not supported
        .... ..0. = DTM Handover Capability: Not supported
*/

	bitvec_unhex(bv_dec, "17b3432b25966200019a42c6620001ba48c662000100");

	printf("=== Test decoding of MS RA Capability 4===\n");
	rc = decode_gsm_ra_cap(bv_dec, &data);
	printf("decode_gsm_ra_cap() returns %d\n", rc);
	OSMO_ASSERT(rc == 0);

	/* Make sure there's 3 values */
	OSMO_ASSERT(data.Count_MS_RA_capability_value == 3);

	/* Make sure GPRS / EGPRS multislot class is parsed correctly */
	printf("GPRS multislot class = %u\n", get_ms_class_by_capability(&data));
	printf("EGPRS multislot class = %u\n", get_egprs_ms_class_by_capability(&data));

	bitvec_free(bv_dec);
}

void testEGPRSPktChReq(void *test_ctx)
{
	EGPRS_PacketChannelRequest_t req;
	int rc;

	printf("*** %s ***\n", __func__);

	static const uint16_t EGPRSPktChReqs[] = {
		/* < One Phase Access Request : '0'B
		     < MultislotClass : '10101'B >
		     < Priority : '10'B >
		     < RandomBits : '101'B > > */
		0x2b5,
		/* < One Phase Access Request : '0'B
		     < MultislotClass : '01010'B >
		     < Priority : '01'B >
		     < RandomBits : '010'B > > */
		0x14a,
		/* < Short Access Request : '100'B
		     < NumberOfBlocks : '001'B >
		     < Priority : '01'B >
		     < RandomBits : '000'B > > */
		0x428,
		/* < Two Phase Access Request : '110000'B
		     < Priority : '00'B >
		     < RandomBits : '000'B > > */
		0x600,
		/* < Two Phase Access Request : '110000'B
		     < Priority : '11'B >
		     < RandomBits : '111'B > > */
		0x61f,
		/* < Signalling : '110011'B
		     < RandomBits : '10101'B > > */
		0x675,
		/* < Signalling : '110011'B
		     < RandomBits : '10001'B > > */
		0x671,
		/* < Emergency call : '110111'B
		     < RandomBits : '11001'B > > */
		0x6f9,
		/* < Unknown (test) : '111111'B
		     < RandomBits : '01010'B > > */
		0x7ea,
	};

	for (size_t i = 0; i < ARRAY_SIZE(EGPRSPktChReqs); i++) {
		rc = decode_egprs_pkt_ch_req(EGPRSPktChReqs[i], &req);
		printf("decode_egprs_pkt_ch_req(0x%03x) returns %d\n", EGPRSPktChReqs[i], rc);
		if (rc == 0)
			printf(" ==> %s\n", get_value_string(egprs_pkt_ch_req_type_names, req.Type));
	}
}

int main(int argc, char *argv[])
{
	void *ctx = talloc_named_const(NULL, 1, "RLCMACTest");
	osmo_init_logging2(ctx, &gprs_log_info);
	log_parse_category_mask(osmo_stderr_target, "DPCU,3:DLGLOBAL,1:DRLCMACDATA,2:DCSN1,1:");

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	//printSizeofRLCMAC();
	testRlcMacDownlink(ctx);
	testRlcMacUplink(ctx);
	testCsnLeftAlignedVarBmpBounds(ctx);
	testRAcap(ctx);
	testMalformedRAcap(ctx);
	testRAcap2(ctx);
	testRAcap3(ctx);

	testEGPRSPktChReq(ctx);

	testRAcap4(ctx);

	talloc_free(ctx);
}
