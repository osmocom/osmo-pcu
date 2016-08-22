#include <stdint.h>
#include <string.h>

#include "rlc.h"
#include "gprs_debug.h"
#include "egprs_rlc_compression.h"

extern "C" {
#include <osmocom/core/logging.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
}

#define NEW 1
#define MASK(n) (0xFF << (8-n))
#define MAX_CRBB_LEN 23
#define MAX_URBB_LEN 40

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;

struct test_data {
	int8_t crbb_len;
	uint8_t cc;
	uint8_t crbb_data[MAX_CRBB_LEN]; /* compressed data   */
	uint8_t ucmp_data[MAX_URBB_LEN]; /* uncompressed data */
	int ucmp_len;
	int verify;
} test[] = {
		{ .crbb_len = 67, .cc = 1,
			.crbb_data = {
			0x02, 0x0c, 0xa0, 0x30, 0xcb, 0x1a, 0x0c, 0xe3, 0x6c
			},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x01, 0xff, 0xff,
			0xff, 0xf8, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe,
			0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0xdb
			},
			.ucmp_len = 194, .verify = 1
		},
		{ .crbb_len = 40, .cc = 1,
			.crbb_data = {
			0x53, 0x06, 0xc5, 0x40, 0x6d
			},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00,
			0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
			0x00, 0x00, 0x00, 0x00, 0x03
			},
			.ucmp_len = 182, .verify = 1
		},
		{ .crbb_len = 8, .cc = 1,
			.crbb_data = {0x02},
			.ucmp_data = {0xff, 0xff, 0xff, 0xf8},
			.ucmp_len = 29, .verify = 1
		},
		{ .crbb_len = 103, .cc = 1,
			.crbb_data = {
			0x02, 0x0c, 0xe0, 0x41, 0xa0, 0x0c, 0x36, 0x0d, 0x03,
			0x71, 0xb0, 0x6e, 0x24
			},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0xff, 0xff, 0xff,
			0xf8, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xfe, 0x00, 0x00,
			0x0f, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x7f, 0xff,
			0xff, 0xff, 0x80, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff
			},
			.ucmp_len = 288, .verify = 1
		},
		/* Test vector from libosmocore test */
		{ .crbb_len = 35, .cc = 0,
			.crbb_data = {0xde, 0x88, 0x75, 0x65, 0x80},
			.ucmp_data = {0x37, 0x47, 0x81, 0xf0},
			.ucmp_len = 28, .verify = 1
		},
		{ .crbb_len = 18, .cc = 1,
			.crbb_data = {0xdd, 0x41, 0x00},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0x00, 0x00
			},
			.ucmp_len = 90, .verify = 1
		},
		/*Invalid inputs*/
		{ .crbb_len = 18, .cc = 1,
			.crbb_data = {0x1E, 0x70, 0xc0},
			.ucmp_data = {0x0},
			.ucmp_len = 0, .verify = 0
		},
		{ .crbb_len = 14, .cc = 1,
			.crbb_data = {0x00, 0x1E, 0x7c},
			.ucmp_data = {0x0},
			.ucmp_len = 0, .verify = 0
		},
		{ .crbb_len = 24, .cc = 0,
			.crbb_data = {0x00, 0x00, 0x00},
			.ucmp_data = {0x0},
			.ucmp_len = 0, .verify = 0
		}
	};

static const struct log_info_cat default_categories[] = {
	{"DCSN1", "\033[1;31m", "Concrete Syntax Notation One (CSN1)", LOGL_INFO, 0},
	{"DL1IF", "\033[1;32m", "GPRS PCU L1 interface (L1IF)", LOGL_DEBUG, 1},
	{"DRLCMAC", "\033[0;33m", "GPRS RLC/MAC layer (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACDATA", "\033[0;33m", "GPRS RLC/MAC layer Data (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACDL", "\033[1;33m", "GPRS RLC/MAC layer Downlink (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACUL", "\033[1;36m", "GPRS RLC/MAC layer Uplink (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACSCHED", "\033[0;36m", "GPRS RLC/MAC layer Scheduling (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACMEAS", "\033[1;31m", "GPRS RLC/MAC layer Measurements (RLCMAC)", LOGL_INFO, 1},
	{"DNS", "\033[1;34m", "GPRS Network Service Protocol (NS)", LOGL_INFO, 1},
	{"DBSSGP", "\033[1;34m", "GPRS BSS Gateway Protocol (BSSGP)", LOGL_INFO, 1},
	{"DPCU", "\033[1;35m", "GPRS Packet Control Unit (PCU)", LOGL_NOTICE, 1},
};

static int filter_fn(const struct log_context *ctx,
			struct log_target *tar)
{
	return 1;
}

/* To verify the result with expected result */
int check_result(bitvec bits, uint8_t *exp_data, int exp_len)
{
	if (bits.cur_bit != exp_len)
		return 0;
	size_t n = (exp_len / 8);
	int rem = (exp_len % 8);

	if (memcmp(exp_data, bits.data, n) == 0) {
		if (rem == 0)
			return 1;
		if ((bits.data[n] & MASK(rem)) == ((*(exp_data + n)) & MASK(rem)))
			return 1;
		else
			return 0;
	} else
		return 0;
}

/*  To test decoding of compressed bitmap by Tree based method
 *  and to verify the result with expected result
 *  for invalid input verfication is suppressed
 */
static void test_EPDAN_decode_tree(void)
{
	bitvec dest;
	int init_flag = 1;
	int itr;
	int rc;
	uint8_t bits_data[RLC_EGPRS_MAX_WS/8];

	printf("=== start %s ===\n", __func__);

	for (itr = 0 ; itr < (sizeof(test) / sizeof(test_data)) ; itr++) {
		dest.data = bits_data;
		dest.data_len = sizeof(bits_data);
		dest.cur_bit = 0;
		memset(dest.data, 0, sizeof(bits_data));
		LOGP(DRLCMACDL, LOGL_DEBUG, "\nTest:%d\nTree based decoding:"
			"\nuncompressed data = %s\nlen = %d\n", itr + 1,
			osmo_hexdump(test[itr].crbb_data,
			(test[itr].crbb_len + 7)/8), test[itr].crbb_len
		);
		rc = decompress_crbb(test[itr].crbb_len, test[itr].cc,
				test[itr].crbb_data, &dest
				);
		if (rc < 0) {
			LOGP(DRLCMACUL, LOGL_NOTICE,
				"\nFailed to decode CRBB: length %d, data %s",
				test[itr].crbb_len, osmo_hexdump(
				test[itr].crbb_data, (test[itr].crbb_len + 7)/8));
		}
		if (init_flag)
			init_flag = 0;
		if (test[itr].verify) {
			if (check_result(dest, test[itr].ucmp_data,
				test[itr].ucmp_len) == 0) {
				LOGP(DRLCMACDL, LOGL_DEBUG, "\nTree based decoding"
					":Error\nexpected data = %s\nexpected"
					" len = %d\ndecoded data = %s\n"
					"decoded len = %d\n",
					osmo_hexdump(test[itr].ucmp_data,
						(test[itr].ucmp_len + 7)/8),
					test[itr].ucmp_len, osmo_hexdump(dest.data,
						(dest.cur_bit + 7)/8), dest.cur_bit
				);
				OSMO_ASSERT(0);
			}
		}
		LOGP(DRLCMACDL, LOGL_DEBUG, "\nexpected data = %s\nexpected len = %d"
			"\ndecoded data = %s\ndecoded len = %d\n",
			osmo_hexdump(test[itr].ucmp_data,
			(test[itr].ucmp_len + 7)/8),
			test[itr].ucmp_len, osmo_hexdump(dest.data,
			(dest.cur_bit + 7)/8), dest.cur_bit
		);
	}

	printf("=== end %s ===\n", __func__);
}

const struct log_info debug_log_info = {
	filter_fn,
	(struct log_info_cat *)default_categories,
	ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&debug_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	tall_pcu_ctx = talloc_named_const(NULL, 1, "BitcompTest context");
	if (!tall_pcu_ctx)
		abort();

	test_EPDAN_decode_tree();

	if (getenv("TALLOC_REPORT_FULL"))
		talloc_report_full(tall_pcu_ctx, stderr);
	talloc_free(tall_pcu_ctx);
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

