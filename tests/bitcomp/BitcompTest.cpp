#include <stdint.h>
#include <string.h>

#include "rlc.h"
#include "gprs_debug.h"
#include <gprs_rlcmac.h>
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
#define CEIL_DIV_8(x) (((x) + 7)/8)
#define _LOG(fmt, args...) \
	fprintf(stderr, fmt, ## args)

void *tall_pcu_ctx;

struct test_data {
	int8_t crbb_len;
	uint8_t cc;
	uint8_t crbb_data[MAX_CRBB_LEN]; /* compressed data */
	uint8_t ucmp_data[MAX_URBB_LEN]; /* uncompressed data */
	int ucmp_len;
	int expect_rc;
} test[] = {
		{ .crbb_len = 67, .cc = 1,
			.crbb_data = {
			0x02, 0x0c, 0xa0, 0x30, 0xcb, 0x1a, 0x0c, 0xe3, 0x6c
			},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x01, 0xff, 0xff,
			0xff, 0xf8, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe,
			0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0xc0
			},
			.ucmp_len = 194,
			.expect_rc = 0,
		},
		{ .crbb_len = 40, .cc = 1,
			.crbb_data = {
			0x53, 0x06, 0xc5, 0x40, 0x6d
			},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00,
			0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
			0x00, 0x00, 0x00, 0x00, 0x00
			},
			.ucmp_len = 182,
			.expect_rc = 0,
		},
		{ .crbb_len = 8, .cc = 1,
			.crbb_data = {0x02},
			.ucmp_data = {0xff, 0xff, 0xff, 0xf8},
			.ucmp_len = 29,
			.expect_rc = 0,
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
			.ucmp_len = 288,
			.expect_rc = 0,
		},
		/* Test vector from libosmocore test */
		{ .crbb_len = 35, .cc = 0,
			.crbb_data = {0xde, 0x88, 0x75, 0x65, 0x80},
			.ucmp_data = {0x37, 0x47, 0x81, 0xf0},
			.ucmp_len = 28,
			.expect_rc = 0,
		},
		{ .crbb_len = 18, .cc = 1,
			.crbb_data = {0xdd, 0x41, 0x00},
			.ucmp_data = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0x00, 0x00
			},
			.ucmp_len = 90,
			.expect_rc = 0,
		},
		/* TODO: previously marked as "Invalid inputs" but succeeds */
		{ .crbb_len = 18, .cc = 1,
			.crbb_data = {0x1E, 0x70, 0xc0},
			.ucmp_data = {0xb0, 0x00, 0x00},
			.ucmp_len = 19,
			.expect_rc = 0,
		},
		/* Invalid inputs */
		{ .crbb_len = 14, .cc = 1,
			.crbb_data = {0x00, 0x1E, 0x7c},
			.ucmp_data = {0x0},
			.ucmp_len = 0,
			.expect_rc = -1,
		},
		{ .crbb_len = 24, .cc = 0,
			.crbb_data = {0x00, 0x00, 0x00},
			.ucmp_data = {0x0},
			.ucmp_len = 0,
			.expect_rc = -1,
		}
	};

bool result_matches(const bitvec &bits, const uint8_t *exp_data, unsigned int exp_len)
{
	if (bits.cur_bit != exp_len)
		return false;
	return (memcmp(exp_data, bits.data, CEIL_DIV_8(exp_len)) == 0);
}

/*  To test decoding of compressed bitmap by Tree based method
 *  and to verify the result with expected result
 *  for invalid input verfication is suppressed
 */
static void test_EPDAN_decode_tree(void)
{
	bitvec dest;
	unsigned int itr;
	int rc;
	uint8_t bits_data[RLC_EGPRS_MAX_WS/8];

	printf("=== start %s ===\n", __func__);

	for (itr = 0 ; itr < (sizeof(test) / sizeof(test_data)) ; itr++) {
		memset(bits_data, 0, sizeof(bits_data));
		dest.data = bits_data;
		dest.data_len = sizeof(bits_data);
		dest.cur_bit = 0;
		_LOG("\nTest:%d\n"
		     "Tree based decoding:\n"
		     "uncompressed data = %s\n"
		     "len = %d\n",
		     itr + 1,
		     osmo_hexdump(test[itr].crbb_data,
				  CEIL_DIV_8(test[itr].crbb_len)),
		     test[itr].crbb_len);
		rc = egprs_compress::decompress_crbb(test[itr].crbb_len,
			test[itr].cc, test[itr].crbb_data, &dest);
		_LOG("rc = %d\n", rc);
		OSMO_ASSERT(test[itr].expect_rc == rc);
		if (rc < 0) {
			_LOG("Failed to decode CRBB: length %d, data %s\n",
			     test[itr].crbb_len,
			     osmo_hexdump(test[itr].crbb_data,
					  CEIL_DIV_8(test[itr].crbb_len)));
			continue;
		}
		if (!result_matches(dest, test[itr].ucmp_data,
				    test[itr].ucmp_len)) {
			_LOG("\nTree based decoding: Error\n"
			     "expected data = %s\n"
			     "expected len = %d\n",
			     osmo_hexdump(test[itr].ucmp_data,
					  CEIL_DIV_8(test[itr].ucmp_len)),
			     test[itr].ucmp_len);
			_LOG("decoded data = %s\n"
			     "decoded len = %d\n",
			     osmo_hexdump(dest.data,
					  CEIL_DIV_8(dest.cur_bit)),
			     dest.cur_bit);
			OSMO_ASSERT(0);
		}
		_LOG("\nexpected data = %s\n"
		     "expected len = %d\n",
		     osmo_hexdump(test[itr].ucmp_data,
				  CEIL_DIV_8(test[itr].ucmp_len)),
		     test[itr].ucmp_len);
		_LOG("decoded data = %s\n"
		     "decoded len = %d\n",
		     osmo_hexdump(dest.data, CEIL_DIV_8(dest.cur_bit)),
		     dest.cur_bit);
	}

	printf("=== end %s ===\n", __func__);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_parse_category_mask(osmo_stderr_target, "DRLCMACUL,1");

	tall_pcu_ctx = talloc_named_const(NULL, 1, "moiji-mobile bitcompTest context");
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

