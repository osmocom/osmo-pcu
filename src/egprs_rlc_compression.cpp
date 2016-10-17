/* egprs_rlc_compression.h
*  Routines for EGPRS RLC bitmap compression handling
*/
#include <errno.h>
#include <decoding.h>
#include <arpa/inet.h>
#include <string.h>
#include <gprs_debug.h>
#include <gprs_rlcmac.h>
#include <egprs_rlc_compression.h>

extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/stats.h>
}

#define EGPRS_CODEWORDS		79 /* total number of codewords */

struct egprs_compress_node{
	struct egprs_compress_node *left;
	struct egprs_compress_node *right;
	int run_length;
};

extern void *tall_pcu_ctx;

egprs_compress *egprs_compress::s_instance = 0;

egprs_compress_node *egprs_compress::create_tree_node(void *parent)
{
	egprs_compress_node *new_node;

	new_node = talloc_zero(parent, egprs_compress_node);
	new_node->left = NULL;
	new_node->right = NULL;
	new_node->run_length = -1;
	return new_node;
}

egprs_compress *egprs_compress::instance()
{
	if (!egprs_compress::s_instance)
		egprs_compress::s_instance = new egprs_compress;
	return egprs_compress::s_instance;
}

/* Expands the given tree by incorporating
 * the given codewords.
 * \param root[in] Root of ones or zeros tree
 * \param cdwd[in] Array of code words
 * number of codewords is EGPRS_CODEWORDS
 */
void egprs_compress::build_codewords(egprs_compress_node *root, const char *cdwd[])
{
	egprs_compress_node *iter;
	int len;
	int i;
	int idx;

	for (idx = 0; idx < EGPRS_CODEWORDS; idx++) {
		len = strlen((const char *)cdwd[idx]);
		iter = root;
		for (i = 0; i < len; i++) {
			if (cdwd[idx][i] == '0') {
				if (!iter->left)
					iter->left = create_tree_node(root);
				iter = iter->left;
			} else {
				if (!iter->right)
					iter->right = create_tree_node(root);
				iter = iter->right;
			}
		}
		if (iter) {
			/* The first 64 run lengths are 0, 1, 2, ..., 63
			 * and the following ones are 64, 128, 192 described in
			 * section 9.1.10 of 3gpp 44.060 */
			if (idx < 64)
				iter->run_length = idx;
			else
				iter->run_length = (idx - 63) * 64;
		}
	}
}

/* The code words for one run length and zero run length are described in
 * table 9.1.10.1 of 3gpp 44.060
 */
const char *one_run_len_code_list[EGPRS_CODEWORDS] = {
	"00110101",
	"000111",
	"0111",
	"1000",
	"1011",
	"1100",
	"1110",
	"1111",
	"10011",
	"10100",
	"00111",
	"01000",
	"001000",
	"000011",
	"110100",
	"110101",
	"101010",
	"101011",
	"0100111",
	"0001100",
	"0001000",
	"0010111",
	"0000011",
	"0000100",
	"0101000",
	"0101011",
	"0010011",
	"0100100",
	"0011000",
	"00000010",
	"00000011",
	"00011010",
	"00011011",
	"00010010",
	"00010011",
	"00010100",
	"00010101",
	"00010110",
	"00010111",
	"00101000",
	"00101001",
	"00101010",
	"00101011",
	"00101100",
	"00101101",
	"00000100",
	"00000101",
	"00001010",
	"00001011",
	"01010010",
	"01010011",
	"01010100",
	"01010101",
	"00100100",
	"00100101",
	"01011000",
	"01011001",
	"01011010",
	"01011011",
	"01001010",
	"01001011",
	"00110010",
	"00110011",
	"00110100",
	"11011",
	"10010",
	"010111",
	"0110111",
	"00110110",
	"00110111",
	"01100100",
	"01100101",
	"01101000",
	"01100111",
	"011001100",
	"011001101",
	"011010010",
	"011010011",
	"011010100"
};

const char *zero_run_len_code_list[EGPRS_CODEWORDS] = {
	"0000110111",
	"10",
	"11",
	"010",
	"011",
	"0011",
	"0010",
	"00011",
	"000101",
	"000100",
	"0000100",
	"0000101",
	"0000111",
	"00000100",
	"00000111",
	"000011000",
	"0000010111",
	"0000011000",
	"0000001000",
	"00001100111",
	"00001101000",
	"00001101100",
	"00000110111",
	"00000101000",
	"00000010111",
	"00000011000",
	"000011001010",
	"000011001011",
	"000011001100",
	"000011001101",
	"000001101000",
	"000001101001",
	"000001101010",
	"000001101011",
	"000011010010",
	"000011010011",
	"000011010100",
	"000011010101",
	"000011010110",
	"000011010111",
	"000001101100",
	"000001101101",
	"000011011010",
	"000011011011",
	"000001010100",
	"000001010101",
	"000001010110",
	"000001010111",
	"000001100100",
	"000001100101",
	"000001010010",
	"000001010011",
	"000000100100",
	"000000110111",
	"000000111000",
	"000000100111",
	"000000101000",
	"000001011000",
	"000001011001",
	"000000101011",
	"000000101100",
	"000001011010",
	"000001100110",
	"000001100111",
	"0000001111",
	"000011001000",
	"000011001001",
	"000001011011",
	"000000110011",
	"000000110100",
	"000000110101",
	"0000001101100",
	"0000001101101",
	"0000001001010",
	"0000001001011",
	"0000001001100",
	"0000001001101",
	"0000001110010",
	"0000001110011"
};

/* Calculate runlength of a  codeword
 * \param root[in]  Root of Ones or Zeros tree
 * \param bmbuf[in] Received compressed bitmap buf
 * \param bit_pos[in] The start bit pos to read codeword
 * \param len_codewd[in] Length of code word
 * \param rlen[out] Calculated run length
 */
static int search_runlen(
		egprs_compress_node *root,
		const uint8_t *bmbuf,
		uint8_t bit_pos,
		uint8_t *len_codewd,
		uint16_t *rlen)
{
	egprs_compress_node *iter;
	uint8_t dir;

	iter = root;
	*len_codewd = 0;

	while (iter->run_length == -1) {
		if ((!iter->left) && (!iter->right))
			return -1;
		/* get the bit value at the bitpos and put it in right most of dir */
		dir = (bmbuf[bit_pos/8] >> (7 - (bit_pos & 0x07))) & 0x01;
		bit_pos++;
		(*len_codewd)++;
		if (!dir && (iter->left != NULL))
			iter = iter->left;
		else if (dir && (iter->right != NULL))
			iter = iter->right;
		else
			return -1;
	}
	LOGP(DRLCMACUL, LOGL_DEBUG, "Run_length = %d\n", iter->run_length);
	*rlen = iter->run_length;
	return 1;
}

/* Decompress received block bitmap
 * \param compress_bmap_len[in] Compressed bitmap length
 * \param start[in] Starting Color Code, true if bitmap starts with a run
 *	    	    length of ones, false if zeros; see 9.1.10, 3GPP 44.060.
 * \param orig_crbb_buf[in] Received block crbb bitmap
 * \param dest[out] Uncompressed bitvector
 */
int egprs_compress::decompress_crbb(
		int8_t compress_bmap_len,
		bool start,
		const uint8_t *orig_crbb_buf,
		bitvec *dest)
{

	uint8_t bit_pos = 0;
	uint8_t data;
	egprs_compress_node *list = NULL;
	uint8_t nbits = 0; /* number of bits of codeword */
	uint16_t run_length = 0;
	uint16_t cbmaplen = 0; /* compressed bitmap part after decompression */
	unsigned wp = dest->cur_bit;
	int rc = 0;
	egprs_compress *compress = instance();

	while (compress_bmap_len > 0) {
		if (start) {
			data = 0xff;
			list = compress->ones_list;
		} else {
			data = 0x00;
			list = compress->zeros_list;
		}
		rc = search_runlen(list, orig_crbb_buf,
				bit_pos, &nbits, &run_length);
		if (rc == -1)
			return -1;
		/* If run length > 64, need makeup and terminating code */
		if (run_length < 64)
			start = !start;
		cbmaplen = cbmaplen + run_length;
		/* put run length of Ones in uncompressed bitmap */
		while (run_length != 0) {
			if (run_length > 8) {
				bitvec_write_field(dest, wp, data, 8);
				run_length = run_length - 8;
			} else {
				bitvec_write_field(dest, wp, data, run_length);
				run_length = 0;
			}
		}
		bit_pos = bit_pos + nbits;
		compress_bmap_len = compress_bmap_len - nbits;
	}
	return 0;
}

void egprs_compress::decode_tree_init()
{
	ones_list = create_tree_node(tall_pcu_ctx);
	zeros_list = create_tree_node(tall_pcu_ctx);
	build_codewords(ones_list, one_run_len_code_list);
	build_codewords(zeros_list, zero_run_len_code_list);
}

egprs_compress::egprs_compress()
{
	decode_tree_init();
}

