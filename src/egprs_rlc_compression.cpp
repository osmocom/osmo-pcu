/* egprs_rlc_compression.h
*  Routines for EGPRS RLC bitmap compression handling
*/
#include <egprs_rlc_compression.h>
#include <errno.h>
#include <decoding.h>

extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/stats.h>
}

egprs_compress *egprs_compress::s_instance = 0;

/* Function to create tree node */
Node *egprs_compress::create_tree_node(void *parent)
{
	Node *new_node;

	new_node = talloc_zero(parent, Node);
	new_node->left = NULL;
	new_node->right = NULL;
	new_node->run_length = -1;
	return new_node;
}

/* Function to build the codeword tree
 * \param iter[in] Iterate the node on the tree
 * \param len[in] Length of the code word
 * \param i[in] Iterator
 * \param idx[in] Iterate index of the code word table
 */
void egprs_compress::build_codeword(Node *root, const char *cdwd[])
{
	Node *iter;
	int  len;
	int  i;
	int idx;

	for (idx = 0; idx < MAX_CDWDTBL_LEN; idx++) {
		len = strlen((const char *)cdwd[idx]);
		iter = root;
		for (i = 0;  i < len;  i++) {
			if (cdwd[idx][i] == '0') {
				if (!iter->left)
					iter->left = create_tree_node(root);
				iter = iter->left;
			} else if (cdwd[idx][i] == '1') {
				if (!iter->right)
					iter->right = create_tree_node(root);
				iter = iter->right;
			}
		}
		if (iter) {
			if (idx < 64)
				(iter->run_length) = idx;
			else
				(iter->run_length) = (idx - 63) * 64;
		}
	}
}

const char *one_run_len_code_list[MAX_CDWDTBL_LEN] = {
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

const char *zero_run_len_code_list[MAX_CDWDTBL_LEN] = {
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

/* search_runlen function will return the runlength for the codeword
 * \param root[in]  Root of Ones or Zeros tree
 * \param bmbuf[in] Recevied compressed bitmap buf
 * \param bit_pos[in] The start bit pos to read codeword
 * \param len_codewd[in] Length of code word
 * \param rlen[out] Run length value
 */
static int search_runlen(
		Node *root,
		const uint8_t *bmbuf,
		uint8_t bit_pos,
		uint8_t *len_codewd,
		uint16_t *rlen)
{
	Node *iter;
	uint8_t dir;

	iter = root;
	*len_codewd = 0;

	while (iter->run_length == -1) {
		if ((!iter->left) && (!iter->right))
			return -1;
		/* get the bit value at the bitpos and put it in right most of dir */
		dir = ((bmbuf[BITS_TO_BYTES(bit_pos)-1]
				>>(7-(MOD8(bit_pos)))) & 0x01);
		(bit_pos)++;
		(*len_codewd)++;
		if (((dir&0x01) == 0) && (iter->left != NULL))
			iter = iter->left;
		else if (((dir&0x01) == 1) && (iter->right != NULL))
			iter = iter->right;
		else
			return -1;
	}
	(*rlen) = (iter->run_length);
	return 1;
}

/* Function to decompress crbb
 * \param[in] Compressed bitmap length
 * \clr_code_bit[in] Color code 1 for Ones runlength 0 for Zero runlength
 * \orig_crbb_buf[in] Received block crbb bitmap
 * \dest[out] Uncompressed bitvector
 */
int decompress_crbb(
		int8_t compress_bmap_len,
		uint8_t clr_code_bit,
		const uint8_t *orig_crbb_buf,
		bitvec *dest)
{

	uint8_t bit_pos = 0;
	uint8_t data = 0x0;
	node *list = NULL;
	uint8_t nbits = 0; /* number of bits of codeword */
	uint16_t run_length = 0;
	uint16_t cbmaplen = 0; /* compressed bitmap part after decompression */
	unsigned wp = dest->cur_bit;
	int rc = 0;
	egprs_compress *compress = egprs_compress::instance();

	while (compress_bmap_len > 0) {
		if (clr_code_bit == 1) {
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
			clr_code_bit ? clr_code_bit = 0 : clr_code_bit = 1;
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

/* init function to build codeword */
int egprs_compress::decode_tree_init()
{
	ones_list = create_tree_node(tall_pcu_ctx);
	zeros_list = create_tree_node(tall_pcu_ctx);
	build_codeword(
			ones_list, one_run_len_code_list);
	build_codeword(
			zeros_list, zero_run_len_code_list);
	return 0;
}
