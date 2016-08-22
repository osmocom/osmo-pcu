/* egprs_rlc_compression.h
 *  Routines for EGPRS RLC bitmap compression handling
 */

#pragma once

#include <gprs_rlcmac.h>
#include <gprs_debug.h>

extern "C" {
#include <osmocom/core/talloc.h>
}

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#define	MAX_CDWDTBL_LEN          79        /* total number of codewords */
#define	BITS_TO_BYTES(X)      ((X ? (X/8):0)+1)
#define	MOD8(X)             (((X)+8) & (0x07))

typedef struct node {
	struct node *left;
	struct node *right;
	int run_length;
} Node;

extern const char *one_run_len_code_list[MAX_CDWDTBL_LEN];
extern const char *zero_run_len_code_list[MAX_CDWDTBL_LEN];
extern void *tall_pcu_ctx;

int decompress_crbb(int8_t compress_bmap_len, uint8_t clr_code_bit,
			const uint8_t *orig_buf, bitvec *dest);

/* Creating singleton class
 */
class egprs_compress
{
	static egprs_compress *s_instance;

	egprs_compress()
	{
		if (decode_tree_init() < 0) {
			fprintf(stderr, "Error initializing tree\n");
			exit(1);
		}
	}
	Node *create_tree_node(void *);
	void build_codeword(Node *root, const char *cdwd[]);
	~egprs_compress();
public:
	Node *ones_list;
	Node *zeros_list;

	int decode_tree_init(void);

	static egprs_compress *instance()
	{
		if (!s_instance)
			s_instance = new egprs_compress;

		return s_instance;
	}
};
