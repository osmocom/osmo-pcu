#pragma once

#include <stdint.h>
#include <osmocom/core/gsmtap_util.h>

int l1if_init(void);
void *l1if_open_trx(uint8_t bts_nr, uint8_t trx_no, uint32_t hlayer1, struct gsmtap_inst *gsmtap);
int l1if_connect_pdch(void *obj, uint8_t ts);
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn, uint16_t arfcn, uint8_t block_nr, uint8_t *data,
		  uint8_t len);
int l1if_disconnect_pdch(void *obj, uint8_t ts);
int l1if_close_trx(void *obj);
