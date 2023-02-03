#pragma once

#include <stdint.h>
#include <osmocom/abis/e1_input.h>
#include "er_ccu_descr.h"

int er_ccu_if_open(struct er_ccu_descr *ccu_descr);
void er_ccu_if_close(struct er_ccu_descr *ccu_descr);
void er_ccu_if_tx(struct er_ccu_descr *ccu_descr, const ubit_t *bits, unsigned int num_bits);
void er_ccu_if_init(void *ctx);
