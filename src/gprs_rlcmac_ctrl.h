#ifndef _GPRS_RLCMAC_CTRL_H
#define _GPRS_RLCMAC_CTRL_H

#ifdef __cplusplus
extern "C"
#endif
int write_immediate_assignment_uplink(uint8_t *data, uint8_t ra, uint32_t fn,
	uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, uint8_t tfi,
	uint8_t usf, uint8_t polling, uint32_t poll_fn);

#ifdef __cplusplus
extern "C"
#endif
int write_immediate_assignment_downlink(uint8_t *data, uint8_t ra, uint32_t fn,
	uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, uint8_t tfi,
	uint32_t tlli, uint8_t polling, uint32_t poll_fn);

#ifdef __cplusplus
extern "C"
#endif
struct msgb *write_packet_uplink_assignment(uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
	struct gprs_rlcmac_tbf *tbf, uint8_t poll);

#ifdef __cplusplus
extern "C"
#endif
struct msgb *write_packet_downlink_assignment(uint8_t old_tfi,
	uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll);

#ifdef __cplusplus
extern "C"
#endif
struct msgb *write_packet_uplink_ack(struct gprs_rlcmac_tbf *tbf,
	uint8_t final);

#ifdef __cplusplus
extern "C"
#endif
struct msgb *gprs_rlcmac_send_packet_paging_request(
	struct gprs_rlcmac_pdch *pdch);

#ifdef __cplusplus
extern "C"
#endif
int gprs_rlcmac_rcv_control_block(uint8_t trx, uint8_t ts, uint32_t fn,
        uint8_t *data, uint8_t len);

#endif /* _GPRS_RLCMAC_CTRL_H */
