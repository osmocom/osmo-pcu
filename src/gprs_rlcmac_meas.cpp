/* Measurements
 *
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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

extern "C" {
#include <osmocom/core/timer_compat.h>
}

#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <pcu_l1_if.h>
#include <tbf.h>
#include <tbf_dl.h>
#include <gprs_ms.h>

#include <string.h>
#include <errno.h>

/*
 * downlink measurement
 */
/* TODO: trigger the measurement report from the pollcontroller and use it for flow control */

/* received Measurement Report */
int gprs_rlcmac_meas_rep(Packet_Measurement_Report_t *pmr)
{
	NC_Measurement_Report_t *ncr;
	NC_Measurements_t *nc;
	int i;

	LOGP(DRLCMACMEAS, LOGL_INFO, "Measurement Report of TLLI=0x%08x:",
	     pmr->TLLI);

	switch (pmr->UnionType) {
	case 0:
		ncr = &pmr->u.NC_Measurement_Report;
		LOGPC(DRLCMACMEAS, LOGL_INFO, " NC%u Serv %d dbm",
			ncr->NC_MODE + 1,
			ncr->Serving_Cell_Data.RXLEV_SERVING_CELL - 110);
		for (i = 0; i < ncr->NUMBER_OF_NC_MEASUREMENTS; i++) {
			nc = &ncr->NC_Measurements[i];
			LOGPC(DRLCMACMEAS, LOGL_DEBUG, ", Neigh %u %d dbm",
				nc->FREQUENCY_N, nc->RXLEV_N - 110);
		}
		LOGPC(DRLCMACMEAS, LOGL_INFO, "\n");

		break;
	case 1:
		LOGPC(DRLCMACMEAS, LOGL_INFO,
			" <EXT Reporting not supported!>\n");
		break;
	}

	return 0;
}


/*
 * uplink measurement
 */

/* RSSI values received from MS */
int gprs_rlcmac_rssi(struct gprs_rlcmac_tbf *tbf, int8_t rssi)
{
	struct timespec now_tv, *rssi_tv = &tbf->meas.rssi_tv;
	struct timespec elapsed;

	tbf->meas.rssi_sum += rssi;
	tbf->meas.rssi_num++;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now_tv);

	timespecsub(&now_tv, rssi_tv, &elapsed);
	if (elapsed.tv_sec < 1)
		return 0;

	gprs_rlcmac_rssi_rep(tbf);

	/* reset rssi values and timestamp */
	memcpy(rssi_tv, &now_tv, sizeof(*rssi_tv));
	tbf->meas.rssi_sum = 0;
	tbf->meas.rssi_num = 0;

	return 0;
}

/* Give RSSI report */
int gprs_rlcmac_rssi_rep(struct gprs_rlcmac_tbf *tbf)
{
	/* No measurement values */
	if (!tbf->meas.rssi_num)
		return -EINVAL;

	LOGPMS(tbf->ms(), DRLCMACMEAS, LOGL_INFO, "UL RSSI: %d dBm\n",
	       tbf->meas.rssi_sum / tbf->meas.rssi_num);

	return 0;
}


/*
 * lost frames
 */

/* Lost frames reported from RLCMAC layer */
int gprs_rlcmac_received_lost(struct gprs_rlcmac_dl_tbf *tbf, uint16_t received,
	uint16_t lost)
{
	struct timespec now_tv, *loss_tv = &tbf->m_bw.dl_loss_tv;
	struct timespec elapsed;
	uint16_t sum = received + lost;

	/* No measurement values */
	if (!sum)
		return -EINVAL;

	LOGP(DRLCMACMEAS, LOGL_DEBUG, "DL Loss of TLLI 0x%08x: Received: %4d  "
		"Lost: %4d  Sum: %4d\n", tbf->tlli(), received, lost, sum);

	tbf->m_bw.dl_loss_received += received;
	tbf->m_bw.dl_loss_lost += lost;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now_tv);
	timespecsub(&now_tv, loss_tv, &elapsed);
	if (elapsed.tv_sec < 1)
		return 0;

	gprs_rlcmac_lost_rep(tbf);

	/* reset lost values and timestamp */
	memcpy(loss_tv, &now_tv, sizeof(*loss_tv));
	tbf->m_bw.dl_loss_received = 0;
	tbf->m_bw.dl_loss_lost = 0;

	return 0;
}

/* Give Lost report */
int gprs_rlcmac_lost_rep(struct gprs_rlcmac_dl_tbf *tbf)
{
	uint16_t sum = tbf->m_bw.dl_loss_lost + tbf->m_bw.dl_loss_received;

	/* No measurement values */
	if (!sum)
		return -EINVAL;

	LOGP(DRLCMACMEAS, LOGL_DEBUG, "DL packet loss of IMSI=%s / TLLI=0x%08x: "
		"%d%%\n", tbf->imsi(), tbf->tlli(),
		tbf->m_bw.dl_loss_lost * 100 / sum);

	return 0;
}


/*
 * downlink bandwidth
 */

int gprs_rlcmac_dl_bw(struct gprs_rlcmac_dl_tbf *tbf, uint16_t octets)
{
	struct timespec now_tv, *bw_tv = &tbf->m_bw.dl_bw_tv;
	struct timespec elapsed;

	tbf->m_bw.dl_bw_octets += octets;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now_tv);
	timespecsub(&now_tv, bw_tv, &elapsed);
	if (elapsed.tv_sec < 1)
		return 0;

	tbf->m_bw.dl_throughput = (tbf->m_bw.dl_bw_octets << 10) / ((elapsed.tv_sec << 10) + (elapsed.tv_nsec >> 20));
	LOGP(DRLCMACMEAS, LOGL_INFO, "DL Bandwitdh of IMSI=%s / TLLI=0x%08x: "
		"%d KBits/s\n", tbf->imsi(), tbf->tlli(), tbf->m_bw.dl_throughput);

	/* reset bandwidth values timestamp */
	memcpy(bw_tv, &now_tv, sizeof(*bw_tv));
	tbf->m_bw.dl_bw_octets = 0;

	return 0;
}
