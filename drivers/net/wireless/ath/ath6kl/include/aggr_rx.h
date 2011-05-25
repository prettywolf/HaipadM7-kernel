/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef AGGR_RX_H
#define AGGR_RX_H

#define AGGR_WIN_IDX(x, y)          ((x) % (y))
#define AGGR_INCR_IDX(x, y)         AGGR_WIN_IDX(((x)+1), (y))
#define AGGR_DCRM_IDX(x, y)         AGGR_WIN_IDX(((x)-1), (y))
#define IEEE80211_MAX_SEQ_NO        0xFFF
#define IEEE80211_NEXT_SEQ_NO(x)    (((x) + 1) & IEEE80211_MAX_SEQ_NO)


#define NUM_OF_TIDS         8
#define AGGR_SZ_DEFAULT     8

#define AGGR_WIN_SZ_MIN     2
#define AGGR_WIN_SZ_MAX     8

#define TID_WINDOW_SZ(_x)   ((_x) << 1)

#define AGGR_NUM_OF_FREE_NETBUFS    16

#define AGGR_GET_RXTID_STATS(_p, _x)    (&(_p->stat[(_x)]))
#define AGGR_GET_RXTID(_p, _x)    (&(_p->RxTid[(_x)]))

#define HOLD_Q_SZ(_x)   (TID_WINDOW_SZ((_x))*sizeof(struct osbuf_hold_q))
#define AGGR_RX_TIMEOUT     400  /* in ms */

/* Pkt log info */
struct pkt_log {
	struct info_t {
		u16 st;
		u16 end;
		u16 cur;
	}info[4096];
	u16 last_idx;
} __attribute__ ((packed));

struct osbuf_hold_q {
	void *osbuf;
	bool is_amsdu;
	u16 seq_no;
};

struct rxtid {
	bool aggr;
	bool progress;
	bool timerMon;
	u16 win_sz;
	u16 seq_next;
	u32 hold_q_sz;
	struct osbuf_hold_q *hold_q;
	struct sk_buff_head q;
	spinlock_t lock;
};

struct rxtid_stats {
	u32 num_into_aggr;
	u32 num_dups;
	u32 num_oow;
	u32 num_mpdu;
	u32 num_amsdu;
	u32 num_delivered;
	u32 num_timeouts;
	u32 num_hole;
	u32 num_bar;
};

struct aggr_info {
	u8 aggr_sz;
	u8 timerScheduled;
	struct timer_list    timer;
	void *dev;
	void (*rx_fn) (void *, void*);
	struct rxtid RxTid[NUM_OF_TIDS];
	void (*netbuf_allocator) (struct sk_buff_head  *, u16);
	struct sk_buff_head freeQ;
	struct rxtid_stats stat[NUM_OF_TIDS];
	struct pkt_log pkt_log;
};

void *
aggr_init(void (*netbuf_allocator)(struct sk_buff_head  *, u16));


void
aggr_register_rx_dispatcher(void *cntxt, void * dev,
			    void (*fn)(void *, void *));


void
aggr_process_bar(void *cntxt, u8 tid, u16 seq_no);


void
aggr_recv_addba_req_evt(void * cntxt, u8 tid, u16 seq_no, u8 win_sz);


void
aggr_recv_delba_req_evt(void * cntxt, u8 tid);

void
aggr_process_recv_frm(void *cntxt, u8 tid, u16 seq_no, bool is_amsdu, void **osbuf);

void
aggr_module_destroy(void *cntxt);

void
aggr_dump_stats(void *cntxt, struct pkt_log **log_buf);

void
aggr_reset_state(void *cntxt);

#endif
