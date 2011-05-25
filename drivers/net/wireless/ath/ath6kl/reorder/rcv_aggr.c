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

#include <ath6kl.h>
#include <a_debug.h>
#include "aggr_rx.h"

static void * aggr_get_osbuf(struct aggr_info *p_aggr)
{
	void *buf = NULL;

	if (skb_queue_len(&p_aggr->freeQ) < (AGGR_NUM_OF_FREE_NETBUFS >> 2))
		p_aggr->netbuf_allocator(&p_aggr->freeQ, AGGR_NUM_OF_FREE_NETBUFS);

	if (skb_queue_len(&p_aggr->freeQ))
		buf = skb_dequeue(&p_aggr->freeQ);

	return buf;
}

static void aggr_dispatch_frames(struct aggr_info *p_aggr, struct sk_buff_head  *q)
{
	void *osbuf;

	while((osbuf = skb_dequeue(q)))
		p_aggr->rx_fn(p_aggr->dev, osbuf);
}

static void
aggr_slice_amsdu(struct aggr_info *p_aggr, struct rxtid *rxtid, void **osbuf)
{
	void *new_buf;
	u16 frame_8023_len, payload_8023_len, mac_hdr_len, amsdu_len;
	u8 *framep;

	mac_hdr_len = sizeof(ATH_MAC_HDR);
	framep = ((struct sk_buff *) *osbuf)->data + mac_hdr_len;
	amsdu_len = ((struct sk_buff *) *osbuf)->len - mac_hdr_len;

	while(amsdu_len > mac_hdr_len) {
		/* Begin of a 802.3 frame */
		payload_8023_len = ntohs(((ATH_MAC_HDR *)framep)->typeOrLen);
#define MAX_MSDU_SUBFRAME_PAYLOAD_LEN 1508
#define MIN_MSDU_SUBFRAME_PAYLOAD_LEN 46
		if(payload_8023_len < MIN_MSDU_SUBFRAME_PAYLOAD_LEN || payload_8023_len > MAX_MSDU_SUBFRAME_PAYLOAD_LEN) {
			A_PRINTF("802.3 AMSDU frame bound check failed. len %d\n", payload_8023_len);
			break;
		}
		frame_8023_len = payload_8023_len + mac_hdr_len;
		new_buf = aggr_get_osbuf(p_aggr);
		if(new_buf == NULL) {
			A_PRINTF("No buffer available \n");
			break;
		}

		memcpy(((struct sk_buff *) new_buf)->data, framep, frame_8023_len);
		skb_put(new_buf, frame_8023_len);
		if (wmi_dot3_2_dix(new_buf) != 0) {
			A_PRINTF("dot3_2_dix err..\n");
			dev_kfree_skb(new_buf);
			break;
		}

		skb_queue_tail(&rxtid->q, new_buf);

		/* Is this the last subframe within this aggregate ? */
		if ((amsdu_len - frame_8023_len) == 0) {
			break;
		}

		/* Add the length of A-MSDU subframe padding bytes -
		 * Round to nearest word.
		 */
		frame_8023_len = ((frame_8023_len + 3) & ~3);

		framep += frame_8023_len;
		amsdu_len -= frame_8023_len;
	}

	dev_kfree_skb(*osbuf);
	*osbuf = NULL;
}

static void
aggr_deque_frms(struct aggr_info *p_aggr, u8 tid, u16 seq_no, u8 order)
{
	struct rxtid *rxtid;
	struct osbuf_hold_q *node;
	u16 idx, idx_end, seq_end;
	struct rxtid_stats *stats;

	if (!p_aggr)
		return;

	rxtid = AGGR_GET_RXTID(p_aggr, tid);
	stats = AGGR_GET_RXTID_STATS(p_aggr, tid);

	idx = AGGR_WIN_IDX(rxtid->seq_next, rxtid->hold_q_sz);

	/* idx_end is typically the last possible frame in the window,
	 * but changes to 'the' seq_no, when BAR comes. If seq_no
	 * is non-zero, we will go up to that and stop.
	 * Note: last seq no in current window will occupy the same
	 * index position as index that is just previous to start.
	 * An imp point : if win_sz is 7, for seq_no space of 4095,
	 * then, there would be holes when sequence wrap around occurs.
	 * Target should judiciously choose the win_sz, based on
	 * this condition. For 4095, (TID_WINDOW_SZ = 2 x win_sz
	 * 2, 4, 8, 16 win_sz works fine).
	 * We must deque from "idx" to "idx_end", including both.
	 */
	seq_end = (seq_no) ? seq_no : rxtid->seq_next;
	idx_end = AGGR_WIN_IDX(seq_end, rxtid->hold_q_sz);

	spin_lock_bh(&rxtid->lock);
	do {

		node = &rxtid->hold_q[idx];

		if((order == 1) && (!node->osbuf))
			break;

		if(node->osbuf) {
			if(node->is_amsdu) {
				aggr_slice_amsdu(p_aggr, rxtid, &node->osbuf);
			} else {
				skb_queue_tail(&rxtid->q, node->osbuf);
			}
			node->osbuf = NULL;
		} else {
			stats->num_hole++;
		}

		rxtid->seq_next = IEEE80211_NEXT_SEQ_NO(rxtid->seq_next);
		idx = AGGR_WIN_IDX(rxtid->seq_next, rxtid->hold_q_sz);
	} while(idx != idx_end);
	spin_unlock_bh(&rxtid->lock);

	stats->num_delivered += skb_queue_len(&rxtid->q);
	aggr_dispatch_frames(p_aggr, &rxtid->q);
}

static void
aggr_timeout(unsigned long arg)
{
	u8 i,j;
	struct aggr_info *p_aggr = (struct aggr_info *)arg;
	struct rxtid   *rxtid;
	struct rxtid_stats *stats;

	for(i = 0; i < NUM_OF_TIDS; i++) {
		rxtid = AGGR_GET_RXTID(p_aggr, i);
		stats = AGGR_GET_RXTID_STATS(p_aggr, i);

		if(rxtid->aggr == false ||
				rxtid->timerMon == false ||
				rxtid->progress == true) {
			continue;
		}

		stats->num_timeouts++;
		A_PRINTF("TO: st %d end %d\n", rxtid->seq_next, ((rxtid->seq_next + rxtid->hold_q_sz-1) & IEEE80211_MAX_SEQ_NO));
		aggr_deque_frms(p_aggr, i, 0, 0);
	}

	p_aggr->timerScheduled = false;
	for(i = 0; i < NUM_OF_TIDS; i++) {
		rxtid = AGGR_GET_RXTID(p_aggr, i);

		if(rxtid->aggr == true && rxtid->hold_q) {
			for(j = 0 ; j < rxtid->hold_q_sz ; j++)
			{
				if(rxtid->hold_q[j].osbuf)
				{
					p_aggr->timerScheduled = true;
					rxtid->timerMon = true;
					rxtid->progress = false;
					break;
				}
			}

			if(j >= rxtid->hold_q_sz) {
				rxtid->timerMon = false;
			}
		}
	}

	if(p_aggr->timerScheduled)
		mod_timer(&p_aggr->timer,
			  jiffies + msecs_to_jiffies(AGGR_RX_TIMEOUT));
}

void *
aggr_init(void (*netbuf_allocator)(struct sk_buff_head  *q, u16 num))
{
	struct aggr_info   *p_aggr = NULL;
	struct rxtid *rxtid;
	u8 i;
	int status = 0;

	A_PRINTF("In aggr_init..\n");

	p_aggr = kzalloc(sizeof(struct aggr_info), GFP_KERNEL);
	if(!p_aggr) {
		A_PRINTF("Failed to allocate memory for aggr_node\n");
		status = -ENOMEM;
		goto out;
	}

	p_aggr->aggr_sz = AGGR_SZ_DEFAULT;

	init_timer(&p_aggr->timer);
	p_aggr->timer.function = aggr_timeout;
	p_aggr->timer.data = (unsigned long) p_aggr;

	p_aggr->timerScheduled = false;
	skb_queue_head_init(&p_aggr->freeQ);

	p_aggr->netbuf_allocator = netbuf_allocator;
	p_aggr->netbuf_allocator(&p_aggr->freeQ, AGGR_NUM_OF_FREE_NETBUFS);

	for(i = 0; i < NUM_OF_TIDS; i++) {
		rxtid = AGGR_GET_RXTID(p_aggr, i);
		rxtid->aggr = false;
		rxtid->progress = false;
		rxtid->timerMon = false;
		skb_queue_head_init(&rxtid->q);
		spin_lock_init(&rxtid->lock);
	}

out:
	A_PRINTF("going out of aggr_init..status %s\n",
			(status == 0) ? "OK":"Error");

	if (status)
		aggr_module_destroy(p_aggr);

	return (status == 0) ? p_aggr : NULL;
}

static void aggr_delete_tid_state(struct aggr_info *p_aggr, u8 tid)
{
	struct rxtid *rxtid;
	struct rxtid_stats *stats;

	if (!p_aggr || tid >= NUM_OF_TIDS)
		return;

	rxtid = AGGR_GET_RXTID(p_aggr, tid);
	stats = AGGR_GET_RXTID_STATS(p_aggr, tid);

	if(rxtid->aggr)
		aggr_deque_frms(p_aggr, tid, 0, 0);

	rxtid->aggr = false;
	rxtid->progress = false;
	rxtid->timerMon = false;
	rxtid->win_sz = 0;
	rxtid->seq_next = 0;
	rxtid->hold_q_sz = 0;

	if(rxtid->hold_q) {
		kfree(rxtid->hold_q);
		rxtid->hold_q = NULL;
	}

	memset(stats, 0, sizeof(struct rxtid_stats));
}

void aggr_module_destroy(void *cntxt)
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;
	struct rxtid *rxtid;
	u8 i, k;

	A_PRINTF("%s(): aggr = %p\n",_A_FUNCNAME_, p_aggr);

	if (!p_aggr)
		return;

	if(p_aggr->timerScheduled) {
		del_timer(&p_aggr->timer);
		p_aggr->timerScheduled = false;
	}

	for(i = 0; i < NUM_OF_TIDS; i++) {
		rxtid = AGGR_GET_RXTID(p_aggr, i);
		if(rxtid->hold_q) {
			for(k = 0; k< rxtid->hold_q_sz; k++) {
				if(rxtid->hold_q[k].osbuf)
					dev_kfree_skb(rxtid->hold_q[k].osbuf);
			}
			kfree(rxtid->hold_q);
		}

		while(skb_queue_len(&rxtid->q))
			dev_kfree_skb(skb_dequeue(&rxtid->q));
	}

	while(skb_queue_len(&p_aggr->freeQ))
		dev_kfree_skb(skb_dequeue(&p_aggr->freeQ));

	kfree(p_aggr);
	A_PRINTF("out aggr_module_destroy\n");
}


void
aggr_register_rx_dispatcher(void *cntxt, void * dev,
		void (*fn)(void *dev, void *osbuf))
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;

	if (!p_aggr || !fn || !dev)
		return;

	p_aggr->rx_fn = fn;
	p_aggr->dev = dev;
}

void
aggr_process_bar(void *cntxt, u8 tid, u16 seq_no)
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;
	struct rxtid_stats *stats;

	if (!p_aggr)
		return;
	stats = AGGR_GET_RXTID_STATS(p_aggr, tid);
	stats->num_bar++;

	aggr_deque_frms(p_aggr, tid, seq_no, 0);
}

void
aggr_recv_addba_req_evt(void *cntxt, u8 tid, u16 seq_no, u8 win_sz)
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;
	struct rxtid *rxtid;
	struct rxtid_stats *stats;

	if (!p_aggr)
		return;

	rxtid = AGGR_GET_RXTID(p_aggr, tid);
	stats = AGGR_GET_RXTID_STATS(p_aggr, tid);

	A_PRINTF("%s(): win_sz = %d aggr %d\n", _A_FUNCNAME_, win_sz, rxtid->aggr);

	if(win_sz < AGGR_WIN_SZ_MIN || win_sz > AGGR_WIN_SZ_MAX) {
		A_PRINTF("win_sz %d, tid %d\n", win_sz, tid);
	}

	if(rxtid->aggr)
		aggr_delete_tid_state(p_aggr, tid);

	rxtid->seq_next = seq_no;
	rxtid->hold_q = kzalloc(HOLD_Q_SZ(win_sz), GFP_KERNEL);
	if((rxtid->hold_q == NULL))
		BUG_ON(true);

	rxtid->win_sz = win_sz;
	rxtid->hold_q_sz = TID_WINDOW_SZ(win_sz);
	if(skb_queue_len(&rxtid->q) != 0)
		BUG_ON(true);

	rxtid->aggr = true;
}

void
aggr_recv_delba_req_evt(void *cntxt, u8 tid)
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;
	struct rxtid *rxtid;

	if (!p_aggr)
		return;

	A_PRINTF("%s(): tid %d\n", _A_FUNCNAME_, tid);

	rxtid = AGGR_GET_RXTID(p_aggr, tid);

	if(rxtid->aggr)
		aggr_delete_tid_state(p_aggr, tid);
}

void
aggr_process_recv_frm(void *cntxt, u8 tid, u16 seq_no, bool is_amsdu, void **osbuf)
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;
	struct rxtid *rxtid;
	struct rxtid_stats *stats;
	u16 idx, st, cur, end;
	u16 *log_idx;
	struct osbuf_hold_q *node;
	struct pkt_log *log;

	rxtid = AGGR_GET_RXTID(p_aggr, tid);
	stats = AGGR_GET_RXTID_STATS(p_aggr, tid);

	stats->num_into_aggr++;

	if(!rxtid->aggr) {
		if(is_amsdu) {
			aggr_slice_amsdu(p_aggr, rxtid, osbuf);
			stats->num_amsdu++;
			aggr_dispatch_frames(p_aggr, &rxtid->q);
		}
		return;
	}

	/* Check the incoming sequence no, if it's in the window */
	st = rxtid->seq_next;
	cur = seq_no;
	end = (st + rxtid->hold_q_sz-1) & IEEE80211_MAX_SEQ_NO;
	/* Log the pkt info for future analysis */
	log = &p_aggr->pkt_log;
	log_idx = &log->last_idx;
	log->info[*log_idx].cur = cur;
	log->info[*log_idx].st = st;
	log->info[*log_idx].end = end;
	*log_idx = IEEE80211_NEXT_SEQ_NO(*log_idx);

	if(((st < end) && (cur < st || cur > end)) ||
			((st > end) && (cur > end) && (cur < st))) {
		u16 extended_end;

		extended_end = (end + rxtid->hold_q_sz-1) & IEEE80211_MAX_SEQ_NO;

		if(((end < extended_end) && (cur < end || cur > extended_end)) ||
				((end > extended_end) && (cur > extended_end) && (cur < end))) {
			// dequeue all frames in queue and shift window to new frame
			aggr_deque_frms(p_aggr, tid, 0, 0);
			//set window start so that new frame is last frame in window
			if(cur >= rxtid->hold_q_sz-1) {
				rxtid->seq_next = cur - (rxtid->hold_q_sz-1);
			}else{
				rxtid->seq_next = IEEE80211_MAX_SEQ_NO - (rxtid->hold_q_sz-2 - cur);
			}
		} else {
			// dequeue only those frames that are outside the new shifted window
			if(cur >= rxtid->hold_q_sz-1) {
				st = cur - (rxtid->hold_q_sz-1);
			}else{
				st = IEEE80211_MAX_SEQ_NO - (rxtid->hold_q_sz-2 - cur);
			}

			aggr_deque_frms(p_aggr, tid, st, 0);
		}

		stats->num_oow++;
	}

	idx = AGGR_WIN_IDX(seq_no, rxtid->hold_q_sz);

	node = &rxtid->hold_q[idx];

	spin_lock_bh(&rxtid->lock);
	if(node->osbuf) {
		/* Is the cur frame duplicate or something beyond our
		 * window(hold_q -> which is 2x, already)?
		 * 1. Duplicate is easy - drop incoming frame.
		 * 2. Not falling in current sliding window.
		 *  2a. is the frame_seq_no preceding current tid_seq_no?
		 *      -> drop the frame. perhaps sender did not get our ACK.
		 *         this is taken care of above.
		 *  2b. is the frame_seq_no beyond window(st, TID_WINDOW_SZ);
		 *      -> Taken care of it above, by moving window forward.
		 *
		 */
		dev_kfree_skb(node->osbuf);
		stats->num_dups++;
	}

	node->osbuf = *osbuf;
	node->is_amsdu = is_amsdu;
	node->seq_no = seq_no;
	if(node->is_amsdu) {
		stats->num_amsdu++;
	} else {
		stats->num_mpdu++;
	}
	spin_unlock_bh(&rxtid->lock);

	*osbuf = NULL;
	aggr_deque_frms(p_aggr, tid, 0, 1);

	if(p_aggr->timerScheduled) {
		rxtid->progress = true;
	}else{
		for(idx=0 ; idx<rxtid->hold_q_sz ; idx++) {
			if(rxtid->hold_q[idx].osbuf) {
				/* there is a frame in the queue and no timer so
				 * start a timer to ensure that the frame doesn't remain
				 * stuck forever. */
				p_aggr->timerScheduled = true;
				mod_timer(&p_aggr->timer,
					(jiffies + HZ * (AGGR_RX_TIMEOUT) / 1000));

				rxtid->progress = false;
				rxtid->timerMon = true;
				break;
			}
		}
	}
}

void
aggr_reset_state(void *cntxt)
{
	u8 tid;
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;

	for(tid=0 ; tid<NUM_OF_TIDS ; tid++)
		aggr_delete_tid_state(p_aggr, tid);
}

void
aggr_dump_stats(void *cntxt, struct pkt_log **log_buf)
{
	struct aggr_info *p_aggr = (struct aggr_info *)cntxt;
	struct rxtid   *rxtid;
	struct rxtid_stats *stats;
	u8 i;

	*log_buf = &p_aggr->pkt_log;
	A_PRINTF("\n\n================================================\n");
	A_PRINTF("tid: num_into_aggr, dups, oow, mpdu, amsdu, delivered, timeouts, holes, bar, seq_next\n");
	for(i = 0; i < NUM_OF_TIDS; i++) {
		stats = AGGR_GET_RXTID_STATS(p_aggr, i);
		rxtid = AGGR_GET_RXTID(p_aggr, i);
		A_PRINTF("%d: %d %d %d %d %d %d %d %d %d : %d\n", i, stats->num_into_aggr, stats->num_dups,
				stats->num_oow, stats->num_mpdu,
				stats->num_amsdu, stats->num_delivered, stats->num_timeouts,
				stats->num_hole, stats->num_bar,
				rxtid->seq_next);
	}
	A_PRINTF("================================================\n\n");

}
