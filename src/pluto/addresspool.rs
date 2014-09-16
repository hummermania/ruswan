/*
 * addresspool management functions used with left/rightaddresspool= option.
 * Currently used for IKEv1 XAUTH/ModeConfig options if we are an XAUTH server.
 *
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

/* Address Pools
 *
 * With XAUTH, we need a way to allocate an address to a client.
 * This address must be unique on our system.
 * The pools of addresses to be used are declared in our config file.
 * Each connection may specify a pool as a range of IPv4 addresses.
 * All pools must be non-everlapping, but each pool may be
 * used for more than one connection.
 */

/*
#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "connections.h"
#include "defs.h"
#include "constants.h"
#include "addresspool.h"
*/

//extern crate connections;
extern crate connections;
use std::mem;




mod addresspool {

struct ip_pool_old {
	refcnt: uint,    /* reference counted! */
	start: ip_address,
	end: ip_address,
	size: i32,
	lease_list: &lease_addr_list
}

struct lease_addr {
	index: u32,        /* index in addresspool. The first address 0 */
	thatid:  id,       /* from connection */
	starts: time_t,    /* first time it was leased to this id */
	ends: time_t,       /* 0 is never. > 0 is when it ended */
	next: lease_addr
}

struct ip_pool {
	refcnt: uint,    /* reference counted! */
	start: ip_address,
	end: ip_address,
	size: u32,
	used: u32,
	cached: u32,
	lease: &lease_addr,
	next: &ip_pool
}

struct monotime_t { 
	mono_secs: time_t 
}


/*
 * head of chained addresspool list
 * addresspool come from ipsec.conf or whacked connection.
 */
static mut pluto_pools: ip_pool = None;

/* note: free_lease_entry returns a pointer to h's list successor.
 * The caller MUST use this to replace the linked list's pointer to h.
 */
pub fn free_lease_entry(h: lease_addr) -> lease_addr
{
	test::test_mod.foo();
	let mut next: lease_addr = h.next;

	DBG(DBG_CONTROL, DBG_log("addresspool free lease entry ptr %p refcnt %u",
		h, h.refcnt));

	//free_id_content(h.thatid);
	//pfree(h);
	return next;
}

pub fn free_lease_list(mut head: lease_addr)
{
	DBG(DBG_CONTROL,
	    DBG_log("%s: addresspool free the lease list ptr %p",
		    __func__, head));
	while head != None {
		head = free_lease_entry(head);
	}
}

/*
 *search for a lease in a pool with index i
 *
 * tricky: returns a pointer to the pointer that connects the lease.
 * This allows efficient removal.
 * It the index isn't found, NULL is returned (not a pointer to the
 * pointer to NULL).
 */
pub fn ref_to_lease(pool: ip_pool, i: u32 ) -> Option<Box<Box<lease_addr>>> {
	
	let pp: Box<Box<lease_addr>>; // TODO: Check if double boxed is realy needed 
	let p: Box<lease_addr>;

	for pp in  &pool.leases {
		if p.index == i {
			return pp;
		}
	}
	return None;
}

/*
 * mark a lease as ended.
 *
 * If the ID is distinctive and uniqueid is set, the lease "lingers"
 * so that the same client can be reassigned the same address.
 * A lingering lease is available to be re-activated
 * by lease_an_address/find_lingering_lease to the same thatid when uniqueid is
 * set.
 *
 * If uniqueIDs is set or thatid is ID_NONE, we don't know how to share.
 * In that case, we do free the lease since that ID isn't distinctive.
 * Note: without sharing the refcnt should be 1.
 */

pub fn rel_lease_addr(c: &connection) {
	let pool: ip_pool = c.pool;
	let i: u32;	/* index within range of IPv4 address to be released */
	let refcnt: uint;	/* for DBG logging */
	let story: &str;	/* for DBG logging */

	if !c.spd.that.has_lease {
		return; /* it is not from the addresspool to free */
	}

	passert(addrtypeof(&c.spd.that.client.addr) == AF_INET);

	/* i is index of client.addr within pool's range.
	 * Using unsigned arithmetic means that if client.addr is less than
	 * start, i will wrap around to a very large value.
	 * Therefore a single test against size will indicate
	 * membership in the range.
	 */
	i = ntohl(c.spd.that.client.addr.u.v4.sin_addr.s_addr) -
	    ntohl(pool.r.start.u.v4.sin_addr.s_addr);

	passert(i < pool.size);

	{
		let pp: Box<Box<lease_addr>> = ref_to_lease(pool, i);
		let p: Box<lease_addr>;

		passert(pp != NULL);	/* not found */

		p = *pp;

		if (could_share_lease(c)) {
			/* we could share, so leave lease lingering */
			story = "left (shared)";
			passert(p.refcnt > 0);
			p.refcnt -= 1;
			if (p.refcnt == 0) {
				story = "left (to linger)";
				pool.lingering += 1;
				p.lingering_since = mononow();
			}
			refcnt = p.refcnt;
		} else {
			/* cannot share: free it */
			story = "freed";
			passert(p.refcnt == 1);
			p.refcnt -= 1;
			refcnt = p.refcnt;
			*pp = free_lease_entry(p);
			pool.used -= 1;
		}
	}

	c.spd.that.has_lease = FALSE;

	DBG(DBG_CONTROLMORE, {
		/* text of addresses */
		let ta_client: [char, ..ADDRTOT_BUF];
		let ta_range:  [char, ..RANGETOT_BUF];

		addrtot(&c.spd.that.client.addr, 0, ta_client, mem::size_of_val(ta_client));
		rangetot(&pool.r, 0, ta_range, mem::size_of_val(ta_range));
		DBG_log("%s lease refcnt %u %s from addresspool %s index=%u. pool size %u used %u lingering=%u address",
				story,
				refcnt, ta_client, ta_range, i,
				pool.size, pool.used,
				pool.lingering);
	});
}

/*
 * return previous lease if there is one lingering for the same ID
 * but only if uniqueIDs, and ID_NONE does not count.
 */
pub fn share_lease(c: &connection, index: u32) -> bool {
	let mut p: Box<lease_addr>;
	let mut r: bool = false;

	if !could_share_lease(c) {
		return false;
	}

	for p in c.pool.leases {
		if (same_id(&p.thatid, &c.spd.that.id)) {
			*index = p.index;
			if (p.refcnt == 0) {
				c.pool.lingering -= 1;
				c.pool.used += 1;
			}
			p.refcnt +=1;
			r = TRUE;
			break;
		}
	}

	DBG(DBG_CONTROLMORE, {
			let thatid: [char, ..IDTOA_BUF];

			idtoa(&c.spd.that.id, thatid, mem::size_of_val(thatid));
			if (r) {
				let abuf: [char, ..ADDRTOT_BUF];
				let ip_address: ipaddr;
				let addr: u32 = ntohl(c.pool.r.start.u.v4.sin_addr.s_addr) + *index;
				let addr_nw: u32 = htonl(addr);

				initaddr(&addr_nw, mem::size_of_val(addr_nw), AF_INET, &ipaddr);
				addrtot(&ipaddr, 0, abuf, mem::size_of_val(abuf));

				DBG_log("in %s: found a lingering addresspool lease %s refcnt %d for '%s'",
					__func__,
					abuf,
					p.refcnt,
					thatid);
			} else {
				DBG_log("in %s: no lingering addresspool lease for '%s'",
					__func__,
					thatid);
			}
		});

	return r;
}

pub fn lease_an_address(c: &connection, 
						ipa: ip_address  ) -> err_t {
	/*
	 * index within address range
	 * Initialized just to silence GCC.
	 */
	let mut i: u32 = 0;
	let s: bool;

	DBG(DBG_CONTROL, {
		let rbuf: [char, ..RANGETOT_BUF];
		let thatidbuf: [char, ..IDTOA_BUF];
		let abuf: [char, ..ADDRTOT_BUF];

		rangetot(&c.pool.r, 0, rbuf, mem::size_of_val(rbuf));
		idtoa(&c.spd.that.id, thatidbuf, mem::size_of_val(thatidbuf));
		addrtot(&c.spd.that.client.addr, 0, abuf, mem::size_of_val(abuf));

		/* ??? what is that.client.addr and why do we care? */
		DBG_log("request lease from addresspool %s reference count %u thatid '%s' that.client.addr %s",
			rbuf, c.pool.pool_refcount, thatidbuf, abuf);
	});

	s = share_lease(c, &i);
	if (!s) {
		/*
		 * cannot find or cannot share an existing lease:
		 * allocate a new one
		 */
		let size: u32 = c.pool.size;
		let pp: Box<Box<lease_addr>>;
		let p: Box<lease_addr>;
		let ll: Box<lease_addr>;	/* longest lingerer */

		for pp in &c.pool.leases {
			/* check that list of leases is
			 * monotonically increasing.
			 */
			passert(p.index >= i);
			if p.index > i {
				break;
			}
			/* remember the longest lingering lease found */
			if p.refcnt == 0 &&
			    (ll == NULL ||
			     monobefore(ll.lingering_since, p.lingering_since)) {
			    	ll = p;	
			    }
				
			/* Subtle point: this addition won't overflow.
			 * 0.0.0.0 cannot be in a range
			 * so the size will be less than 2^32.
			 * No index can equal size
			 * so i cannot exceed it.
			 */
			i = p.index + 1;
		}

		if i < size {
			/* we can allocate a new address and lease */
			let a: Box<lease_addr> = alloc_thing(lease_addr, "address lease entry");

			a.index = i;
			a.refcnt = 1;
			c.pool.used += 1;

			duplicate_id(&a.thatid, &c.spd.that.id);

			a.next = p;
			*pp = a;

			DBG(DBG_CONTROLMORE,
				DBG_log("New lease from addresspool index %u", i));
		} else if (ll != NULL) {
			/* we take over this lingering lease */
			DBG(DBG_CONTROLMORE, {
				let thatidbuf: [char, ..IDTOA_BUF];

				idtoa(&ll.thatid, thatidbuf, mem::size_of_val(thatidbuf));
				DBG_log("grabbed lingering lease index %u from %s",
					i, thatidbuf);
			});
			free_id_content(&ll.thatid);
			duplicate_id(&ll.thatid, &c.spd.that.id);
			c.pool.lingering -= -1;
			ll.refcnt += 1;
			i = ll.index;
		} else {
			DBG(DBG_CONTROL,
			    DBG_log("no free address within pool; size %u, used %u, lingering %u",
				size, c.pool.used, c.pool.lingering));
			passert(size == c.pool.used);
			return "no free address in addresspool";
		}
	}

	/* convert index i in range to an IP_address */
	{
		let addr: u32 = ntohl(c.pool.r.start.u.v4.sin_addr.s_addr) + i;
		let addr_nw: u32 = htonl(addr);
		let e: err_t = initaddr(&addr_nw, mem::size_of_val(addr_nw),
			     AF_INET, ipa);

		if e != NULL {
			return e;
		}
	}

	DBG(DBG_CONTROL, {
		let rbuf: [char, ..RANGETOT_BUF];
		let thatidbuf: [char, ..IDTOA_BUF];
		let abuf: [char, ..ADDRTOT_BUF];
		let lbuf: [char, ..ADDRTOT_BUF];

		rangetot(&c.pool.r, 0, rbuf, mem::size_of_val(rbuf));
		idtoa(&c.spd.that.id, thatidbuf, mem::size_of_val(thatidbuf));
		addrtot(&c.spd.that.client.addr, 0, abuf, mem::size_of_val(abuf));
		addrtot(ipa, 0, lbuf, mem::size_of_val(lbuf));

		DBG_log("%s lease %s from addresspool %s to that.client.addr %s thatid '%s'",
			match s { true => "re-use", false => "new"},
			lbuf, rbuf, abuf, thatidbuf);
	});

	return NULL;
}

pub fn free_addresspool(pool: &ip_pool) {
	let pp: Box<Box<ip_pool>>;
	let p: Box<ip_pool>;

	/* search for pool in list of pools so we can unlink it */
	if pool == NULL {
		return;
	}

	for pp in &pluto_pools {
		if p == pool {
			*pp = p.next;	/* unlink pool */
			free_lease_list(&pool.leases);
			pfree(pool);
			return;
		}
	}
	DBG_log("%s addresspool %p not found in list of pools", __func__,
		pool);
}

pub fn unreference_addresspool(c: &connection) {
	let pool: Box<ip_pool> = c.pool;

	DBG(DBG_CONTROLMORE, DBG_log("unreference addresspool of conn %s [%lu] kind %s refcnt %u",
				c.name, c.instance_serial,
				enum_name(&connection_kind_names,
					c.kind), pool.pool_refcount));

	passert(pool.pool_refcount > 0);

	pool.pool_refcount -= 1;
	if (pool.pool_refcount == 0) {
		DBG(DBG_CONTROLMORE,
				DBG_log("freeing memory for addresspool ptr %p",
					pool));
		free_addresspool(pool);
	}

	c.pool = NULL;
}

pub fn reference_addresspool(pool: &ip_pool) {
	pool.pool_refcount += 1;
}

/*
 * Finds an ip_pool that has exactly matching bounds.
 * If a pool overlaps, an error is logged AND returned
 * *pool is set to the entry found; NULL if none found.
 */
pub fn find_addresspool(pool_range: &ip_range, pool: &Box<Box<ip_pool>>) -> err_t {
	let h: Box<ip_pool>;

	*pool = NULL;	/* nothing found (yet) */
	for h in pluto_pools {
		let a = pool_range;
		let b = &h.r;

		let sc: int = addrcmp(&a.start, &b.start);

		if sc == 0 && addrcmp(&a.end, &b.end) == 0 {
			/* exact match */
			*pool = h;
			break;
		} else if match sc < 0 { 
					true => addrcmp(&a.end, &b.start) < 0,
					false => addrcmp(&a.start, &b.end) > 0 } {
			/* before or after */
		} else {
			/* overlap */
			let prbuf: [char, ..RANGETOT_BUF];
			let hbuf: [char, ..RANGETOT_BUF];

			rangetot(pool_range, 0, prbuf, mem::size_of_val(prbuf));
			rangetot(&h.r, 0, hbuf, mem::size_of_val(hbuf));
			loglog(RC_CLASH,
				"ERROR: new addresspool %s INEXACTLY OVERLAPS with existing one %s.",
					prbuf, hbuf);
			return "ERROR: partial overlap of addresspool";
		}
	}
	return NULL;
}

/*
 * the caller must enforce the following:
 * - Range must not include 0.0.0.0
 * - Only IPv4 allowed.
 * - The range must be non-empty
 */
pub fn install_addresspool(pool_range: &ip_range) -> &ip_pool {
	let head: Box<Box<ip_pool>> = &pluto_pools;
	let p: Box<ip_pool>;
	let ugh: err_t = find_addresspool(pool_range, &p);

	if ugh != NULL {
		/* some problem: refuse to install bad addresspool */
		/* ??? Assume diagnostic already logged? */
	} else if p != NULL {
		/* re-use existing pool p */
		reference_addresspool(p);
		DBG(DBG_CONTROLMORE, {
			let rbuf:[char, ..RANGETOT_BUF];

			rangetot(&p.r, 0, rbuf, mem::size_of_val(rbuf));
			DBG_log("re-use addresspool %s exists ref count %u used %u size %u ptr %p re-use it",
				rbuf, p.pool_refcount, p.used, p.size, p);
		});
	} else {
		/* make a new pool */
		p = alloc_thing(ip_pool, "addresspool entry");

		p.pool_refcount = 0;
		reference_addresspool(p);
		p.r = *pool_range;
		p.size = ntohl(p.r.end.u.v4.sin_addr.s_addr) -
			  ntohl(p.r.start.u.v4.sin_addr.s_addr) + 1;
		p.used = 0;
		p.lingering = 0;

		DBG(DBG_CONTROLMORE, {
			let rbuf: [char, ..RANGETOT_BUF];

			rangetot(&p.r, 0, rbuf, mem::size_of_val(rbuf));
			DBG_log("add new addresspool to global pools %s size %d ptr %p",
				rbuf, p.size, p);
		});
		p.leases = NULL;
		p.next = *head;
		*head = p;
	}
	return p;
}

}  // End mod addresspool
