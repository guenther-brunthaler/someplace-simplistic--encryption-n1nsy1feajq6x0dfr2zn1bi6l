#! /usr/bin/awk -f

function die(msg) {
	print msg > "/dev/stderr"
	exit 1
}

function prng_init() {
	prng_addend= atan2(0, -1)
}

function prng_new(me, seed, min, max    , entropy) {
	if (seed <= 0) {
		entropy= "date -u +%S%M%H%d%m%Y"
		entropy | getline seed
		close(entropy)
	}
	while (seed >= 1) seed/= 2
	while (seed < 0.5) seed+= seed
	me["state"]= seed
	me["span"]= max + 1 - (me["min"]= min)
}

function prng_next(me) {
	me["state"]= me["state"] * 997 + prng_addend
	return int(me["min"] + (me["state"]-= int(me["state"])) * me["span"])
}

function swap0(array, i1, i2    , t) {
	t= array[i1]; array[i1]= array[i2]; array[i2]= t
}

function swap(array, reverse, i1, i2    , r1, r2) {
	r1= reverse[i1]; r2= reverse[i1]
	swap0(array, i1, i2);
	swap0(reverse, r1, r2);
}

function copy(dst, src    , i) {
	for (i in dst) delete dst[i]
	for (i in src) dst[i]= src[i]
}

function show(array, title    , i, start, last, max, owidth, pic, out) {
	start= -1
	for (i in array) {
		if (start < 0) max= array[start= last= i]
		else {
			if (i < start) start= i
			if (i > last) last= i
			if (array[i] > max) max= array[i]
		}
	}
	owidth= 2; pic= 9
	while (max > pic) {
		pic= 10 * pic + 9
		++owidth
	}
	for (i= start; i <= last; ++i) {
		out= out sprintf( \
			"[%u]%-*u", i,  i < last ? owidth : 0, array[i] \
		)
	}
	print title ":"
	print out
	print ""
}

function verify_inverses(a, rev    , i) {
	for (i in a) {
		if (rev[a[i]] != i) {
			show(last_good_a, "a (last good)")
			show(last_good_rev, "rev (last good)")
			show(a, "a (now)")
			show(rev, "rev (now)")
			die("a[" i "] == " a[i] ", rev[" a[i] "] == " \
				rev[a[i]])
		}
	}
	copy(last_good_a, a)
	copy(last_good_rev, rev)
}

function main(    sbox_size, seed, rounds, i, s, rs) {
	rounds= 100
	sbox_size= 15
	seed= 42
	prng_init()
	prng_new(rnd, seed, 0, sbox_size - 1)
	for (i= sbox_size; i--; ) s[i]= rs[i]= i
	for (i= sbox_size; i--; ) {
		verify_inverses(s, rs)
		swap(s, rs, i, prng_next(rnd))
		verify_inverses(s, rs)
	}
	while (rounds--) {
		verify_inverses(s, rs)
		swap(s, rs, prng_next(rnd), prng_next(rnd))
		verify_inverses(s, rs)
	}
}

BEGIN {main()}
