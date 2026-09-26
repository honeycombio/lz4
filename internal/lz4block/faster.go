package lz4block

import (
	"encoding/binary"
	"math/bits"
	"sync"
)

// CompressorFaster is a port of LZ4_compress_fast from the reference
// implementation (lz4 1.10), and produces the same output. It searches one
// position per step with a 16kiB table, where Compressor searches three per
// step with a 128kiB one: it is faster, but compresses less.
//
// Constants and names follow lz4.c.
const (
	fasterHashLog   = 12          // LZ4_HASHLOG, for the default LZ4_MEMORY_USAGE of 14
	fasterMFLimit   = 12          // MFLIMIT
	fasterMinLength = 13          // LZ4_minLength
	lastLiterals    = 5           // LASTLITERALS
	skipTrigger     = 6           // LZ4_skipTrigger
	fasterU16Limit  = 64<<10 + 11 // LZ4_64Klimit: smaller inputs use the byU16 table
	fasterMaxInput  = 0x7E000000  // LZ4_MAX_INPUT_SIZE
	distanceMax     = 65535       // LZ4_DISTANCE_MAX
	accelerationMax = 65537       // LZ4_ACCELERATION_MAX
)

type CompressorFaster struct {
	// For inputs below fasterU16Limit, all 1<<(fasterHashLog+1) entries are
	// used with hash4 (byU16 in lz4.c); otherwise the first 1<<fasterHashLog
	// with hash5 (byU32). The table is cleared on each call.
	table [1 << (fasterHashLog + 1)]uint32
}

var compressorFasterPool = sync.Pool{New: func() interface{} { return new(CompressorFaster) }}

// CompressBlockFaster is CompressorFaster.CompressBlock with acceleration 1,
// using a pooled CompressorFaster.
func CompressBlockFaster(src, dst []byte) (int, error) {
	c := compressorFasterPool.Get().(*CompressorFaster)
	n, err := c.CompressBlock(src, dst, 1)
	compressorFasterPool.Put(c)
	return n, err
}

func load32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
func load64(b []byte, i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }

// fasterHash is LZ4_hashPosition: hash4 for byU16, hash5 for byU32.
func fasterHash(src []byte, i int, u16 bool) uint32 {
	if u16 {
		return load32(src, i) * 2654435761 >> (32 - (fasterHashLog + 1))
	}
	return uint32(load64(src, i) << 24 * 889523592379 >> (64 - fasterHashLog))
}

// countMatch is LZ4_count: the length of the common prefix of src[in:] and
// src[match:], stopping at limit.
func countMatch(src []byte, in, match, limit int) int {
	start := in
	for in < limit-7 {
		if diff := load64(src, match) ^ load64(src, in); diff != 0 {
			return in + bits.TrailingZeros64(diff)>>3 - start
		}
		in += 8
		match += 8
	}
	if in < limit-3 && load32(src, match) == load32(src, in) {
		in += 4
		match += 4
	}
	if in < limit-1 && binary.LittleEndian.Uint16(src[match:]) == binary.LittleEndian.Uint16(src[in:]) {
		in += 2
		match += 2
	}
	if in < limit && src[match] == src[in] {
		in++
	}
	return in - start
}

// CompressBlock compresses src into dst with the given acceleration, as
// LZ4_compress_fast_extState does. It returns 0 if the result does not fit
// in dst, which cannot happen if len(dst) >= CompressBlockBound(len(src)).
func (c *CompressorFaster) CompressBlock(src, dst []byte, acceleration int) (int, error) {
	if acceleration < 1 {
		acceleration = 1
	} else if acceleration > accelerationMax {
		acceleration = accelerationMax
	}
	if len(src) == 0 {
		if len(dst) == 0 {
			return 0, nil
		}
		dst[0] = 0
		return 1, nil
	}
	if len(src) > fasterMaxInput {
		// Beyond what lz4.c accepts, and what 32-bit positions can hold.
		return CompressBlock(src, dst)
	}
	u16 := len(src) < fasterU16Limit
	table := c.table[:1<<fasterHashLog]
	if u16 {
		table = c.table[:]
	}
	for i := range table {
		table[i] = 0
	}
	// limitedOutput in lz4.c: check that the output fits as it is written.
	limited := len(dst) < CompressBlockBound(len(src))

	var (
		anchor, ip, di int
		mfLimitPlusOne = len(src) - fasterMFLimit + 1
		matchLimit     = len(src) - lastLiterals
		forwardH       uint32
		match, token   int
	)
	if len(src) < fasterMinLength {
		goto lastLiteralsLabel
	}

	// First byte.
	table[fasterHash(src, 0, u16)] = 0
	ip = 1
	forwardH = fasterHash(src, ip, u16)

	for {
		// Find a match.
		{
			forwardIP := ip
			step := 1
			searchMatchNb := acceleration << skipTrigger
			for {
				h := forwardH
				cur := forwardIP
				matchIndex := int(table[h])
				ip = forwardIP
				forwardIP += step
				step = searchMatchNb >> skipTrigger
				searchMatchNb++
				if forwardIP > mfLimitPlusOne {
					goto lastLiteralsLabel
				}
				match = matchIndex
				forwardH = fasterHash(src, forwardIP, u16)
				table[h] = uint32(cur)
				if !u16 && matchIndex+distanceMax < cur {
					continue // too far
				}
				if load32(src, match) == load32(src, ip) {
					break
				}
			}
		}

		// Catch up.
		if match > 0 && src[ip-1] == src[match-1] {
			for {
				ip--
				match--
				if ip <= anchor || match <= 0 || src[ip-1] != src[match-1] {
					break
				}
			}
		}

		// Encode literals.
		{
			litLength := ip - anchor
			token = di
			di++
			if limited && di+litLength+(2+1+lastLiterals)+litLength/255 > len(dst) {
				return 0, nil
			}
			if litLength >= 0xF {
				dst[token] = 0xF0
				l := litLength - 0xF
				for ; l >= 0xFF; l -= 0xFF {
					dst[di] = 0xFF
					di++
				}
				dst[di] = byte(l)
				di++
			} else {
				dst[token] = byte(litLength << 4)
			}
			// LZ4_wildCopy8: may write up to 7 bytes past the literals,
			// which the rest of the output always overwrites.
			for i := 0; i < litLength; i += 8 {
				binary.LittleEndian.PutUint64(dst[di+i:], load64(src, anchor+i))
			}
			di += litLength
		}

	nextMatch:
		// Encode offset.
		offset := ip - match
		dst[di] = byte(offset)
		dst[di+1] = byte(offset >> 8)
		di += 2

		// Encode match length.
		{
			matchCode := countMatch(src, ip+minMatch, match+minMatch, matchLimit)
			ip += matchCode + minMatch
			if limited && di+(1+lastLiterals)+(matchCode+240)/255 > len(dst) {
				return 0, nil
			}
			if matchCode >= 0xF {
				dst[token] += 0xF
				matchCode -= 0xF
				for ; matchCode >= 0xFF; matchCode -= 0xFF {
					dst[di] = 0xFF
					di++
				}
				dst[di] = byte(matchCode)
				di++
			} else {
				dst[token] += byte(matchCode)
			}
		}
		anchor = ip

		// Test end of chunk.
		if ip >= mfLimitPlusOne {
			break
		}

		// Fill table.
		table[fasterHash(src, ip-2, u16)] = uint32(ip - 2)

		// Test next position.
		{
			h := fasterHash(src, ip, u16)
			matchIndex := int(table[h])
			table[h] = uint32(ip)
			if (u16 || matchIndex+distanceMax >= ip) && load32(src, matchIndex) == load32(src, ip) {
				token = di
				dst[di] = 0
				di++
				match = matchIndex
				goto nextMatch
			}
		}

		// Prepare next loop.
		ip++
		forwardH = fasterHash(src, ip, u16)
	}

lastLiteralsLabel:
	lastRun := len(src) - anchor
	if limited && di+lastRun+1+(lastRun+255-0xF)/255 > len(dst) {
		return 0, nil
	}
	if lastRun >= 0xF {
		dst[di] = 0xF0
		di++
		acc := lastRun - 0xF
		for ; acc >= 0xFF; acc -= 0xFF {
			dst[di] = 0xFF
			di++
		}
		dst[di] = byte(acc)
		di++
	} else {
		dst[di] = byte(lastRun << 4)
		di++
	}
	di += copy(dst[di:], src[anchor:])
	return di, nil
}
