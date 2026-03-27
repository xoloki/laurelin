package main

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const bsgsM = 1 << 16 // 65536 = sqrt(2^32)

type bsgsTable struct {
	table map[[64]byte]uint32
	mG    bn254.G1Affine // m·G, used as the giant step
}

// buildBSGSTable precomputes i·G for i in [0, m) and stores them keyed by
// their serialised point. The giant step is m·G. Building costs ~65536 point
// additions and ~4 MB of map storage.
func buildBSGSTable(G bn254.G1Affine) bsgsTable {
	table := make(map[[64]byte]uint32, bsgsM)

	// i=0: point at infinity (zero value of G1Affine)
	var inf bn254.G1Affine
	table[g1Bytes(&inf)] = 0

	cur := G // cur = 1·G
	for i := uint32(1); i < bsgsM; i++ {
		table[g1Bytes(&cur)] = i
		cur.Add(&cur, &G)
	}
	// After the loop cur = bsgsM·G — use it as the giant step.
	return bsgsTable{table: table, mG: cur}
}

// solve finds v ∈ [0, 2^32) such that v·G = P, using the precomputed table.
// Returns (v, true) on success or (0, false) if P is not in range.
func (t *bsgsTable) solve(P bn254.G1Affine) (uint32, bool) {
	var negMG bn254.G1Affine
	negMG.Neg(&t.mG)

	cur := P
	for j := uint32(0); j < bsgsM; j++ {
		if i, ok := t.table[g1Bytes(&cur)]; ok {
			return j*bsgsM + i, true
		}
		cur.Add(&cur, &negMG)
	}
	return 0, false
}
