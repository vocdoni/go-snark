package prover

import (
	"bytes"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/vocdoni/go-snark/types"
)

func arrayOfZeroes(n int) []*big.Int {
	r := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		r[i] = new(big.Int).SetInt64(0)
	}
	return r[:]
}

func arrayOfZeroesE(n int) []*ff.Element {
	r := make([]*ff.Element, n)
	for i := 0; i < n; i++ {
		r[i] = ff.NewElement()
	}
	return r[:]
}

func arrayOfZeroesG1(n int) []*curve.G1Affine {
	r := make([]*curve.G1Affine, n)
	for i := 0; i < n; i++ {
		r[i] = new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	}
	return r[:]
}

func arrayOfZeroesG2(n int) []*curve.G2Affine {
	r := make([]*curve.G2Affine, n)
	for i := 0; i < n; i++ {
		r[i] = new(curve.G2Affine).ScalarMultiplicationBase(big.NewInt(0))
	}
	return r[:]
}

func fAdd(a, b *big.Int) *big.Int {
	ab := new(big.Int).Add(a, b)
	return ab.Mod(ab, types.R)
}

func fSub(a, b *big.Int) *big.Int {
	ab := new(big.Int).Sub(a, b)
	return new(big.Int).Mod(ab, types.R)
}

func fMul(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, b)
	return ab.Mod(ab, types.R)
}

func fDiv(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, new(big.Int).ModInverse(b, types.R))
	return new(big.Int).Mod(ab, types.R)
}

//nolint:unused,deadcode // TODO check
func fNeg(a *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(a), types.R)
}

func fInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, types.R)
}

func fExp(base *big.Int, e *big.Int) *big.Int {
	res := big.NewInt(1)
	rem := new(big.Int).Set(e)
	exp := base

	for !bytes.Equal(rem.Bytes(), big.NewInt(int64(0)).Bytes()) {
		// if BigIsOdd(rem) {
		if rem.Bit(0) == 1 { // .Bit(0) returns 1 when is odd
			res = fMul(res, exp)
		}
		exp = fMul(exp, exp)
		rem.Rsh(rem, 1)
	}
	return res
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func polynomialSub(a, b []*big.Int) []*big.Int {
	r := arrayOfZeroes(max(len(a), len(b)))
	for i := 0; i < len(a); i++ {
		r[i] = fAdd(r[i], a[i])
	}
	for i := 0; i < len(b); i++ {
		r[i] = fSub(r[i], b[i])
	}
	return r
}

func polynomialSubE(a, b []*ff.Element) []*ff.Element {
	r := arrayOfZeroesE(max(len(a), len(b)))
	for i := 0; i < len(a); i++ {
		r[i].Add(r[i], a[i])
	}
	for i := 0; i < len(b); i++ {
		r[i].Sub(r[i], b[i])
	}
	return r
}

func polynomialMul(a, b []*big.Int) []*big.Int {
	r := arrayOfZeroes(len(a) + len(b) - 1)
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			r[i+j] = fAdd(r[i+j], fMul(a[i], b[j]))
		}
	}
	return r
}

func polynomialMulE(a, b []*ff.Element) []*ff.Element {
	r := arrayOfZeroesE(len(a) + len(b) - 1)
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			r[i+j].Add(r[i+j], ff.NewElement().Mul(a[i], b[j]))
		}
	}
	return r
}

func polynomialDiv(a, b []*big.Int) ([]*big.Int, []*big.Int) {
	// https://en.wikipedia.org/wiki/Division_algorithm
	r := arrayOfZeroes(len(a) - len(b) + 1)
	rem := a
	for len(rem) >= len(b) {
		l := fDiv(rem[len(rem)-1], b[len(b)-1])
		pos := len(rem) - len(b)
		r[pos] = l
		aux := arrayOfZeroes(pos)
		aux1 := append(aux, l)
		aux2 := polynomialSub(rem, polynomialMul(b, aux1))
		rem = aux2[:len(aux2)-1]
	}
	return r, rem
}

func polynomialDivE(a, b []*ff.Element) ([]*ff.Element, []*ff.Element) {
	// https://en.wikipedia.org/wiki/Division_algorithm
	r := arrayOfZeroesE(len(a) - len(b) + 1)
	rem := a
	for len(rem) >= len(b) {
		l := ff.NewElement().Div(rem[len(rem)-1], b[len(b)-1])
		pos := len(rem) - len(b)
		r[pos] = l
		aux := arrayOfZeroesE(pos)
		aux1 := append(aux, l)
		aux2 := polynomialSubE(rem, polynomialMulE(b, aux1))
		rem = aux2[:len(aux2)-1]
	}
	return r, rem
}
