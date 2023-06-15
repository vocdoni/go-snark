package prover

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sync"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/vocdoni/go-snark/types"
)

// Group Size
const (
	gSize = 6
)

func randBigInt() (*big.Int, error) {
	maxbits := types.R.BitLen()
	b := make([]byte, (maxbits/8)-1)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(b)
	rq := new(big.Int).Mod(r, types.R)

	return rq, nil
}

// GenerateProof generates the Groth16 zkSNARK proof
func GenerateProof(pk *types.Pk, w types.Witness) (*types.Proof, []*big.Int, error) {
	var proof types.Proof

	r, err := randBigInt()
	if err != nil {
		return nil, nil, err
	}
	s, err := randBigInt()
	if err != nil {
		return nil, nil, err
	}

	// BEGIN PAR
	numcpu := 1

	proofA := arrayOfZeroesG1(numcpu)
	proofB := arrayOfZeroesG2(numcpu)
	proofC := arrayOfZeroesG1(numcpu)
	proofBG1 := arrayOfZeroesG1(numcpu)
	gsize := gSize
	var wg1 sync.WaitGroup
	wg1.Add(numcpu)
	for _cpu, _ranges := range ranges(pk.NVars, numcpu) {
		// split 1
		func(cpu int, ranges [2]int) {
			fmt.Printf("cpu %d, ranges %v\n", cpu, ranges)
			proofA[cpu] = scalarMultNoDoubleG1(pk.A[ranges[0]:ranges[1]],
				w[ranges[0]:ranges[1]],
				proofA[cpu],
				gsize)
			proofB[cpu] = scalarMultNoDoubleG2(pk.B2[ranges[0]:ranges[1]],
				w[ranges[0]:ranges[1]],
				proofB[cpu],
				gsize)
			proofBG1[cpu] = scalarMultNoDoubleG1(pk.B1[ranges[0]:ranges[1]],
				w[ranges[0]:ranges[1]],
				proofBG1[cpu],
				gsize)
			minLim := pk.NPublic + 1
			if ranges[0] > pk.NPublic+1 {
				minLim = ranges[0]
			}
			if ranges[1] > pk.NPublic+1 {
				proofC[cpu] = scalarMultNoDoubleG1(pk.C[minLim:ranges[1]],
					w[minLim:ranges[1]],
					proofC[cpu],
					gsize)
			}
			wg1.Done()
		}(_cpu, _ranges)
	}
	wg1.Wait()
	// join 1
	for cpu := 1; cpu < numcpu; cpu++ {
		proofA[0].Add(proofA[0], proofA[cpu])
		proofB[0].Add(proofB[0], proofB[cpu])
		proofC[0].Add(proofC[0], proofC[cpu])
		proofBG1[0].Add(proofBG1[0], proofBG1[cpu])
	}
	proof.A = proofA[0]
	proof.B = proofB[0]
	proof.C = proofC[0]
	// END PAR

	h := calculateH(pk, w)

	proof.A.Add(proof.A, pk.VkAlpha1)
	proof.A.Add(proof.A, new(bn256.G1).ScalarMult(pk.VkDelta1, r))

	proof.B.Add(proof.B, pk.VkBeta2)
	proof.B.Add(proof.B, new(bn256.G2).ScalarMult(pk.VkDelta2, s))

	proofBG1[0].Add(proofBG1[0], pk.VkBeta1)
	proofBG1[0].Add(proofBG1[0], new(bn256.G1).ScalarMult(pk.VkDelta1, s))

	proofC = arrayOfZeroesG1(numcpu)
	var wg2 sync.WaitGroup
	wg2.Add(numcpu)
	for _cpu, _ranges := range ranges(len(h), numcpu) {
		// split 2
		func(cpu int, ranges [2]int) {
			proofC[cpu] = scalarMultNoDoubleG1(pk.HExps[ranges[0]:ranges[1]],
				h[ranges[0]:ranges[1]],
				proofC[cpu],
				gsize)
			wg2.Done()
		}(_cpu, _ranges)
	}
	wg2.Wait()
	// join 2
	for cpu := 1; cpu < numcpu; cpu++ {
		proofC[0].Add(proofC[0], proofC[cpu])
	}
	proof.C.Add(proof.C, proofC[0])

	proof.C.Add(proof.C, new(bn256.G1).ScalarMult(proof.A, s))
	proof.C.Add(proof.C, new(bn256.G1).ScalarMult(proofBG1[0], r))
	rsneg := new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(r, s)), types.R)
	proof.C.Add(proof.C, new(bn256.G1).ScalarMult(pk.VkDelta1, rsneg))

	pubSignals := w[1 : pk.NPublic+1]

	return &proof, pubSignals, nil
}

func calculateH(pk *types.Pk, w types.Witness) []*big.Int {
	m := pk.DomainSize
	polAT := arrayOfZeroes(m)
	polBT := arrayOfZeroes(m)

	numcpu := 1

	var wg1 sync.WaitGroup
	wg1.Add(2) //nolint:gomnd
	func() {
		for i := 0; i < pk.NVars; i++ {
			for j := range pk.PolsA[i] {
				polAT[j] = fAdd(polAT[j], fMul(w[i], pk.PolsA[i][j]))
			}
		}
		wg1.Done()
	}()
	func() {
		for i := 0; i < pk.NVars; i++ {
			for j := range pk.PolsB[i] {
				polBT[j] = fAdd(polBT[j], fMul(w[i], pk.PolsB[i][j]))
			}
		}
		wg1.Done()
	}()
	wg1.Wait()
	polATe := utils.BigIntArrayToElementArray(polAT)
	polBTe := utils.BigIntArrayToElementArray(polBT)

	polASe := ifft(polATe)
	polBSe := ifft(polBTe)

	r := int(math.Log2(float64(m))) + 1
	roots := newRootsT()
	roots.setRoots(r)

	var wg2 sync.WaitGroup
	wg2.Add(numcpu)
	for _cpu, _ranges := range ranges(len(polASe), numcpu) {
		func(cpu int, ranges [2]int) {
			for i := ranges[0]; i < ranges[1]; i++ {
				polASe[i].Mul(polASe[i], roots.roots[r][i])
				polBSe[i].Mul(polBSe[i], roots.roots[r][i])
			}
			wg2.Done()
		}(_cpu, _ranges)
	}
	wg2.Wait()

	polATodd := fft(polASe)
	polBTodd := fft(polBSe)

	polABT := arrayOfZeroesE(len(polASe) * 2) //nolint:gomnd
	var wg3 sync.WaitGroup
	wg3.Add(numcpu)
	for _cpu, _ranges := range ranges(len(polASe), numcpu) {
		func(cpu int, ranges [2]int) {
			for i := ranges[0]; i < ranges[1]; i++ {
				polABT[2*i].Mul(polATe[i], polBTe[i])
				polABT[2*i+1].Mul(polATodd[i], polBTodd[i])
			}
			wg3.Done()
		}(_cpu, _ranges)
	}
	wg3.Wait()

	hSeFull := ifft(polABT)

	hSe := hSeFull[m:]
	return utils.ElementArrayToBigIntArray(hSe)
}

func ranges(n, parts int) [][2]int {
	s := make([][2]int, parts)
	p := float64(n) / float64(parts)
	for i := 0; i < parts; i++ {
		a, b := int(float64(i)*p), int(float64(i+1)*p)
		s[i] = [2]int{a, b}
	}
	return s
}
