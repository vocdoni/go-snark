package prover

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
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
	fmt.Println("Generating proof")
	var proof types.Proof

	r, err := randBigInt()
	if err != nil {
		return nil, nil, err
	}
	s, err := randBigInt()
	if err != nil {
		return nil, nil, err
	}

	proofA := new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	proofB := new(curve.G2Affine).ScalarMultiplicationBase(big.NewInt(0))
	proofC := new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	proofBG1 := new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	gsize := gSize

	// split 1
	fmt.Println("scalar mults A")
	proofA = scalarMultNoDoubleG1(pk.A,
		w,
		proofA,
		gsize)
	fmt.Println("scalar mults B")
	proofB = scalarMultNoDoubleG2(pk.B2,
		w,
		proofB,
		gsize)
	fmt.Println("scalar mults BG1")
	proofBG1 = scalarMultNoDoubleG1(pk.B1,
		w,
		proofBG1,
		gsize)
	fmt.Println("scalar mults C")
	proofC = scalarMultNoDoubleG1(pk.C,
		w,
		proofC,
		gsize)
	// join 1
	proof.A = proofA
	proof.B = proofB
	proof.C = proofC
	// END PAR

	fmt.Println("calculating h")
	h := calculateH(pk, w)

	proof.A.Add(proof.A, pk.VkAlpha1)
	proof.A.Add(proof.A, new(curve.G1Affine).ScalarMultiplication(pk.VkDelta1, r))

	proof.B.Add(proof.B, pk.VkBeta2)
	proof.B.Add(proof.B, new(curve.G2Affine).ScalarMultiplication(pk.VkDelta2, s))

	proofBG1.Add(proofBG1, pk.VkBeta1)
	proofBG1.Add(proofBG1, new(curve.G1Affine).ScalarMultiplication(pk.VkDelta1, s))

	proofC = new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))

	fmt.Println("scalar mults 2")
	proofC = scalarMultNoDoubleG1(pk.HExps,
		h,
		proofC,
		gsize)
	// join 2

	proof.C.Add(proof.C, proofC)

	proof.C.Add(proof.C, new(curve.G1Affine).ScalarMultiplication(proof.A, s))
	proof.C.Add(proof.C, new(curve.G1Affine).ScalarMultiplication(proofBG1, r))
	rsneg := new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(r, s)), types.R)
	proof.C.Add(proof.C, new(curve.G1Affine).ScalarMultiplication(pk.VkDelta1, rsneg))

	pubSignals := w[1 : pk.NPublic+1]
	fmt.Println("proof generated")
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
