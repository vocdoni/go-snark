package verifier

import (
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/vocdoni/go-snark/types"
)

// Vk is the Verification Key data structure
type Vk struct {
	Alpha *curve.G1Affine
	Beta  *curve.G2Affine
	Gamma *curve.G2Affine
	Delta *curve.G2Affine
	IC    []*curve.G1Affine
}

// Verify verifies the Groth16 zkSNARK proof
func Verify(vk *types.Vk, proof *types.Proof, inputs []*big.Int) bool {
	if len(inputs)+1 != len(vk.IC) {
		fmt.Println("len(inputs)+1 != len(vk.IC)")
		return false
	}
	vkX := new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[i].Cmp(types.R) != -1 {
			return false
		}
		vkX = new(curve.G1Affine).Add(vkX, new(curve.G1Affine).ScalarMultiplication(vk.IC[i+1], inputs[i]))
	}
	vkX = new(curve.G1Affine).Add(vkX, vk.IC[0])

	g1 := []curve.G1Affine{}
	g1a := curve.G1Affine{}
	g1a.Neg(proof.A)
	g1 = append(g1, g1a)
	g1 = append(g1, *vk.Alpha)
	g1 = append(g1, *vkX)
	g1 = append(g1, *proof.C)

	g2 := []curve.G2Affine{}
	g2 = append(g2, *proof.B)
	g2 = append(g2, *vk.Beta)
	g2 = append(g2, *vk.Gamma)
	g2 = append(g2, *vk.Delta)

	val, err := curve.PairingCheck(g1, g2)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return val
}
