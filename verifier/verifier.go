package verifier

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/iden3/go-circom-prover-verifier/prover"
	"github.com/iden3/go-circom-prover-verifier/types"
)

// Vk is the Verification Key data structure
type Vk struct {
	Alpha *bn256.G1
	Beta  *bn256.G2
	Gamma *bn256.G2
	Delta *bn256.G2
	IC    []*bn256.G1
}

func Verify(vk *types.Vk, proof *types.Proof, inputs []*big.Int) bool {
	if len(inputs)+1 != len(vk.IC) {
		fmt.Println("len(inputs)+1 != len(vk.IC)")
		return false
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[0].Cmp(prover.R) != -1 {
			return false
		}
		vkX = new(bn256.G1).Add(vkX, new(bn256.G1).ScalarMult(vk.IC[i+1], inputs[i]))
	}
	vkX = new(bn256.G1).Add(vkX, vk.IC[0])

	g1 := []*bn256.G1{proof.A, vk.Alpha.Neg(vk.Alpha), vkX.Neg(vkX), proof.C.Neg(proof.C)}
	g2 := []*bn256.G2{proof.B, vk.Beta, vk.Gamma, vk.Delta}
	return bn256.PairingCheck(g1, g2)
}