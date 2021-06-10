package verifier

import (
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/vocdoni/go-snark/types"
)

// Vk is the Verification Key data structure
type Vk struct {
	Alpha *bn256.G1
	Beta  *bn256.G2
	Gamma *bn256.G2
	Delta *bn256.G2
	IC    []*bn256.G1
}

// Verify verifies the Groth16 zkSNARK proof
func Verify(vk *types.Vk, proof *types.Proof, inputs []*big.Int) bool {
	if len(inputs)+1 != len(vk.IC) {
		fmt.Println("len(inputs)+1 != len(vk.IC)")
		return false
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[i].Cmp(types.R) != -1 {
			return false
		}
		vkX = new(bn256.G1).Add(vkX, new(bn256.G1).ScalarMult(vk.IC[i+1], inputs[i]))
	}
	vkX = new(bn256.G1).Add(vkX, vk.IC[0])

	g1 := []*bn256.G1{new(bn256.G1).Neg(proof.A), vk.Alpha, vkX, proof.C}
	g2 := []*bn256.G2{proof.B, vk.Beta, vk.Gamma, vk.Delta}
	return bn256.PairingCheck(g1, g2)
}
