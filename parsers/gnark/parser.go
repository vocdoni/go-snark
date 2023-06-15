package gnarkparser

import (
	"io"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gnarkPk "github.com/consensys/gnark/backend/groth16/bn254"
	gnarkWit "github.com/consensys/gnark/backend/witness"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/vocdoni/go-snark/types"
)

// TransformWitness transforms a witness from gnark to go-snark.
func TransformWitness(wReader io.Reader) (*types.Witness, error) {
	gw, err := gnarkWit.New(curve.ID.ScalarField())
	if err != nil {
		return nil, err
	}
	_, err = gw.ReadFrom(wReader)
	if err != nil {
		return nil, err
	}
	w := types.Witness{}
	v := gw.Vector().(fr.Vector)
	for _, e := range v {
		w = append(w, e.BigInt(new(big.Int)))
	}
	return &w, nil
}

// TransformProvingKey transforms a proving key from gnark to go-snark.
func TransformProvingKey(pkReader io.Reader) (*types.Pk, error) {
	gnarkProvingKey := gnarkPk.ProvingKey{}
	if _, err := gnarkProvingKey.UnsafeReadFrom(pkReader); err != nil {
		return nil, err
	}
	goSnarkProvingKey := &types.Pk{
		NVars:      len(gnarkProvingKey.Domain.Generator),
		DomainSize: len(gnarkProvingKey.Domain.Generator),
	}

	// Convert G1 and G2 points
	goSnarkProvingKey.A = make([]*bn256.G1, len(gnarkProvingKey.G1.A))
	for i, g1Point := range gnarkProvingKey.G1.A {
		goSnarkProvingKey.A[i] = new(bn256.G1)
		goSnarkProvingKey.A[i].Unmarshal(g1Point.Marshal())
	}

	goSnarkProvingKey.B1 = make([]*bn256.G1, len(gnarkProvingKey.G1.B))
	for i, g1Point := range gnarkProvingKey.G1.B {
		goSnarkProvingKey.B1[i] = new(bn256.G1)
		goSnarkProvingKey.B1[i].Unmarshal(g1Point.Marshal())
	}

	goSnarkProvingKey.B2 = make([]*bn256.G2, len(gnarkProvingKey.G2.B))
	for i, g2Point := range gnarkProvingKey.G2.B {
		goSnarkProvingKey.B2[i] = new(bn256.G2)
		goSnarkProvingKey.B2[i].Unmarshal(g2Point.Marshal())
	}

	goSnarkProvingKey.C = make([]*bn256.G1, len(gnarkProvingKey.G1.K))
	for i, g1Point := range gnarkProvingKey.G1.K {
		goSnarkProvingKey.C[i] = new(bn256.G1)
		goSnarkProvingKey.C[i].Unmarshal(g1Point.Marshal())
	}

	// Convert alpha, beta, and delta
	goSnarkProvingKey.VkAlpha1 = new(bn256.G1)
	goSnarkProvingKey.VkAlpha1.Unmarshal(gnarkProvingKey.G1.Alpha.Marshal())

	goSnarkProvingKey.VkBeta1 = new(bn256.G1)
	goSnarkProvingKey.VkBeta1.Unmarshal(gnarkProvingKey.G1.Beta.Marshal())

	goSnarkProvingKey.VkBeta2 = new(bn256.G2)
	goSnarkProvingKey.VkBeta2.Unmarshal(gnarkProvingKey.G2.Beta.Marshal())

	goSnarkProvingKey.VkDelta1 = new(bn256.G1)
	goSnarkProvingKey.VkDelta1.Unmarshal(gnarkProvingKey.G1.Delta.Marshal())

	goSnarkProvingKey.VkDelta2 = new(bn256.G2)
	goSnarkProvingKey.VkDelta2.Unmarshal(gnarkProvingKey.G2.Delta.Marshal())

	// Convert HExps
	goSnarkProvingKey.HExps = make([]*bn256.G1, len(gnarkProvingKey.G1.Z))
	for i, g1Point := range gnarkProvingKey.G1.Z {
		goSnarkProvingKey.HExps[i] = new(bn256.G1)
		goSnarkProvingKey.HExps[i].Unmarshal(g1Point.Marshal())
	}

	// Convert PolsA and PolsB
	goSnarkProvingKey.PolsA = make([]map[int]*big.Int, len(gnarkProvingKey.G1.A))
	for i, g1Point := range gnarkProvingKey.G1.A {
		goSnarkProvingKey.PolsA[i] = make(map[int]*big.Int)
		goSnarkProvingKey.PolsA[i][0] = new(big.Int).SetBits(toBigWords(g1Point.X.Bits()))
		goSnarkProvingKey.PolsA[i][1] = new(big.Int).SetBits(toBigWords(g1Point.Y.Bits()))
	}

	goSnarkProvingKey.PolsB = make([]map[int]*big.Int, len(gnarkProvingKey.G1.B))
	for i, g1Point := range gnarkProvingKey.G1.B {
		goSnarkProvingKey.PolsB[i] = make(map[int]*big.Int)
		goSnarkProvingKey.PolsB[i][0] = new(big.Int).SetBits(toBigWords(g1Point.X.Bits()))
		goSnarkProvingKey.PolsB[i][1] = new(big.Int).SetBits(toBigWords(g1Point.Y.Bits()))
	}

	return goSnarkProvingKey, nil
}

// toBigWords converts an array of uint64 values to a slice of big.Word values.
func toBigWords(words [4]uint64) []big.Word {
	bigWords := make([]big.Word, len(words))
	for i, word := range words {
		bigWords[i] = big.Word(word)
	}
	return bigWords
}
