package gnarkparser

import (
	"fmt"
	"io"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gnarkPk "github.com/consensys/gnark/backend/groth16/bn254"
	gnarkWit "github.com/consensys/gnark/backend/witness"

	"github.com/vocdoni/go-snark/types"
)

// TransformWitness transforms a witness from gnark to go-snark.
func TransformWitness(wReader io.Reader) (*types.Witness, error) {
	fmt.Println("Transforming witness")
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
	fmt.Println("Witness transformed")
	return &w, nil
}

// TransformProvingKey transforms a proving key from gnark to go-snark.
func TransformProvingKey(pkReader io.Reader) (*types.Pk, error) {
	fmt.Println("Transforming proving key")
	gnarkProvingKey := gnarkPk.ProvingKey{}

	if _, err := gnarkProvingKey.UnsafeReadFrom(pkReader); err != nil {
		return nil, err
	}
	goSnarkProvingKey := &types.Pk{
		NVars:      len(gnarkProvingKey.Domain.Generator),
		DomainSize: len(gnarkProvingKey.Domain.Generator),
	}

	// Convert G1 and G2 points
	fmt.Println("Converting G1 and G2 points A", len(gnarkProvingKey.G1.A))
	goSnarkProvingKey.A = make([]*curve.G1Affine, len(gnarkProvingKey.G1.A))
	for i := range gnarkProvingKey.G1.A {
		goSnarkProvingKey.A[i] = &gnarkProvingKey.G1.A[i]
	}

	fmt.Println("Converting G1 and G2 points B1", len(gnarkProvingKey.G1.B))
	goSnarkProvingKey.B1 = make([]*curve.G1Affine, len(gnarkProvingKey.G1.B))
	for i := range gnarkProvingKey.G1.B {
		goSnarkProvingKey.B1[i] = &gnarkProvingKey.G1.B[i]
	}

	fmt.Println("Converting G1 and G2 points B2", len(gnarkProvingKey.G2.B))
	goSnarkProvingKey.B2 = make([]*curve.G2Affine, len(gnarkProvingKey.G2.B))
	for i := range gnarkProvingKey.G2.B {
		goSnarkProvingKey.B2[i] = &gnarkProvingKey.G2.B[i]
	}

	fmt.Println("Converting G1 and G2 points C", len(gnarkProvingKey.G1.K))
	goSnarkProvingKey.C = make([]*curve.G1Affine, len(gnarkProvingKey.G1.K))
	for i := range gnarkProvingKey.G1.K {
		goSnarkProvingKey.C[i] = &gnarkProvingKey.G1.K[i]
	}

	// Convert alpha, beta, and delta
	fmt.Println("Converting alpha, beta, and delta")
	goSnarkProvingKey.VkAlpha1 = new(curve.G1Affine)
	goSnarkProvingKey.VkAlpha1.Unmarshal(gnarkProvingKey.G1.Alpha.Marshal())

	goSnarkProvingKey.VkBeta1 = new(curve.G1Affine)
	goSnarkProvingKey.VkBeta1.Unmarshal(gnarkProvingKey.G1.Beta.Marshal())

	goSnarkProvingKey.VkBeta2 = new(curve.G2Affine)
	goSnarkProvingKey.VkBeta2.Unmarshal(gnarkProvingKey.G2.Beta.Marshal())

	goSnarkProvingKey.VkDelta1 = new(curve.G1Affine)
	goSnarkProvingKey.VkDelta1.Unmarshal(gnarkProvingKey.G1.Delta.Marshal())

	goSnarkProvingKey.VkDelta2 = new(curve.G2Affine)
	goSnarkProvingKey.VkDelta2.Unmarshal(gnarkProvingKey.G2.Delta.Marshal())

	// Convert HExps
	fmt.Println("Converting HExps", len(gnarkProvingKey.G1.Z))
	goSnarkProvingKey.HExps = make([]*curve.G1Affine, len(gnarkProvingKey.G1.Z))
	for i := range gnarkProvingKey.G1.Z {
		goSnarkProvingKey.HExps[i] = &gnarkProvingKey.G1.Z[i]
	}

	// Convert PolsA and PolsB
	fmt.Println("Converting PolsA and PolsB", len(gnarkProvingKey.G1.A)+len(gnarkProvingKey.G1.B))
	goSnarkProvingKey.PolsA = make([]map[int]*big.Int, len(gnarkProvingKey.G1.A))
	for i := range gnarkProvingKey.G1.A {
		//goSnarkProvingKey.PolsA[i][0] = new(big.Int).SetBits(toBigWords(g1Point.X.Bits()))
		//goSnarkProvingKey.PolsA[i][1] = new(big.Int).SetBits(toBigWords(g1Point.Y.Bits()))
		goSnarkProvingKey.PolsA[i] = make(map[int]*big.Int)
		goSnarkProvingKey.PolsA[i][0] = gnarkProvingKey.G1.A[i].X.BigInt(new(big.Int))
		goSnarkProvingKey.PolsA[i][1] = gnarkProvingKey.G1.A[i].Y.BigInt(new(big.Int))
	}

	goSnarkProvingKey.PolsB = make([]map[int]*big.Int, len(gnarkProvingKey.G1.B))
	for i := range gnarkProvingKey.G1.B {
		goSnarkProvingKey.PolsB[i] = make(map[int]*big.Int)
		//goSnarkProvingKey.PolsB[i][0] = new(big.Int).SetBits(toBigWords(g1Point.X.Bits()))
		//goSnarkProvingKey.PolsB[i][1] = new(big.Int).SetBits(toBigWords(g1Point.Y.Bits()))
		goSnarkProvingKey.PolsB[i][0] = gnarkProvingKey.G1.B[i].X.BigInt(new(big.Int))
		goSnarkProvingKey.PolsB[i][1] = gnarkProvingKey.G1.B[i].Y.BigInt(new(big.Int))
	}
	fmt.Println("finished converting proving key")
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
