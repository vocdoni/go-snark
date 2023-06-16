package prover

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
)

const (
	n1 = 5000
	n2 = 5000
)

func randomBigIntArray(n int) []*big.Int {
	var p []*big.Int
	for i := 0; i < n; i++ {
		pi := randBI()
		p = append(p, pi)
	}

	return p
}

func randomG1(r io.Reader) *curve.G1Affine {
	order := bn254.ID.ScalarField().Uint64()
	k, err := rand.Int(r, new(big.Int).SetUint64(order))
	if err != nil {
		panic(err)
	}
	return new(curve.G1Affine).ScalarMultiplicationBase(k)
}

func randomG2(r io.Reader) *curve.G2Affine {
	order := bn254.ID.ScalarField().Uint64()
	k, err := rand.Int(r, new(big.Int).SetUint64(order))
	if err != nil {
		panic(err)
	}
	return new(curve.G2Affine).ScalarMultiplicationBase(k)
}

func randomG1Array(n int) []*curve.G1Affine {
	arrayG1 := make([]*curve.G1Affine, n)

	//new(curve.G1Affine).
	for i := 0; i < n; i++ {
		arrayG1[i] = randomG1(rand.Reader)
	}
	return arrayG1
}

func randomG2Array(n int) []*curve.G2Affine {
	arrayG2 := make([]*curve.G2Affine, n)

	for i := 0; i < n; i++ {
		arrayG2[i] = randomG2(rand.Reader)
	}
	return arrayG2
}

func TestTableG1(t *testing.T) {
	n := n1

	// init scalar
	var arrayW = randomBigIntArray(n)
	// init G1 array
	var arrayG1 = randomG1Array(n)

	beforeT := time.Now()
	Q1 := new(curve.G1Affine).ScalarMultiplicationBase(new(big.Int))
	for i := 0; i < n; i++ {
		Q1.Add(Q1, new(curve.G1Affine).ScalarMultiplication(arrayG1[i], arrayW[i]))
	}
	fmt.Println("Std. Mult. time elapsed:", time.Since(beforeT))

	for gsize := 2; gsize < 10; gsize++ {
		ntables := int((n + gsize - 1) / gsize)
		table := make([]tableG1, ntables)

		for i := 0; i < ntables-1; i++ {
			table[i].newTableG1(arrayG1[i*gsize:(i+1)*gsize], gsize, true)
		}
		table[ntables-1].newTableG1(arrayG1[(ntables-1)*gsize:], gsize, true)

		beforeT = time.Now()
		Q2 := new(curve.G1Affine).ScalarMultiplicationBase(new(big.Int))
		for i := 0; i < ntables-1; i++ {
			Q2 = table[i].mulTableG1(arrayW[i*gsize:(i+1)*gsize], Q2, gsize)
		}
		Q2 = table[ntables-1].mulTableG1(arrayW[(ntables-1)*gsize:], Q2, gsize)
		fmt.Printf("Gsize : %d, TMult time elapsed: %s\n", gsize, time.Since(beforeT))

		beforeT = time.Now()
		Q3 := scalarMultG1(arrayG1, arrayW, nil, gsize)
		fmt.Printf("Gsize : %d, TMult time elapsed (inc table comp): %s\n", gsize, time.Since(beforeT))

		beforeT = time.Now()
		Q4 := mulTableNoDoubleG1(table, arrayW, nil, gsize)
		fmt.Printf("Gsize : %d, TMultNoDouble time elapsed: %s\n", gsize, time.Since(beforeT))

		beforeT = time.Now()
		Q5 := scalarMultNoDoubleG1(arrayG1, arrayW, nil, gsize)
		fmt.Printf("Gsize : %d, TMultNoDouble time elapsed (inc table comp): %s\n",
			gsize, time.Since(beforeT))

		if !bytes.Equal(Q1.Marshal(), Q2.Marshal()) {
			t.Error("Error in TMult")
		}
		if !bytes.Equal(Q1.Marshal(), Q3.Marshal()) {
			t.Error("Error in  TMult with table comp")
		}
		if !bytes.Equal(Q1.Marshal(), Q4.Marshal()) {
			t.Error("Error in  TMultNoDouble")
		}
		if !bytes.Equal(Q1.Marshal(), Q5.Marshal()) {
			t.Error("Error in  TMultNoDoublee with table comp")
		}
	}
}

func TestTableG2(t *testing.T) {
	n := n2

	// init scalar
	var arrayW = randomBigIntArray(n)
	// init G2 array
	var arrayG2 = randomG2Array(n)

	beforeT := time.Now()
	Q1 := new(curve.G2Affine).ScalarMultiplicationBase(new(big.Int))
	for i := 0; i < n; i++ {
		Q1.Add(Q1, new(curve.G2Affine).ScalarMultiplication(arrayG2[i], arrayW[i]))
	}
	fmt.Println("Std. Mult. time elapsed:", time.Since(beforeT))

	for gsize := 2; gsize < 10; gsize++ {
		ntables := int((n + gsize - 1) / gsize)
		table := make([]tableG2, ntables)

		for i := 0; i < ntables-1; i++ {
			table[i].newTableG2(arrayG2[i*gsize:(i+1)*gsize], gsize, false)
		}
		table[ntables-1].newTableG2(arrayG2[(ntables-1)*gsize:], gsize, false)

		beforeT = time.Now()
		Q2 := new(curve.G2Affine).ScalarMultiplicationBase(new(big.Int))
		for i := 0; i < ntables-1; i++ {
			Q2 = table[i].mulTableG2(arrayW[i*gsize:(i+1)*gsize], Q2, gsize)
		}
		Q2 = table[ntables-1].mulTableG2(arrayW[(ntables-1)*gsize:], Q2, gsize)
		fmt.Printf("Gsize : %d, TMult time elapsed: %s\n", gsize, time.Since(beforeT))

		beforeT = time.Now()
		Q3 := scalarMultG2(arrayG2, arrayW, nil, gsize)
		fmt.Printf("Gsize : %d, TMult time elapsed (inc table comp): %s\n", gsize, time.Since(beforeT))

		beforeT = time.Now()
		Q4 := mulTableNoDoubleG2(table, arrayW, nil, gsize)
		fmt.Printf("Gsize : %d, TMultNoDouble time elapsed: %s\n", gsize, time.Since(beforeT))

		beforeT = time.Now()
		Q5 := scalarMultNoDoubleG2(arrayG2, arrayW, nil, gsize)
		fmt.Printf("Gsize : %d, TMultNoDouble time elapsed (inc table comp): %s\n",
			gsize, time.Since(beforeT))

		if !bytes.Equal(Q1.Marshal(), Q2.Marshal()) {
			t.Error("Error in TMult")
		}
		if !bytes.Equal(Q1.Marshal(), Q3.Marshal()) {
			t.Error("Error in  TMult with table comp")
		}
		if !bytes.Equal(Q1.Marshal(), Q4.Marshal()) {
			t.Error("Error in  TMultNoDouble")
		}
		if !bytes.Equal(Q1.Marshal(), Q5.Marshal()) {
			t.Error("Error in  TMultNoDoublee with table comp")
		}
	}
}
