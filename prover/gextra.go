package prover

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	cryptoConstants "github.com/iden3/go-iden3-crypto/constants"
)

type tableG1 struct {
	data []*curve.G1Affine
}

//nolint:unused // TODO check
func (t tableG1) getData() []*curve.G1Affine {
	return t.data
}

// Compute table of gsize elements as ::
//
//	Table[0] = Inf
//	Table[1] = a[0]
//	Table[2] = a[1]
//	Table[3] = a[0]+a[1]
//	.....
//	Table[(1<<gsize)-1] = a[0]+a[1]+...+a[gsize-1]
func (t *tableG1) newTableG1(a []*curve.G1Affine, gsize int, toaffine bool) {
	// EC table
	table := make([]*curve.G1Affine, 0)

	// We need at least gsize elements. If not enough, fill with 0
	aExt := make([]*curve.G1Affine, 0)
	aExt = append(aExt, a...)

	for i := len(a); i < gsize; i++ {
		aExt = append(aExt, new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0)))
	}

	elG1 := new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	table = append(table, elG1)
	lastPow2 := 1
	nelems := 0
	for i := 1; i < 1<<gsize; i++ {
		elG1 := new(curve.G1Affine)
		// if power of 2
		if i&(i-1) == 0 {
			lastPow2 = i
			elG1.Set(aExt[nelems])
			nelems++
		} else {
			elG1.Add(table[lastPow2], table[i-lastPow2])
			// TODO bn256 doesn't export MakeAffine function. We need to fork repo
			//table[i].MakeAffine()
		}
		table = append(table, elG1)
	}
	if toaffine {
		for i := 0; i < len(table); i++ {
			info := table[i].Marshal()
			table[i].Unmarshal(info) //nolint:errcheck,gosec // TODO WIP
		}
	}
	t.data = table
}

func (t tableG1) Marshal() []byte {
	info := make([]byte, 0)
	for _, el := range t.data {
		info = append(info, el.Marshal()...)
	}

	return info
}

// Multiply scalar by precomputed table of G1 elements
func (t *tableG1) mulTableG1(k []*big.Int, qPrev *curve.G1Affine, gsize int) *curve.G1Affine {
	// We need at least gsize elements. If not enough, fill with 0
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)

	for i := len(k); i < gsize; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}

	Q := new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))

	msb := getMsb(kExt)

	for i := msb - 1; i >= 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		Q = new(curve.G1Affine).Add(Q, Q)
		b := getBit(kExt, i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q.Add(Q, t.data[b])
		}
	}
	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G1 elements without intermediate doubling
func mulTableNoDoubleG1(t []tableG1, k []*big.Int, qPrev *curve.G1Affine, gsize int) *curve.G1Affine {
	// We need at least gsize elements. If not enough, fill with 0
	minNElems := len(t) * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*curve.G1Affine, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < len(t); j++ {
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], t[j].data[b])
			}
		}
	}

	// Consolidate Addition
	R := new(curve.G1Affine).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(curve.G1Affine).Add(R, R)
		R.Add(R, Q[i-1])
	}

	if qPrev != nil {
		return R.Add(R, qPrev)
	}
	return R
}

// Compute tables within function. This solution should still be faster than std  multiplication
// for gsize = 7
func scalarMultG1(a []*curve.G1Affine, k []*big.Int, qPrev *curve.G1Affine, gsize int) *curve.G1Affine {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG1{}
	Q := new(curve.G1Affine).ScalarMultiplicationBase(new(big.Int))

	for i := 0; i < ntables-1; i++ {
		table.newTableG1(a[i*gsize:(i+1)*gsize], gsize, false)
		Q = table.mulTableG1(k[i*gsize:(i+1)*gsize], Q, gsize)
	}
	table.newTableG1(a[(ntables-1)*gsize:], gsize, false)
	Q = table.mulTableG1(k[(ntables-1)*gsize:], Q, gsize)

	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G1 elements without intermediate doubling
func scalarMultNoDoubleG1(a []*curve.G1Affine, k []*big.Int, qPrev *curve.G1Affine, gsize int) *curve.G1Affine {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG1{}

	// We need at least gsize elements. If not enough, fill with 0
	minNElems := ntables * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*curve.G1Affine, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(curve.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	}

	// Perform bitwise addition
	var jacQ curve.G1Jac
	for j := 0; j < ntables-1; j++ {
		table.newTableG1(a[j*gsize:(j+1)*gsize], gsize, false)
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])
		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				// Q[i].Add(Q[i], table.data[b])
				// DONE
				jacQ.FromAffine(Q[i])
				jacQ.AddMixed(table.data[b])
				Q[i].FromJacobian(&jacQ)
			}
		}
	}
	table.newTableG1(a[(ntables-1)*gsize:], gsize, false)
	msb := getMsb(kExt[(ntables-1)*gsize:])

	for i := msb - 1; i >= 0; i-- {
		b := getBit(kExt[(ntables-1)*gsize:], i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			// Q[i].Add(Q[i], table.data[b])
			// Using gnark-crypto library for mixed addition (Jacobian + Affine)
			jacQ.FromAffine(Q[i])
			jacQ.AddMixed(table.data[b])
			Q[i].FromJacobian(&jacQ)
		}
	}

	// Consolidate Addition
	//	R := new(curve.G1Affine).Set(Q[nbitsQ-1])
	//	for i := nbitsQ - 1; i > 0; i-- {
	// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
	//		R = new(curve.G1Affine).Add(R, R)
	//		R.Add(R, Q[i-1])
	//	}
	//	if qPrev != nil {
	//		return R.Add(R, qPrev)
	//	}

	// Consolidate Addition
	RJac := new(bn254.G1Jac)
	RJac.FromAffine(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		RJac.Double(RJac) // Use the Double method for Jacobian points
		jacQ.FromAffine(Q[i-1])
		RJac.AddAssign(&jacQ)
	}
	R := new(bn254.G1Affine).FromJacobian(RJac)
	if qPrev != nil {
		var qPrevJac bn254.G1Jac
		qPrevJac.FromAffine(qPrev)
		RJac.AddAssign(&qPrevJac)
		R.FromJacobian(RJac)
	}

	return R
}

/////

// TODO - How can avoid replicating code in G2?
//G2

type tableG2 struct {
	data []*curve.G2Affine
}

//nolint:unused // TODO check
func (t tableG2) getData() []*curve.G2Affine {
	return t.data
}

// Compute table of gsize elements as ::
//
//	Table[0] = Inf
//	Table[1] = a[0]
//	Table[2] = a[1]
//	Table[3] = a[0]+a[1]
//	.....
//	Table[(1<<gsize)-1] = a[0]+a[1]+...+a[gsize-1]
//
// TODO -> toaffine = True doesnt work. Problem with Marshal/Unmarshal
func (t *tableG2) newTableG2(a []*curve.G2Affine, gsize int, toaffine bool) {
	// EC table
	table := make([]*curve.G2Affine, 0)

	// We need at least gsize elements. If not enough, fill with 0
	aExt := make([]*curve.G2Affine, 0)
	aExt = append(aExt, a...)
	zero := new(curve.G2Affine).ScalarMultiplicationBase(big.NewInt(0))
	for i := len(a); i < gsize; i++ {
		aExt = append(aExt, zero)
	}

	elG2 := new(curve.G2Affine).ScalarMultiplicationBase(big.NewInt(0))
	table = append(table, elG2)
	lastPow2 := 1
	nelems := 0
	for i := 1; i < 1<<gsize; i++ {
		elG2 := new(curve.G2Affine)
		// if power of 2
		if i&(i-1) == 0 {
			lastPow2 = i
			elG2.Set(aExt[nelems])
			nelems++
		} else {
			elG2.Add(table[lastPow2], table[i-lastPow2])
			// TODO bn256 doesn't export MakeAffine function. We need to fork repo
			//table[i].MakeAffine()
		}
		table = append(table, elG2)
	}
	if toaffine {
		for i := 0; i < len(table); i++ {
			info := table[i].Marshal()
			table[i].Unmarshal(info) //nolint:errcheck,gosec // TODO WIP
		}
	}
	t.data = table
}

func (t tableG2) Marshal() []byte {
	info := make([]byte, 0)
	for _, el := range t.data {
		info = append(info, el.Marshal()...)
	}

	return info
}

// Multiply scalar by precomputed table of G2 elements
func (t *tableG2) mulTableG2(k []*big.Int, qPrev *curve.G2Affine, gsize int) *curve.G2Affine {
	// We need at least gsize elements. If not enough, fill with 0
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)

	for i := len(k); i < gsize; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}

	Q := new(curve.G2Affine).ScalarMultiplicationBase(big.NewInt(0))

	msb := getMsb(kExt)

	for i := msb - 1; i >= 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		Q = new(curve.G2Affine).Add(Q, Q)
		b := getBit(kExt, i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q.Add(Q, t.data[b])
		}
	}
	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G2 elements without intermediate doubling
func mulTableNoDoubleG2(t []tableG2, k []*big.Int, qPrev *curve.G2Affine, gsize int) *curve.G2Affine {
	// We need at least gsize elements. If not enough, fill with 0
	minNElems := len(t) * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*curve.G2Affine, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(curve.G2Affine).ScalarMultiplicationBase(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < len(t); j++ {
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], t[j].data[b])
			}
		}
	}

	// Consolidate Addition
	R := new(curve.G2Affine).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(curve.G2Affine).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if qPrev != nil {
		return R.Add(R, qPrev)
	}
	return R
}

// Compute tables within function. This solution should still be faster than std  multiplication
// for gsize = 7
func scalarMultG2(a []*curve.G2Affine, k []*big.Int, qPrev *curve.G2Affine, gsize int) *curve.G2Affine {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG2{}
	Q := new(curve.G2Affine).ScalarMultiplicationBase(new(big.Int))

	for i := 0; i < ntables-1; i++ {
		table.newTableG2(a[i*gsize:(i+1)*gsize], gsize, false)
		Q = table.mulTableG2(k[i*gsize:(i+1)*gsize], Q, gsize)
	}
	table.newTableG2(a[(ntables-1)*gsize:], gsize, false)
	Q = table.mulTableG2(k[(ntables-1)*gsize:], Q, gsize)

	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G2 elements without intermediate doubling
func scalarMultNoDoubleG2(a []*curve.G2Affine, k []*big.Int, qPrev *curve.G2Affine, gsize int) *curve.G2Affine {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG2{}

	// We need at least gsize elements. If not enough, fill with 0
	minNElems := ntables * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}

	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	fmt.Println("Q size is", nbitsQ)
	Q := make([]*bn254.G2Jac, nbitsQ)

	fmt.Println("performing scalar mult", nbitsQ)
	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn254.G2Jac).ScalarMultiplicationBase(big.NewInt(0))
	}

	var tableDataJac bn254.G2Jac
	fmt.Println("performing bitwise addition", ntables)
	// Perform bitwise addition
	for j := 0; j < ntables-1; j++ {
		table.newTableG2(a[j*gsize:(j+1)*gsize], gsize, false)
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				tableDataJac.FromAffine(table.data[b])
				Q[i].AddAssign(&tableDataJac)
			}
		}
	}
	fmt.Println("end of bitwise addition")
	fmt.Println("creating new tables G2")
	table.newTableG2(a[(ntables-1)*gsize:], gsize, false)
	fmt.Println("get msb")
	msb := getMsb(kExt[(ntables-1)*gsize:])

	fmt.Println("getBit")
	for i := msb - 1; i >= 0; i-- {
		b := getBit(kExt[(ntables-1)*gsize:], i)
		if b != 0 {
			tableDataJac.FromAffine(table.data[b])
			Q[i].AddAssign(&tableDataJac)
		}
	}

	// Consolidate Addition
	fmt.Println("consolidate addition")
	R := new(bn254.G2Jac).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		R.DoubleAssign()
		R.AddAssign(Q[i-1])
	}
	if qPrev != nil {
		var qPrevJac bn254.G2Jac
		qPrevJac.FromAffine(qPrev)
		R.AddAssign(&qPrevJac)
	}
	// Convert R back to affine form before returning
	var Raff bn254.G2Affine
	Raff.FromJacobian(R)
	return &Raff
}

// Return most significant bit position in a group of Big Integers
func getMsb(k []*big.Int) int {
	msb := 0

	for _, el := range k {
		tmpMsb := el.BitLen()
		if tmpMsb > msb {
			msb = tmpMsb
		}
	}
	return msb
}

// Return ith bit in group of Big Integers
func getBit(k []*big.Int, i int) uint {
	tableIdx := uint(0)

	for idx, el := range k {
		b := el.Bit(i)
		tableIdx += (b << idx)
	}
	return tableIdx
}
