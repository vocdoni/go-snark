module github.com/vocdoni/go-snark

replace github.com/consensys/gnark-crypto => github.com/vocdoni/gnark-crypto v0.10.1-0.20230616100730-4d2caf756b80

replace github.com/consensys/gnark => github.com/vocdoni/gnark v0.0.0-20230609152227-b0fa77ea116a

go 1.16

require (
	github.com/consensys/gnark v0.7.2-0.20230609182217-172cc2499244
	github.com/consensys/gnark-crypto v0.11.1-0.20230615015719-a3b568a67d79
	github.com/iden3/go-iden3-crypto v0.0.5
	github.com/stretchr/testify v1.8.2
)
