# go-ethereum-bip39

```go
package main

import (
	"fmt"
	"github.com/1makarov/go-ethereum-bip39"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

func example1() {
	seed := bip39.NewSeed("mnemonic", "password")

	path, err := bip39.MustParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		log.Fatalln(err)
	}

	privateKey, err := bip39.SeedPathToECDSA(seed, path)
	if err != nil {
		log.Fatalln(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hexutil.Encode(privateKeyBytes)

	fmt.Println(privateKeyHex)
}

func example2() {
	privateKey, err := bip39.MnemonicPathToECDSA("mnemonic", "password", "m/44'/60'/0'/0/0")
	if err != nil {
		log.Fatalln(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hexutil.Encode(privateKeyBytes)

	fmt.Println(privateKeyHex)
}
```