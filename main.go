package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/twostack/zklib"
	ivcgroth16 "github.com/twostack/zklib/twostack/groth16"
	"net/http"
	"os"
)

type Prover struct {
	InnerCcs     constraint.ConstraintSystem
	ProvingKey   native_groth16.ProvingKey
	VerifyingKey native_groth16.VerifyingKey
}

//
//func NewProver() *Prover {
//
//	p := &Prover{}
//
//	innerField := ecc.BLS24_315.ScalarField()
//
//	//check if keys exist, if yes, load from disk, otherwise compile and save.
//	innerCcs, provingKey, verifyingKey, err := ivcgroth16.SetupBaseCase(innerField)
//
//	if err != nil {
//		return nil
//	}
//
//	p.InnerCcs = innerCcs
//	p.ProvingKey = provingKey
//	p.VerifyingKey = verifyingKey
//
//	return p
//}

//var prover = NewProver()

/*
	{
		"case": "normal | base",
		"prevProofData" : {
			"proof" : [hex encoded proof],
			"prevTxnId" : [hex encoded bytes],
		}
		"data" : {
		  "prefixBytes" : [hex encoded bytes]
			"postFixBytes" : [hex encoded bytes],
			"prevTxnIdBytes" : [hex encoded bytes],
			"txId" : [hex encoded bytes],
		}
	}
*/

type ProofInfo struct {
	RawTx         string `json:"raw_tx" binding:"required"`
	Prefix        string
	Postfix       string
	PrevTxnId     string
	TransactionId string
}

type ProofData struct {
	Proof string `json:"proof" binding:"required"`
	TxnId string `json:"txn_id" binding:"required"`
}
type VerifyData struct {
	ProofType     string `json:"value" binding:"required"`
	PrevProof     ProofData
	CurrProofInfo ProofInfo
}

type VerifyResult struct {
	TxnId    string `json:"txnid"`
	Verified bool   `json:"verified"`
}

func setupRouter() *gin.Engine {

	router := gin.Default()

	router.POST("/prove", handleProverRoute)
	router.POST("/verify", handleVerifyRoute)
	router.POST("/rollup", handleRollupRoute)

	return router
}

func handleRollupRoute(context *gin.Context) {

}

/*
*
 */
func handleVerifyRoute(context *gin.Context) {

	vdata := &VerifyData{}

	if context.Bind(vdata) == nil {
		isVerified := verifyProof(vdata)

		if isVerified {
			context.JSON(
				http.StatusOK,
				VerifyResult{
					TxnId:    vdata.CurrProofInfo.TransactionId,
					Verified: true,
				})

		} else {
			context.JSON(
				http.StatusOK,
				VerifyResult{
					TxnId:    vdata.CurrProofInfo.TransactionId,
					Verified: false,
				})
		}

	}

}

func verifyProof(vdata *VerifyData) bool {
	return false
}

func handleProverRoute(context *gin.Context) {

	pInfo := ProofInfo{}

	if context.Bind(&pInfo) == nil {

		log.Print(pInfo.Prefix)
		log.Print(pInfo.Postfix)
		proof, err := createBaseCaseProof(&pInfo)

		if err != nil {
			log.Err(err)
			context.Error(err)
		} else {
			context.JSON(
				http.StatusOK,
				gin.H{
					"proof": proof,
				})
		}

	}
}

func createBaseCaseProof(pInfo *ProofInfo) (string, error) {

	innerField := ecc.BLS24_315.ScalarField()
	outerField := ecc.BW6_633.ScalarField()

	fullTxBytes, _ := hex.DecodeString(pInfo.RawTx)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := ivcgroth16.CreateBaseCaseWitness(fullTxBytes, genesisTxId, innerField)

	if err != nil {
		return "", err
	}
	genesisProof, err := native_groth16.Prove(baseProof.Ccs, baseProof.ProvingKey, genesisWitness, groth16.GetNativeProverOptions(outerField, innerField))

	jsonBytes, err := json.Marshal(genesisProof)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func bootBaseProof() (*zklib.BaseProof, error) {

	baseProof, err := zklib.NewBaseProof()
	if err != nil {
		log.Err(err)
		return nil, err
	}

	if _, err := os.Stat("base_pk.cbor"); errors.Is(err, os.ErrNotExist) {
		err = baseProof.SetupKeys()
		if err != nil {
			return nil, err
		}
		err = baseProof.WriteKeys()
		if err != nil {
			return nil, err
		}
	} else {
		err = baseProof.ReadKeys()
		if err != nil {
			return nil, err
		}
	}

	return baseProof, nil
}

func bootNormalProof(ccs constraint.ConstraintSystem, vk native_groth16.VerifyingKey) (*zklib.NormalProof, error) {

	normalProof, err := zklib.NewNormalProof(ccs, vk)
	if err != nil {
		log.Err(err)
		return nil, err
	}

	if _, err := os.Stat("normal_pk.cbor"); errors.Is(err, os.ErrNotExist) {
		err = normalProof.SetupKeys()
		if err != nil {
			return nil, err
		}
		err = normalProof.WriteKeys()
		if err != nil {
			return nil, err
		}
	} else {
		err = normalProof.ReadKeys()
		if err != nil {
			return nil, err
		}
	}

	return normalProof, nil
}

var baseProof *zklib.BaseProof
var normalProof *zklib.NormalProof

func main() {

	//bootstrap the base case proof system
	fmt.Println("Booting base case proof system. This will take around 1 minute")
	bp, err := bootBaseProof()
	if err != nil {
		return
	}
	baseProof = bp

	//bootstrap the normal case proof system
	fmt.Println("Booting normal case proof system. This will take around 1 minute")
	np, err := bootNormalProof(baseProof.Ccs, baseProof.VerifyingKey)
	if err != nil {
		return
	}
	normalProof = np

	//check if normal case keys exist

	router := setupRouter()

	router.Run(":8080")
}