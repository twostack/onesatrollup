package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"net/http"
	"time"
)

type VerifyData struct {
	Proof     string `json:"proof" binding:"required"`
	TxnId     string `json:"txn_id" binding:"required"`
	ProofType string `json:"proof_type" binding:"required"`
}

type VerifyResult struct {
	TxnId    string `json:"txnid"`
	Verified bool   `json:"verified"`
}

func setupRouter() *gin.Engine {

	router := gin.Default()

	router.POST("/prove/base", handleBaseCaseProverRoute)
	router.POST("/prove/normal", handleNormalCaseProverRoute)
	router.POST("/verify/base", handleBaseVerifyRoute)
	router.POST("/verify/normal", handleNormalVerifyRoute)
	router.POST("/rollup", handleRollupRoute)

	return router
}

/*
*
 */
func handleBaseVerifyRoute(context *gin.Context) {

	vData := &VerifyData{}

	if context.Bind(vData) == nil {
		var isVerified bool = false
		if vData.ProofType == "base" {
			isVerified = VerifyBaseProof(vData.TxnId, vData.Proof)
		} else {
			isVerified = VerifyNormalProof(vData.TxnId, vData.Proof)
		}

		context.JSON(
			http.StatusOK,
			VerifyResult{
				TxnId:    vData.TxnId,
				Verified: isVerified,
			})

	}

}

func handleRollupRoute(context *gin.Context) {

	benchNormalCaseGroth16()
}

func main() {

	prefixBytes, _ := hex.DecodeString("0200000001")
	//prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ := hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	//fullTxBytes, _ := hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	err := setupBaseCase(191) //FIXME: config !
	if err != nil {
		fmt.Printf("Failed to bootstrap Base Case of Proof System: %s\n", err)
		return
	}
	err = setupNormalCase(len(prefixBytes), len(postFixBytes))

	if err != nil {
		fmt.Printf("Failed to bootstrap Normal Case of Proof System: %s\n", err)
		return
	}

	//check if normal case keys exist

	router := setupRouter()

	router.Run(":8080")
}

func benchNormalCaseGroth16() {

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId[:])

	start := time.Now()
	genesisProof, err := txivc.ComputeProof(baseCcs, baseProvingKey, genesisWitness)
	elapsed := time.Since(start)
	fmt.Printf("Base case proof created: %s\n", elapsed)

	if err != nil {
		fmt.Printf("Fail on base case proof ! %s\n", err)
		return
	}
	pubGenWitness, err := genesisWitness.Public()
	isVerified := txivc.VerifyProof(pubGenWitness, genesisProof, baseVerifyingKey)
	if !isVerified {
		return
	}

	//can create a lightweight witness here for verification
	//innerVk, err := groth16.ValueOfVerifyingKey[grothivc.G1Affine, grothivc.G2Affine, grothivc.GTEl](verifyingKey)

	//spending tx info
	prefixBytes, _ = hex.DecodeString("0200000001")
	prevTxnIdBytes, _ = hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ = hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	fullTxBytes, _ = hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	//start = time.Now()
	//outerCcs, outerProvingKey, _, err := txivc.SetupNormalCase(len(prefixBytes), len(postFixBytes), OuterField, baseCcs) //using placeholders for pk and proof
	//elapsed = time.Since(start)
	//fmt.Printf("Normal Case Setup: %s\n", elapsed)
	//if err != nil {
	//	fmt.Printf("Fail on normal case setup! %s\n", err)
	//	return
	//}

	circuitVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseVerifyingKey)
	circuitWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](genesisWitness)
	circuitProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](genesisProof)
	firstHash = sha256.Sum256(fullTxBytes)
	normalTxId := sha256.Sum256(firstHash[:])
	outerAssignment := txivc.CreateOuterAssignment(circuitWitness, circuitProof, circuitVk, prefixBytes, prevTxnIdBytes, postFixBytes, normalTxId[:])
	outerWitness, err := frontend.NewWitness(&outerAssignment, OuterField)
	if err != nil {
		fmt.Printf("Fail ! %s\n", err)
		return
	}

	start = time.Now()
	outerProof, err := txivc.ComputeProof(normalCcs, normalProvingKey, outerWitness)
	//outerProof, err := txivc.ComputeProof(outerCcs, outerProvingKey, outerWitness)

	elapsed = time.Since(start)
	fmt.Printf("Proof compute took : %s\n", elapsed)
	if err != nil {
		fmt.Printf("Proof computation failed ! %s\n", err)
		return
	}

	//verify the normal proof
	publicOuterWitness, err := outerWitness.Public()
	isVerified = txivc.VerifyProof(publicOuterWitness, outerProof, normalVerifyingKey)

	if !isVerified {
		return
	}

	log.Info().Msg("Compled normal case proving")
}
