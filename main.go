package main

import (
	"github.com/gin-gonic/gin"
	"github.com/twostack/zklib"
	ivcgroth16 "github.com/twostack/zklib/twostack/groth16"
	"net/http"
)

type ProofData struct {
	Proof string `json:"proof" binding:"required"`
	TxnId string `json:"txn_id" binding:"required"`
}
type VerifyData struct {
	ProofType     string `json:"value" binding:"required"`
	PrevProof     ProofData
	CurrProofInfo ivcgroth16.BaseProofInfo
}

type VerifyResult struct {
	//TxnId    string `json:"txnid"`
	Verified bool `json:"verified"`
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

	vdata := &VerifyData{}

	if context.Bind(vdata) == nil {
		isVerified := verifyProof(vdata)

		if isVerified {
			context.JSON(
				http.StatusOK,
				VerifyResult{
					//TxnId:    vdata.CurrProofInfo.TransactionId,
					Verified: true,
				})

		} else {
			context.JSON(
				http.StatusOK,
				VerifyResult{
					//TxnId:    vdata.CurrProofInfo.TransactionId,
					Verified: false,
				})
		}

	}

}

func verifyProof(vdata *VerifyData) bool {
	return false
}

func handleRollupRoute(context *gin.Context) {

}

func main() {

	//bootstrap the base case proof system
	zklib.BootProofSystem()

	//check if normal case keys exist

	router := setupRouter()

	router.Run(":8080")
}
