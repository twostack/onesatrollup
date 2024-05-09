package main

import (
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
)

type VerifyData struct {
	Proof string `json:"proof"`
	TxnId string `json:"txn_id"`
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

func handleRollupRoute(context *gin.Context) {

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
