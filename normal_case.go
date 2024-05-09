package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"net/http"
)

func handleNormalVerifyRoute(context *gin.Context) {

	vData := &VerifyData{}

	if context.Bind(vData) == nil {

		isVerified := VerifyNormalProof(vData.TxnId, vData.Proof, innerCurveId, outerCurveId)
		if !isVerified {
			log.Error().Msg("\nVerify with Outer CurveID failed \n")
		}

		context.JSON(
			http.StatusOK,
			VerifyResult{
				TxnId:    vData.TxnId,
				Verified: isVerified,
			})

	}
}

func handleNormalCaseProverRoute(context *gin.Context) {

	pInfo := NormalProofInfo{}

	err := context.Bind(&pInfo)

	if err == nil {

		fullTxBytes, err := hex.DecodeString(pInfo.RawTx)

		firstHash := sha256.Sum256(fullTxBytes)
		currTxId := sha256.Sum256(firstHash[:])

		//TODO: currTxId should be returned from following method, not passed in. Too lazy to fix now.
		proof, err := CreateNormalCaseProof(currTxId[:], &pInfo, baseVerifyingKey, normalVerifyingKey)

		if err != nil {
			log.Err(err)
			context.Error(err)
		} else {
			context.JSON(
				http.StatusOK,
				gin.H{
					"txn_id": currTxId,
					"proof":  proof,
				})
		}

	} else {
		log.Error().Msg(fmt.Sprintf("Error parsing JSON: [%s]\n", err.Error()))
	}
}
