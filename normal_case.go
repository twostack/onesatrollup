package main

import (
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

		proof, pubWitness, err := CreateNormalCaseProof(&pInfo, baseVerifyingKey, normalVerifyingKey, baseCcs)

		if err != nil {
			log.Err(err)
			context.Error(err)
		} else {
			context.JSON(
				http.StatusOK,
				gin.H{
					"proof":   proof,
					"witness": pubWitness,
				})
		}

	} else {
		log.Error().Msg(fmt.Sprintf("Error parsing JSON: [%s]\n", err.Error()))
	}
}
