package main

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"net/http"
)

func handleBaseCaseProverRoute(context *gin.Context) {

	pInfo := BaseProofInfo{}

	if context.Bind(&pInfo) == nil {

		proof, err := CreateBaseCaseProof(&pInfo)

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

func handleBaseVerifyRoute(context *gin.Context) {

	vData := &VerifyData{}

	if context.Bind(vData) == nil {
		isVerified := VerifyBaseProof(vData.TxnId, vData.Proof, innerCurveId, outerCurveId)

		context.JSON(
			http.StatusOK,
			VerifyResult{
				TxnId:    vData.TxnId,
				Verified: isVerified,
			})

	}

}
