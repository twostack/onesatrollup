package main

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"net/http"
)

func handleBaseCaseProverRoute(context *gin.Context) {

	pInfo := txivc.BaseProofInfo{}

	if context.Bind(&pInfo) == nil {

		proof, err := proofSystem.CreateBaseCaseProof(&pInfo)

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
