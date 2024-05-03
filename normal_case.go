package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	txivc "github.com/twostack/zklib/twostack/groth16"
)

func handleNormalVerifyRoute(context *gin.Context) {

}

func handleNormalCaseProverRoute(context *gin.Context) {

	pInfo := txivc.NormalProofInfo{}

	err := context.Bind(&pInfo)

	if err == nil {

		////proof, err := proofSystem.CreateNormalCaseProof(&pInfo)
		////
		////if err != nil {
		////	log.Err(err)
		////	context.Error(err)
		////} else {
		////	context.JSON(
		////		http.StatusOK,
		////		gin.H{
		////			"proof": proof,
		////		})
		//}

	} else {
		log.Error().Msg(fmt.Sprintf("Error parsing JSON: [%s]\n", err.Error()))
	}
}
