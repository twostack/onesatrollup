package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/libsv/go-bt"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"io"
	"log"
	"math/big"
	"os"
	"time"
)

type BaseProofInfo struct {
	RawTx string `json:"raw_tx" binding:"required"`
}
type NormalProofInfo struct {
	RawTx        string `json:"raw_tx" binding:"required"`
	InputIndex   int    `json:"input_index"`
	IsParentBase bool   `json:"is_parent_base"`
	PrevTxId     string `json:"prev_tx_id"`
	Proof        string `json:"proof"`
}

var InnerField *big.Int = ecc.BLS12_377.ScalarField()
var OuterField *big.Int = ecc.BW6_761.ScalarField()
var verifierOptions backend.VerifierOption
var proverOptions backend.ProverOption

// normal params
var outerCurveId = ecc.BW6_761
var normalCcs constraint.ConstraintSystem
var normalVerifyingKey native_groth16.VerifyingKey
var normalProvingKey native_groth16.ProvingKey

// /
var innerCurveId = ecc.BLS12_377
var baseCcs constraint.ConstraintSystem
var baseVerifyingKey native_groth16.VerifyingKey
var baseProvingKey native_groth16.ProvingKey

func setupBaseCase(baseTxSize int) error {

	//IMPORTANT: Base proof needs to read the inner field's curveId
	innerCurveId = txivc.InnerCurve

	verifierOptions = groth16.GetNativeVerifierOptions(OuterField, InnerField)
	proverOptions = groth16.GetNativeProverOptions(OuterField, InnerField)

	var err error
	baseCcs, baseProvingKey, baseVerifyingKey, err = readBaseParams(baseTxSize)

	if err != nil {
		return err
	}

	return nil
}

func setupNormalCase(prefixSize int, postfixSize int) error {

	//IMPORTANT: Normal proof needs to read the OUTER field's curveId
	outerCurveId = txivc.OuterCurve

	var err error
	normalCcs, normalProvingKey, normalVerifyingKey, err = readNormalSetupParams(prefixSize, postfixSize)

	if err != nil {
		return err
	}

	return nil
}

func readNormalSetupParams(prefixSize int, postfixSize int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	if _, err := os.Stat("norm_ccs.cbor"); errors.Is(err, os.ErrNotExist) {

		//setup normal case for base parent VK
		normalCcs, normalProvingKey, normalVerifyingKey, err = txivc.SetupNormalCase(prefixSize, postfixSize, OuterField, baseCcs)

		//FIXME:
		//normalCcs, provingKey, verifyingKey, err := txivc.SetupNormalCase(outerField, *normalCcs)

		normalCcsFile, err := os.Create("norm_ccs.cbor")
		_, err = normalCcs.WriteTo(normalCcsFile)
		if err != nil {
			return nil, nil, nil, err
		}
		normalCcsFile.Close()

		err = writeKeys(normalVerifyingKey, normalProvingKey, "norm_")
		if err != nil {
			return nil, nil, nil, err
		}

		return normalCcs, normalProvingKey, normalVerifyingKey, nil
	} else {

		//in this portion we don't run Setup() again, because that generates different keys
		ccs, err := readCircuitParams("norm_", outerCurveId)
		if err != nil {
			return nil, nil, nil, err
		}

		verifyingKey, provingKey, err := readKeys("norm_", outerCurveId)
		if err != nil {
			return nil, nil, nil, err
		}

		return ccs, provingKey, verifyingKey, nil
	}
}

func readBaseParams(txSize int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	if _, err := os.Stat("base_ccs.cbor"); errors.Is(err, os.ErrNotExist) {

		ccs, provingKey, verifyingKey, err := txivc.SetupBaseCase(txSize, InnerField)
		if err != nil {
			return nil, nil, nil, err
		}

		baseccsFile, err := os.Create("base_ccs.cbor")
		_, err = ccs.WriteTo(baseccsFile)
		if err != nil {
			return nil, nil, nil, err
		}
		baseccsFile.Close()

		err = writeKeys(verifyingKey, provingKey, "base_")
		if err != nil {
			return nil, nil, nil, err
		}

		return ccs, provingKey, verifyingKey, nil
	} else {

		//in this portion we don't run Setup() again, because that generates different keys
		ccs, err := readCircuitParams("base_", innerCurveId)
		if err != nil {
			return nil, nil, nil, err
		}

		verifyingKey, provingKey, err := readKeys("base_", innerCurveId)
		if err != nil {
			return nil, nil, nil, err
		}

		return ccs, provingKey, verifyingKey, nil
	}
}

func readCircuitParams(prefix string, curveId ecc.ID) (constraint.ConstraintSystem, error) {

	baseCcs := native_groth16.NewCS(curveId)

	ccsFile, err := os.OpenFile(prefix+"ccs.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		return nil, err
	}
	_, err = baseCcs.ReadFrom(ccsFile)
	if err != nil {
		return nil, err
	}
	ccsFile.Close()

	return baseCcs, nil
}

func writeKeys(verifyingKey native_groth16.VerifyingKey, provingKey native_groth16.ProvingKey, prefix string) error {

	start := time.Now()
	innerVKFile, err := os.Create(prefix + "vk.cbor")
	_, err = verifyingKey.WriteRawTo(innerVKFile)
	if err != nil {
		return fmt.Errorf("Failed to write Verifying Key - %s", err)
	}
	err = innerVKFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to close verifying key file handle  - %s", err)
	}
	end := time.Since(start)
	fmt.Printf("Exporting Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.Create(prefix + "pk.cbor")
	_, err = provingKey.WriteRawTo(innerPKFile)
	if err != nil {
		return fmt.Errorf("Failed to write Proving Key - %s", err)
	}
	err = innerPKFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to properly close Proving Key File handle - %s", err)
	}
	end = time.Since(start)
	fmt.Printf("Exporting Proving Key took : %s\n", end)
	return nil
}

func readKeys(prefix string, curveId ecc.ID) (native_groth16.VerifyingKey, native_groth16.ProvingKey, error) {

	start := time.Now()
	innerVKFile, err := os.OpenFile(prefix+"vk.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	innerVK := native_groth16.NewVerifyingKey(curveId) //curve for inner circuit
	_, err = innerVK.ReadFrom(innerVKFile)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	innerVKFile.Close()
	end := time.Since(start)
	fmt.Printf("Importing Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.OpenFile(prefix+"pk.cbor", os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	innerPK := native_groth16.NewProvingKey(curveId) //curve for inner circuit
	_, err = innerPK.ReadFrom(innerPKFile)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}

	innerPKFile.Close()
	end = time.Since(start)
	fmt.Printf("Importing Proving Key took : %s\n", end)

	return innerVK, innerPK, nil
}

func CreateNormalCaseProof(normalInfo *NormalProofInfo) (string, error) {

	//var prevTxWitness witness.Witness

	fullTxBytes, err := hex.DecodeString(normalInfo.RawTx)
	if err != nil {
		return "", err
	}

	prefixBytes, prevTxnId, postfixBytes, err := SliceTx(fullTxBytes, normalInfo.InputIndex)

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	prevTxProof, err := txivc.UnmarshalProof(normalInfo.Proof, innerCurveId)
	if err != nil {
		fmt.Printf("Failed to unmarshall provided json proof object:   %s\n", err)
		return "", err
	}

	prevTxWitness, err := txivc.CreateBaseCaseLightWitness(prevTxnId[:], InnerField)

	pubWitness, err := prevTxWitness.Public()
	isVerified := txivc.VerifyProof(pubWitness, prevTxProof, baseVerifyingKey)
	if !isVerified {
		return "Failed to verify the inner proof", err
	}

	circuitVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseVerifyingKey)
	circuitWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	circuitProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](prevTxProof)

	outerAssignment := txivc.CreateOuterAssignment(circuitWitness, circuitProof, circuitVk, prefixBytes, prevTxnId, postfixBytes, currTxId[:])
	outerWitness, err := frontend.NewWitness(&outerAssignment, OuterField)
	if err != nil {
		fmt.Printf("Fail ! %s\n", err)
		return "", err
	}

	resultProof, err := txivc.ComputeProof(normalCcs, normalProvingKey, outerWitness)
	//outerProof, err := txivc.ComputeProof(outerCcs, outerProvingKey, outerWitness)

	jsonBytes, err := json.Marshal(resultProof)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil

}

/*
Split a Raw Transaction into it's component "prefix", "suffix" and "postfix" parts

inputIndex - the index of the input that
*/
func SliceTx(rawTx []byte, inputIndex int) ([]byte, []byte, []byte, error) {

	//tx, err := bt.NewTxFromBytes(rawTx)

	reader := bytes.NewReader(rawTx)

	txIdStart, postfixStart, err := getOffSets(uint64(inputIndex), reader)

	if err != nil {
		return nil, nil, nil, err
	}

	return rawTx[0:txIdStart], rawTx[txIdStart : txIdStart+32], rawTx[postfixStart:len(rawTx)], nil

}

func getOffSets(inputIndex uint64, r io.Reader) (int, int, error) {
	t := bt.Tx{}

	version := make([]byte, 4)
	if n, err := io.ReadFull(r, version); n != 4 || err != nil {
		return 0, 0, err
	}
	t.Version = binary.LittleEndian.Uint32(version)

	var err error

	inputCount, _, err := bt.DecodeVarIntFromReader(r)
	if err != nil {
		return 0, 0, err
	}

	if inputCount < inputIndex+1 {
		return 0, 0, fmt.Errorf("Input index is outside of the range of [%d] available inputs", inputCount)
	}

	inputCountSize := len(bt.VarInt(inputCount))

	txIdOffSet := 4 + inputCountSize //version + numInput bytes

	// create Inputs
	var i uint64 = 0
	var input *bt.Input

	//read up to input # inputIndex

	for ; i < inputIndex; i++ {
		input, err = bt.NewInputFromReader(r)
		if err != nil {
			return 0, 0, err
		}
		t.Inputs = append(t.Inputs, input)
	}

	//get the size of inputs read so far
	var inputSize int = 0
	for _, input := range t.Inputs {
		inputSize = inputSize + len(input.ToBytes(false))
	}

	//since the first entry of the next input is the txid we want
	txIdOffSet = txIdOffSet + inputSize

	postfixStart := txIdOffSet + 32

	return txIdOffSet, postfixStart, nil

}

/*
*
Light witness is used for verification of an existing proof. I.e. only public params are filled.
*/
func CreateNormalLightWitness(txId []byte, outerField *big.Int) (*witness.Witness, error) {

	outerAssignment := txivc.Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		CurrTxId: make([]frontend.Variable, 32),
	}

	lightWitness, err := frontend.NewWitness(&outerAssignment, outerField)

	if err != nil {
		return nil, err
	}

	return &lightWitness, nil

}

func CreateBaseCaseProof(pInfo *BaseProofInfo) (string, error) {

	fullTxBytes, _ := hex.DecodeString(pInfo.RawTx)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId[:])

	if err != nil {
		return "", err
	}
	genesisProof, err := txivc.ComputeProof(baseCcs, baseProvingKey, genesisWitness)

	jsonBytes, err := json.Marshal(genesisProof)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func VerifyBaseProof(txId string, jsonProof string) bool {

	txProof := native_groth16.NewProof(txivc.InnerCurve)

	err := json.Unmarshal([]byte(jsonProof), &txProof)
	if err != nil {
		fmt.Printf("%s", err)
		return false
	}

	genesisTxId, err := hex.DecodeString(txId)
	if err != nil {
		fmt.Printf("%s", err)
		return false
	}
	publicWitness, err := txivc.CreateBaseCaseLightWitness(genesisTxId[:], InnerField)
	if err != nil {
		fmt.Printf("%s", err)
		return false
	}

	//isVerified := ps.VerifyProof(publicWitness, &txProof)

	//func (po *BaseProof) VerifyProof(witness *witness.Witness, proof *native_groth16.Proof) bool {
	err = native_groth16.Verify(txProof, baseVerifyingKey, publicWitness, verifierOptions)
	if err != nil {
		fmt.Printf("Fail on proof verification! %s\n", err)
		return false
	}

	return true

}

func VerifyNormalProof(txnId string, proof string) bool {
	return false
}
