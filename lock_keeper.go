package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/sha3"
)

func Login() (string, error) {
	lockKeeperConfig, err := LoadLockKeeperConfig()
	if err != nil {
		return "", err
	}

	loginData := url.Values{
		"username":   {lockKeeperConfig.Username},
		"password":   {lockKeeperConfig.Password},
		"grant_type": {"password"},
	}

	res, postErr := http.PostForm(
		fmt.Sprintf("%s/%s/login", lockKeeperConfig.URL, lockKeeperConfig.Tenant),
		loginData,
	)
	if postErr != nil {
		return "", postErr
	}
	defer res.Body.Close()

	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		return "", readErr
	}

	var result map[string]interface{}
	if deserializeErr := json.Unmarshal(body, &result); deserializeErr != nil {
		return "", deserializeErr
	}

	accessToken := result["access_token"].(string)
	return accessToken, nil
}

func SignTypedMessage(message apitypes.TypedData, keyId string, accessToken string) (string, error) {
	if keyId == "" {
		return "", fmt.Errorf("lock keeper key-id is required")
	}

	lockKeeperConfig, err := LoadLockKeeperConfig()
	if err != nil {
		return "", err
	}

	jsonBytes, serializeErr := SerializeTypedDataWithoutSalt(message)
	if serializeErr != nil {
		return "", serializeErr
	}
	typedData := base64.StdEncoding.EncodeToString(jsonBytes)

	reqBody := map[string]interface{}{
		"typed_data":       typedData,
		"authorizing_data": []interface{}{},
		"key_id":           keyId,
		"message_type":     "Standard",
		"policies":         []string{lockKeeperConfig.Policy},
	}

	reqBodyJson, serializeErr := json.Marshal(reqBody)
	if serializeErr != nil {
		return "", serializeErr
	}

	req, reqErr := http.NewRequest("POST", lockKeeperConfig.URL+"/sign_message", bytes.NewBuffer(reqBodyJson))
	if reqErr != nil {
		return "", reqErr
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, postErr := client.Do(req)
	if postErr != nil {
		return "", postErr
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", readErr
	}

	var result map[string]interface{}
	if deserializeErr := json.Unmarshal(body, &result); deserializeErr != nil {
		return "", deserializeErr
	}

	signature := result["signature"].(string)
	return signature, nil
}

func SignTypedMessageWithApproval(message apitypes.TypedData, keyId string, accessToken string, key *keystore.Key) (string, error) {
	if keyId == "" {
		return "", fmt.Errorf("lock keeper key-id is required")
	}

	lockKeeperConfig, err := LoadLockKeeperConfig()
	if err != nil {
		return "", err
	}

	jsonBytes, serializeErr := SerializeTypedDataWithoutSalt(message)
	if serializeErr != nil {
		return "", serializeErr
	}
	typedData := base64.StdEncoding.EncodeToString(jsonBytes)

	// Get the authorizing data for the typed message
	authData, err := GetAuthDataForTypedData(message, key)
	if err != nil {
		return "", err
	}

	reqBody := map[string]interface{}{
		"typed_data":       typedData,
		"authorizing_data": []interface{}{authData},
		"key_id":           keyId,
		"message_type":     "Standard",
		"policies":         []string{lockKeeperConfig.ApproverPolicy},
	}

	reqBodyJson, serializeErr := json.Marshal(reqBody)
	if serializeErr != nil {
		return "", serializeErr
	}

	req, reqErr := http.NewRequest("POST", lockKeeperConfig.URL+"/sign_message", bytes.NewBuffer(reqBodyJson))
	if reqErr != nil {
		return "", reqErr
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, postErr := client.Do(req)
	if postErr != nil {
		return "", postErr
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", readErr
	}
	os.Stdout.Write(body)

	var result map[string]interface{}
	if deserializeErr := json.Unmarshal(body, &result); deserializeErr != nil {
		return "", deserializeErr
	}

	signature := result["signature"].(string)
	return signature, nil
}

type ECDSASignature struct {
	R, S *big.Int
}

// SignRawMessage is assumed to return raw r || s concatenation
func SignRawMessageWithDerSignature(hash []byte, key *keystore.Key, _ bool) ([]byte, error) {
	// ECDSA signing logic here
	privKey := key.PrivateKey
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return nil, err
	}

	// Create an ECDSASignature object and DER-encode it using ASN.1
	signature := ECDSASignature{R: r, S: s}
	derEncodedSignature, err := asn1.Marshal(signature)
	if err != nil {
		return nil, err
	}

	return derEncodedSignature, nil
}

func GetAuthDataForTypedData(typedData apitypes.TypedData, key *keystore.Key) (map[string]interface{}, error) {

	lockKeeperConfig, err := LoadLockKeeperConfig()
	if err != nil {
		return nil, err
	}

	// first encode the typed data into a 712 hash
	hash, err := EncodeEIP712TypedData(typedData)
	if err != nil {
		return nil, err
	}

	// create the metadata object
	metadata := map[string]interface{}{
		"order_id":        "1",
		"content_hash":    common.Bytes2Hex(hash),
		"approval_status": "1",
		"status_reason":   "Approved",
	}

	// encode the metadata into base64
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	metadataBase64 := base64.StdEncoding.EncodeToString(metadataBytes)
	metadataHash := keccak256(metadataBytes)

	// sign the metadata with the keystore key
	signature, err := SignRawMessageWithDerSignature(metadataHash, key, false)
	if err != nil {
		return nil, err
	}

	// create the authorizing data object
	authData := map[string]interface{}{
		"authorizing_entity": lockKeeperConfig.AuthEntity,
		"level":              "Tenant",
		"metadata":           metadataBase64,
		"metadata_signature": base64.StdEncoding.EncodeToString(signature),
	}

	// return the authorizing data
	return authData, nil
}

// In order to sign the typed message with LockKeeper, we need to serialize
// the typed data message without the salt field in the 'domain' object.
// so we need to create a custom typed data struct to serialize the typed data
type CustomDomain struct {
	Name              string                `json:"name,omitempty"`
	Version           string                `json:"version,omitempty"`
	ChainId           *math.HexOrDecimal256 `json:"chainId,omitempty"`
	VerifyingContract string                `json:"verifyingContract,omitempty"`
}

type CustomTypedData struct {
	Types       map[string][]apitypes.Type `json:"types"`
	PrimaryType string                     `json:"primaryType"`
	Domain      CustomDomain               `json:"domain"`
	Message     map[string]interface{}     `json:"message"`
}

func SerializeTypedDataWithoutSalt(original apitypes.TypedData) ([]byte, error) {
	customDomain := CustomDomain{
		Name:              original.Domain.Name,
		Version:           original.Domain.Version,
		ChainId:           original.Domain.ChainId,
		VerifyingContract: original.Domain.VerifyingContract,
	}

	customTypedData := CustomTypedData{
		Types:       original.Types,
		PrimaryType: original.PrimaryType,
		Domain:      customDomain,
		Message:     original.Message,
	}

	return json.Marshal(customTypedData)
}

// Keccak256 hashing function
func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// Encode and hash the domain
func hashDomain(domain CustomDomain) ([]byte, error) {
	// Create ABI types dynamically
	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		return nil, err
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
	}
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, err
	}

	// ABI Arguments for domain struct
	arguments := abi.Arguments{
		{Type: stringType},  // Name
		{Type: stringType},  // Version
		{Type: uint256Type}, // ChainId
		{Type: addressType}, // VerifyingContract
	}

	// Pack the domain fields
	encoded, err := arguments.Pack(
		domain.Name,
		domain.Version,
		(*big.Int)(domain.ChainId),
		common.HexToAddress(domain.VerifyingContract),
	)
	if err != nil {
		return nil, err
	}

	// Hash the packed result
	return keccak256(encoded), nil
}

// Hash the ClaimPayload message fields
func hashMessage(claimPayload map[string]interface{}) ([]byte, error) {
	// Define the ABI argument types for the ClaimPayload
	arguments := abi.Arguments{}

	// Create types for each expected field and append them to the arguments slice
	for _, field := range []struct {
		Name string
		Type string
	}{
		{"dropId", "uint256"},
		{"requestID", "uint256"},
		{"claimant", "address"},
		{"blockDeadline", "uint256"},
		{"amount", "uint256"},
	} {
		// Create the type and check for errors
		typ, err := abi.NewType(field.Type, "", nil)
		if err != nil {
			return nil, err // Return if there was an error creating the type
		}

		// Append the argument with the field name and type
		arguments = append(arguments, abi.Argument{Name: field.Name, Type: typ})
	}

	// Prepare the values for packing
	values := make([]interface{}, 0, len(arguments))

	// Extract and convert the fields from the claimPayload
	for _, arg := range arguments {
		switch arg.Type.String() {
		case "uint256":
			// For uint256, we expect a string that can be converted to big.Int
			if value, ok := claimPayload[arg.Name].(string); ok {
				bigIntValue := new(big.Int)
				if _, success := bigIntValue.SetString(value, 10); success {
					values = append(values, bigIntValue)
				} else {
					return nil, fmt.Errorf("invalid uint256 value for %s: %s", arg.Name, value)
				}
			} else {
				return nil, fmt.Errorf("expected uint256 for %s but got %T", arg.Name, claimPayload[arg.Name])
			}

		case "address":
			// For address, expect a string representation
			if value, ok := claimPayload[arg.Name].(string); ok {
				address := common.HexToAddress(value)
				values = append(values, address)
			} else {
				return nil, fmt.Errorf("expected address for %s but got %T", arg.Name, claimPayload[arg.Name])
			}
		}
	}

	// Pack the message fields into binary format
	encoded, err := arguments.Pack(values...)
	if err != nil {
		return nil, err
	}

	// Hash the packed result
	return keccak256(encoded), nil
}

// Perform full EIP-712 encoding
func EncodeEIP712TypedData(original apitypes.TypedData) ([]byte, error) {
	// First, serialize the domain without the 'salt'
	customDomain := CustomDomain{
		Name:              original.Domain.Name,
		Version:           original.Domain.Version,
		ChainId:           original.Domain.ChainId,
		VerifyingContract: original.Domain.VerifyingContract,
	}

	// Hash the domain
	domainHash, err := hashDomain(customDomain)
	if err != nil {
		return nil, err
	}

	// Hash the message
	messageHash, err := hashMessage(original.Message)
	if err != nil {
		return nil, err
	}

	// Prefix for EIP-712
	prefix := []byte("\x19\x01")

	// Combine everything into the final hash
	finalHash := keccak256(append(append(prefix, domainHash...), messageHash...))

	return finalHash, nil
}

// To facilitate the LockKeeper integration, we need to load the configuration
// from the environment variables
type LockKeeperConfig struct {
	URL            string
	Tenant         string
	Username       string
	Password       string
	Policy         string
	ApproverPolicy string
	AuthEntity     string
}

func LoadLockKeeperConfig() (*LockKeeperConfig, error) {
	godotenv.Load()

	config := &LockKeeperConfig{}
	var err error

	if config.URL, err = getEnv("LOCK_KEEPER_URL"); err != nil {
		return nil, err
	}
	if config.Tenant, err = getEnv("LOCK_KEEPER_TENANT"); err != nil {
		return nil, err
	}
	if config.Username, err = getEnv("LOCK_KEEPER_USERNAME"); err != nil {
		return nil, err
	}
	if config.Password, err = getEnv("LOCK_KEEPER_PASSWORD"); err != nil {
		return nil, err
	}
	if config.Policy, err = getEnv("LOCK_KEEPER_POLICY"); err != nil {
		return nil, err
	}
	if config.ApproverPolicy, err = getEnv("LOCK_KEEPER_APPROVER_POLICY"); err != nil {
		return nil, err
	}
	if config.AuthEntity, err = getEnv("LOCK_KEEPER_AUTH_ENTITY"); err != nil {
		return nil, err
	}

	return config, nil
}

func getEnv(key string) (string, error) {
	value, exists := os.LookupEnv(key)
	if !exists {
		return "", fmt.Errorf("missing enviroment variable: %s", key)
	}
	return value, nil
}
