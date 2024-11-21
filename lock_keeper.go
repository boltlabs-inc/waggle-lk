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

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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
	authData, err := GetAuthorizingData(message, key, lockKeeperConfig)
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

	var result map[string]interface{}
	if deserializeErr := json.Unmarshal(body, &result); deserializeErr != nil {
		return "", deserializeErr
	}

	signature := result["signature"].(string)
	return signature, nil
}

func GetAuthorizingData(typedData apitypes.TypedData, key *keystore.Key, lockKeeperConfig *LockKeeperConfig) (map[string]interface{}, error) {
	// the metadata object that will be signed needs the EIP-712 message hash
	// of the typed data that will be signed
	contentHashBytes, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, err
	}
	// The contentHash bytes object needs to be represented as an array of integers
	// so it can be JSON serialized appropriately
	contentHashInt := ByteSliceToIntArray(contentHashBytes)

	// create the metadata object, serialize it to JSON, and base64 encode it
	metadata := map[string]interface{}{
		"order_id":        "1",
		"content_hash":    contentHashInt,
		"approval_status": 1,
		"status_reason":   "Approved",
	}
	jsonData, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata to JSON: %v", err)
	}
	base64Metadata := base64.StdEncoding.EncodeToString(jsonData)

	// In order to pre-approve the signing operation, we need to sign the metadata
	// using the approver's key and then send the signature to LockKeeper
	signature, err := SignMetadata([]byte(base64Metadata), key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign metadata: %v", err)
	}

	// create the authorizing data object and return it to be included in the request
	authData := map[string]interface{}{
		"authorizing_entity": lockKeeperConfig.AuthEntity,
		"level":              "Domain",
		"metadata":           base64Metadata,
		"metadata_signature": signature,
	}
	return authData, nil
}

type ECDSASignature struct {
	R, S *big.Int
}

func SignMetadata(base64Metadata []byte, key *keystore.Key) (string, error) {
	// Keccak-256 hash the base64 metadata
	hashedMetadata := sha3.NewLegacyKeccak256()
	hashedMetadata.Write(base64Metadata)
	metadataHash := hashedMetadata.Sum(nil)

	// Gets the private key and use that to sign the pre-approval
	privateKey := key.PrivateKey
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, metadataHash)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return "", err
	}

	// Canonicalize the signature by ensuring s is in the lower half of the curve order
	curveOrder := secp256k1.S256().Params().N
	if s.Cmp(new(big.Int).Rsh(curveOrder, 1)) > 0 {
		s.Sub(curveOrder, s)
	}

	// Before returning the signature, we need to encode it to DER format, and then base64 encode it
	signature := ECDSASignature{R: r, S: s}
	derEncodedSig, err := asn1.Marshal(signature)
	if err != nil {
		fmt.Println("Error encoding signature to DER:", err)
		return "", err
	}
	base64Sig := base64.StdEncoding.EncodeToString(derEncodedSig)

	return base64Sig, nil
}

func ByteSliceToIntArray(byteSlice []byte) []int {
	intArray := make([]int, len(byteSlice))
	for i, b := range byteSlice {
		intArray[i] = int(b)
	}
	return intArray
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

	env_vars := []string{
		"LOCK_KEEPER_URL",
		"LOCK_KEEPER_TENANT",
		"LOCK_KEEPER_USERNAME",
		"LOCK_KEEPER_PASSWORD",
		"LOCK_KEEPER_POLICY",
		"LOCK_KEEPER_APPROVER_POLICY",
		"LOCK_KEEPER_AUTH_ENTITY",
	}
	missing_vars := []string{}

	for _, env_var := range env_vars {
		if _, exists := os.LookupEnv(env_var); !exists {
			missing_vars = append(missing_vars, env_var)
		}
	}

	if len(missing_vars) > 0 {
		return nil, fmt.Errorf("missing environment variables: %v", missing_vars)
	}

	config := &LockKeeperConfig{}
	config.URL, _ = os.LookupEnv("LOCK_KEEPER_URL")
	config.Tenant, _ = os.LookupEnv("LOCK_KEEPER_TENANT")
	config.Username, _ = os.LookupEnv("LOCK_KEEPER_USERNAME")
	config.Password, _ = os.LookupEnv("LOCK_KEEPER_PASSWORD")
	config.Policy, _ = os.LookupEnv("LOCK_KEEPER_POLICY")
	config.ApproverPolicy, _ = os.LookupEnv("LOCK_KEEPER_APPROVER_POLICY")
	config.AuthEntity, _ = os.LookupEnv("LOCK_KEEPER_AUTH_ENTITY")

	return config, nil
}
