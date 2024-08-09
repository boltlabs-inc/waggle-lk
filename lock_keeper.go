package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func Login() (string, error) {
	//TODO: Move these to environment variables
	lockKeeperURL := "http://localhost:3000"
	tenantName := "Game7"
	serviceProviderUsername := "game7_service_provider"
	serviceProviderPassword := "password"

	//TODO: Move these to environment variables
	loginData := url.Values{
		"username":   {serviceProviderUsername},
		"password":   {serviceProviderPassword},
		"grant_type": {"password"},
	}

	res, postErr := http.PostForm(
		fmt.Sprintf("%s/%s/login", lockKeeperURL, tenantName),
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
	// TODO: Move this to environment variable
	lockKeeperURL := "http://localhost:3000"
	policyName := "noop_policy"

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
		"policies":         []string{policyName},
	}

	reqBodyJson, serializeErr := json.Marshal(reqBody)
	if serializeErr != nil {
		return "", serializeErr
	}

	req, reqErr := http.NewRequest("POST", lockKeeperURL+"/sign_message", bytes.NewBuffer(reqBodyJson))
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

// In order to sign the typed message with LockKeeper, we need to serialize
// the typed data message without the salt field in the 'domain' object.
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
