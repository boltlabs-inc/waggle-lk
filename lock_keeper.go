package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func Login() (string, error) {
	//TODO: Move these to environment variables
	lockKeeperURL := "http://localhost:3000"
	tenantName := "Game7"

	//TODO: Move these to environment variables
	loginData := url.Values{
		"username":   {"game7_service_provider"},
		"password":   {"password"},
		"grant_type": {"password"},
	}

	res, err := http.PostForm(
		fmt.Sprintf("%s/%s/login", lockKeeperURL, tenantName),
		loginData,
	)
	if err != nil {
		os.Stdout.Write([]byte("Error making login request: " + err.Error() + "\n"))
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		os.Stdout.Write([]byte("Error reading login response body: " + err.Error() + "\n"))
		return "", err
	}

	// Parse the JSON response to get the access token
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		os.Stdout.Write([]byte("Error decoding login JSON response: " + err.Error() + "\n"))
		return "", err
	}

	accessToken := result["access_token"].(string)

	return accessToken, nil
}

func SignTypedMessage(message apitypes.TypedData, keyId string, accessToken string) (string, error) {
	lockKeeperURL := "http://localhost:3000" // replace with actual URL

	// Encode message to JSON
	jsonBytes, err := json.Marshal(message)
	if err != nil {
		os.Stdout.Write([]byte("Error encoding message to JSON: " + err.Error() + "\n"))
		return "", err
	}

	os.Stdout.Write(jsonBytes)

	// Encode JSON to base64
	typedData := base64.StdEncoding.EncodeToString(jsonBytes)

	os.Stdout.Write([]byte(typedData))

	// Prepare request body
	reqBody := map[string]interface{}{
		"typed_data":       typedData,
		"authorizing_data": []interface{}{},
		"key_id":           keyId,
		"message_type":     "Erc2771",
		"policies":         []string{"noop_policy"},
	}

	// Encode request body to JSON
	reqBodyJson, err := json.Marshal(reqBody)
	if err != nil {
		os.Stdout.Write([]byte("Error encoding request body to JSON: " + err.Error() + "\n"))
		return "", err
	}

	// Make the POST request
	req, err := http.NewRequest("POST", lockKeeperURL+"/sign_message", bytes.NewBuffer(reqBodyJson))
	if err != nil {
		os.Stdout.Write([]byte("Error creating POST request: " + err.Error() + "\n"))
		return "", err
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		os.Stdout.Write([]byte("Error making POST request: " + err.Error() + "\n"))
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		os.Stdout.Write([]byte("Error reading response body: " + err.Error() + "\n"))
		return "", err
	}

	// Print the body text
	os.Stdout.Write(body)

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		os.Stdout.Write([]byte("Error decoding JSON response: " + err.Error() + "\n"))
		return "", err
	}

	// Extract the signature from the response
	signature := result["signature"].(string)

	return signature, nil
}
