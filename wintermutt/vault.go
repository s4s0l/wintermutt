package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type Client struct {
	client *api.Client
}

func NewClient(vaultAddr, roleID, secretIDFile string) (*Client, error) {
	config := api.DefaultConfig()
	config.Address = vaultAddr

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	secretID, err := os.ReadFile(secretIDFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret-id-file: %w", err)
	}

	secretIDStr := strings.TrimSpace(string(secretID))

	appRoleAuth, err := approle.NewAppRoleAuth(
		roleID,
		&approle.SecretID{FromString: secretIDStr},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AppRole auth: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to login to Vault with AppRole: %w", err)
	}

	if authInfo == nil {
		return nil, fmt.Errorf("no auth info returned from Vault login")
	}

	return &Client{client: client}, nil
}

func (c *Client) GetRawSecret(fullPath string) (map[string]interface{}, error) {
	dataSecret, err := c.client.Logical().Read(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret at %s: %w", fullPath, err)
	}

	if dataSecret == nil || dataSecret.Data == nil {
		return nil, nil
	}

	// In KV v2, the data is under "data" key
	if d, exists := dataSecret.Data["data"]; exists {
		if m, ok := d.(map[string]interface{}); ok {
			return m, nil
		}
	}
	return dataSecret.Data, nil
}

func (c *Client) GetSecrets(basePath string) (map[string]string, error) {
	secrets := make(map[string]string)

	// In KV v2, listing is done under /metadata/ and reading under /data/
	// Let's assume KV v2 and common_prefix/fingerprint/* structure
	// README says "lists secrets under common_prefix/fingerprint/*"

	// First, list keys under the path
	listPath := strings.Replace(basePath, "secrets/data/", "secrets/metadata/", 1)
	secret, err := c.client.Logical().List(listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets at %s: %w", listPath, err)
	}

	if secret == nil || secret.Data == nil {
		return secrets, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return secrets, nil
	}

	for _, k := range keys {
		keyName, ok := k.(string)
		if !ok {
			continue
		}

		fullPath := path.Join(basePath, keyName)
		dataSecret, err := c.client.Logical().Read(fullPath)
		if err != nil {
			continue // Log this?
		}

		if dataSecret == nil || dataSecret.Data == nil {
			continue
		}

		// In KV v2, the data is under "data" key
		var data map[string]interface{}
		if d, exists := dataSecret.Data["data"]; exists {
			if m, ok := d.(map[string]interface{}); ok {
				data = m
			}
		} else {
			// Fallback to V1 style
			data = dataSecret.Data
		}

		if val, ok := data["value"].(string); ok {
			secrets[keyName] = val
		}
	}

	return secrets, nil
}
