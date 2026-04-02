package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type Client struct {
	client      *api.Client
	renewCancel context.CancelFunc
	renewDone   chan struct{}
	closeOnce   sync.Once
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

	vaultClient := &Client{client: client}
	vaultClient.startAppRoleRenewal(roleID, secretIDStr, authInfo)

	return vaultClient, nil
}

func NewClientWithTokenFile(vaultAddr, tokenFile string) (*Client, error) {
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file %s: %w", tokenFile, err)
	}

	tokenStr := strings.TrimSpace(string(tokenBytes))

	config := api.DefaultConfig()
	config.Address = vaultAddr

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(tokenStr)

	_, err = client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return &Client{client: client}, nil
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		if c.renewCancel != nil {
			c.renewCancel()
		}
		if c.renewDone != nil {
			select {
			case <-c.renewDone:
			case <-time.After(2 * time.Second):
				logger.Warn("Timed out waiting for Vault renewal goroutine to stop")
			}
		}
	})
}

func (c *Client) startAppRoleRenewal(roleID, secretID string, initialSecret *api.Secret) {
	ctx, cancel := context.WithCancel(context.Background())
	c.renewCancel = cancel
	c.renewDone = make(chan struct{})

	go func() {
		defer close(c.renewDone)
		secret := initialSecret

		for {
			logger.Info("Setting up Vault token lifetime watcher")
			watcher, err := c.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{Secret: secret})
			if err != nil {
				logger.Error("Failed to create Vault token lifetime watcher", "error", err)
			} else {
				logger.Info("Starting the reneval watch")
				go watcher.Start()
				needsRelogin := false
				for {
					select {
					case <-ctx.Done():
						logger.Info("Renewal received context stopped")
						watcher.Stop()
						return
					case <-watcher.RenewCh():
						logger.Info("Vault token renewed successfully")
						continue
					case err, ok := <-watcher.DoneCh():
						if ok && err != nil {
							logger.Warn("Vault token watcher ended", "error", err)
						} else {
							logger.Warn("Vault token watcher ended; re-login required")
						}
						watcher.Stop()
						needsRelogin = true
					}

					if needsRelogin {
						break
					}
				}
			}

			// Vault docs advise re-reading the secret when watcher finishes.
			// For AppRole auth this means performing a fresh login.
			for {
				if ctx.Err() != nil {
					return
				}
				logger.Info("Attempting to re-login to Vault with AppRole")
				newSecret, err := loginWithAppRole(ctx, c.client, roleID, secretID)
				if err == nil {
					secret = newSecret
					break
				}

				logger.Error("Failed to re-login to Vault with AppRole", "error", err)
				if !sleepWithContext(ctx, 2*time.Second) {
					return
				}
			}
		}
	}()
}

func loginWithAppRole(ctx context.Context, client *api.Client, roleID, secretID string) (*api.Secret, error) {
	appRoleAuth, err := approle.NewAppRoleAuth(
		roleID,
		&approle.SecretID{FromString: secretID},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AppRole auth: %w", err)
	}

	authInfo, err := client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to login to Vault with AppRole: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info returned from Vault login")
	}

	return authInfo, nil
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
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

func (c *Client) SetSecret(path, name, value string) error {
	data := map[string]interface{}{
		"value": value,
	}
	_, err := c.client.Logical().Write(path+"/"+name, map[string]interface{}{
		"data": data,
	})
	return err
}

func (c *Client) DeleteSecret(path, name string) error {
	_, err := c.client.Logical().Delete(path + "/" + name)
	return err
}

func (c *Client) UpdateAllowedKeys(path, publicKey string, add bool) error {
	data, err := c.GetRawSecret(path)
	if err != nil && !strings.Contains(err.Error(), "no such secret") {
		return err
	}

	var keys []string
	if data != nil {
		if keysStr, ok := data["keys"].(string); ok {
			json.Unmarshal([]byte(keysStr), &keys)
		}
	}

	if add {
		keys = append(keys, publicKey)
	} else {
		for i, k := range keys {
			if k == publicKey {
				keys = append(keys[:i], keys[i+1:]...)
				break
			}
		}
	}

	keysJSON, _ := json.Marshal(keys)
	_, err = c.client.Logical().Write(path, map[string]interface{}{
		"data": map[string]interface{}{
			"keys": string(keysJSON),
		},
	})
	return err
}
