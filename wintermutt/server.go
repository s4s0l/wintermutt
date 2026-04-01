package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"path"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	cfg   *Config
	vault *Client
	ln    net.Listener
}

func New(cfg *Config, vaultClient *Client) (*Server, error) {
	return &Server{
		cfg:   cfg,
		vault: vaultClient,
	}, nil
}

// _StripIdPubKey strips the id_pub key from the comment
// at the end (if present).
func _StripIdPubKey(k string) (*string, error) {
	fields := strings.Fields(k)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid key format: need at least 2 segments")
	}
	strip := strings.Join(fields[:2], " ")
	return &strip, nil
}

func (s *Server) Start() error {
	sshConfig := &ssh.ServerConfig{}

	privateKey, err := getHostKey(s.cfg.StoragePath)
	if err != nil {
		return fmt.Errorf("failed to get host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	sshConfig.AddHostKey(signer)

	sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if s.cfg.AllowedKeysPath != "" {
			allowedData, err := s.vault.GetRawSecret(s.cfg.AllowedKeysPath)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch allowed keys: %w", err)
			}
			if allowedData == nil {
				return nil, fmt.Errorf("allowed keys path is empty")
			}
			allowedListJson, ok := allowedData["keys"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid format for allowed keys: 'keys' field missing or not a list")
			}
			var allowedList []string
			err = json.Unmarshal([]byte(allowedListJson), &allowedList)
			if err != nil {
				return nil, fmt.Errorf("failed to parse JSON keys: %w", err)
			}
			keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			stripped, err := _StripIdPubKey(keyStr)
			if err != nil {
				return nil, fmt.Errorf("failed to strip id_pub key: %w", err)
			}
			keyStr = *stripped
			fmt.Printf("testing id pub: %s\n", keyStr)
			authorized := false
			for _, a := range allowedList {
				x, err := _StripIdPubKey(a)
				if err != nil {
					fmt.Println(err)
					return nil, fmt.Errorf("failed to strip id_pub key from allowed list")
				}
				if *x == keyStr {
					authorized = true
					break
				}
			}

			if !authorized {
				return nil, fmt.Errorf("public key not authorized")
			}
		}

		fingerprint := ssh.FingerprintSHA256(key)
		// Remove SHA256: prefix to get ASCII string with slashes (e.g., "Hx9G.../...rtytE")
		// Encode the ASCII string (including slashes) as hex to make it path-safe
		// This preserves the entire fingerprint hash string while making it path-safe
		fingerprint = strings.TrimPrefix(fingerprint, "SHA256:")
		fingerprint = hex.EncodeToString([]byte(fingerprint))

		return &ssh.Permissions{
			Extensions: map[string]string{
				"fingerprint": fingerprint,
			},
		}, nil
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.ln = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go s.handleConn(conn, sshConfig)
	}
}

func (s *Server) handleConn(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("SSH handshake error: %v", err)
		return
	}

	go ssh.DiscardRequests(reqs)

	var fingerprint string
	if sshConn.Permissions != nil {
		fingerprint = sshConn.Permissions.Extensions["fingerprint"]
	}

	if fingerprint == "" {
		log.Printf("No fingerprint available")
		sshConn.Close()
		return
	}

	log.Printf("Client connected with fingerprint: %s", fingerprint)

	var wg sync.WaitGroup
	for ch := range chans {
		wg.Add(1)
		go func(newCh ssh.NewChannel) {
			defer wg.Done()
			s.handleChannel(newCh, fingerprint)
		}(ch)
	}

	wg.Wait()
	sshConn.Close()
}

func mergeSecrets(common, shared map[string]string) map[string]string {
	final := make(map[string]string)
	for k, v := range shared {
		final[k] = v
	}
	for k, v := range common {
		final[k] = v
	}
	return final
}

func formatSecrets(secrets map[string]string) string {
	var result string
	for k, v := range secrets {
		// %q will use double quotes and escape any inner quotes/backslashes
		result += fmt.Sprintf("export %s=%q\n", k, v)
	}
	return result
}

func (s *Server) handleChannel(ch ssh.NewChannel, fingerprint string) {
	if ch.ChannelType() != "session" {
		ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	conn, reqs, err := ch.Accept()
	if err != nil {
		log.Printf("Failed to accept channel: %v", err)
		return
	}

	hasPty := false
	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell":
				req.Reply(true, nil)
			case "pty-req":
				hasPty = true
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Fetch secrets from Vault
	commonPath := path.Join(s.cfg.CommonPrefix, fingerprint)
	commonSecrets, err := s.vault.GetSecrets(commonPath)
	if err != nil {
		log.Printf("Failed to fetch common secrets for %s: %v", fingerprint, err)
		fmt.Fprintf(conn, "Error fetching secrets\n")
		conn.Close()
		return
	}

	sharedPath := s.cfg.SharedPath
	if overridenSharedPath, ok := commonSecrets["WINTERMUTT_SHARED_PATH"]; ok && overridenSharedPath != "" {
		sharedPath = overridenSharedPath
	}

	var sharedSecrets map[string]string
	if sharedPath != "" {
		var err error
		sharedSecrets, err = s.vault.GetSecrets(sharedPath)
		if err != nil {
			log.Printf("Failed to fetch shared secrets from %s: %v", sharedPath, err)
		}
	}

	finalSecrets := mergeSecrets(commonSecrets, sharedSecrets)
	output := formatSecrets(finalSecrets)
	if hasPty {
		output = strings.ReplaceAll(output, "\n", "\r\n")
	}
	fmt.Fprint(conn, output)

	// Send exit status 0
	_, _ = conn.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))

	conn.Close()
}

func (s *Server) Stop() {
	if s.ln != nil {
		s.ln.Close()
	}
}
