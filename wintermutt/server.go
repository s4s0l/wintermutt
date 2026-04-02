package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
		// Remove SHA256: prefix to get base64-encoded bytes (e.g., "Hx9G.../...rtytE")
		// Decode the base64 bytes, then encode as hex for path-safe fingerprint
		fingerprint = strings.TrimPrefix(fingerprint, "SHA256:")
		decoded, err := base64.RawStdEncoding.DecodeString(fingerprint)
		if err != nil {
			return nil, fmt.Errorf("failed to decode fingerprint base64: %w", err)
		}
		fingerprint = hex.EncodeToString(decoded)

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
			logger.Error("Accept error", "error", err)
			continue
		}

		go s.handleConn(conn, sshConfig)
	}
}

func (s *Server) handleConn(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		logger.Error("SSH handshake error", "error", err)
		return
	}

	go ssh.DiscardRequests(reqs)

	var fingerprint string
	if sshConn.Permissions != nil {
		fingerprint = sshConn.Permissions.Extensions["fingerprint"]
	}

	if fingerprint == "" {
		logger.Error("No fingerprint available")
		sshConn.Close()
		return
	}

	logger.Info("Client connected", "fingerprint", fingerprint)

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
		logger.Error("Failed to accept channel", "error", err)
		return
	}

	hasPty := false
	requestType := ""
	execCommand := ""

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			hasPty = true
			req.Reply(true, nil)
		case "shell":
			requestType = "shell"
			req.Reply(true, nil)
			goto handleRequest
		case "exec":
			cmd, err := parseExecCommand(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				fmt.Fprintln(conn.Stderr(), "invalid exec payload")
				sendExitStatus(conn, 1)
				conn.Close()
				return
			}

			execCommand = strings.TrimSpace(cmd)
			if execCommand == "" {
				req.Reply(false, nil)
				fmt.Fprintln(conn.Stderr(), "empty exec command")
				sendExitStatus(conn, 1)
				conn.Close()
				return
			}

			requestType = "exec"
			req.Reply(true, nil)
			goto handleRequest
		default:
			req.Reply(false, nil)
		}
	}

	fmt.Fprintln(conn.Stderr(), "no shell or exec request received")
	sendExitStatus(conn, 1)
	conn.Close()
	return

handleRequest:
	if requestType == "exec" {
		err := s.handleExec(conn, execCommand)
		if err != nil {
			logger.Error("Exec command failed", "command", execCommand, "error", err)
			fmt.Fprintln(conn.Stderr(), err.Error())
			sendExitStatus(conn, 1)
		} else {
			sendExitStatus(conn, 0)
		}
		conn.Close()
		return
	}

	// Fetch secrets from Vault
	commonPath := path.Join(s.cfg.CommonPrefix, fingerprint)
	commonSecrets, err := s.vault.GetSecrets(commonPath)
	if err != nil {
		logger.Error("Failed to fetch common secrets", "fingerprint", fingerprint, "error", err)
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
			logger.Error("Failed to fetch shared secrets", "path", sharedPath, "error", err)
		}
	}

	finalSecrets := mergeSecrets(commonSecrets, sharedSecrets)
	output := formatSecrets(finalSecrets)
	if hasPty {
		output = strings.ReplaceAll(output, "\n", "\r\n")
	}
	fmt.Fprint(conn, output)

	sendExitStatus(conn, 0)

	conn.Close()
}

func parseExecCommand(payload []byte) (string, error) {
	var req struct {
		Command string
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return "", fmt.Errorf("failed to decode exec payload: %w", err)
	}
	return req.Command, nil
}

func (s *Server) handleExec(ch ssh.Channel, command string) error {
	switch command {
	case "get-binary":
		if !s.cfg.EnableBinaryDownload {
			return fmt.Errorf("binary download is disabled; enable with -enable-binary-download")
		}

		executablePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve running binary path: %w", err)
		}

		file, err := os.Open(executablePath)
		if err != nil {
			return fmt.Errorf("failed to open running binary: %w", err)
		}
		defer file.Close()

		if _, err := io.Copy(ch, file); err != nil {
			return fmt.Errorf("failed to stream binary: %w", err)
		}

		return nil

	case "cli-install":
		if !s.cfg.EnableBinaryDownload {
			return fmt.Errorf("binary download is disabled; enable with -enable-binary-download")
		}

		script, err := renderCLIInstallScript(s.cfg)
		if err != nil {
			return err
		}

		if _, err := io.WriteString(ch, script); err != nil {
			return fmt.Errorf("failed to stream installer script: %w", err)
		}

		return nil

	default:
		return fmt.Errorf("unsupported command: %s", command)
	}
}

func sendExitStatus(ch ssh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

func (s *Server) Stop() {
	if s.ln != nil {
		s.ln.Close()
	}
}
