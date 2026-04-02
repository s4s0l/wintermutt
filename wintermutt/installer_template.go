package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"
)

//go:embed templates/cli_install.sh.tmpl
var cliInstallScriptTemplate string

type cliInstallScriptData struct {
	VaultAddress    string
	CommonPrefix    string
	AllowedKeysPath string
	ExternalHost    string
	ExternalPort    string
}

func renderCLIInstallScript(cfg *Config) (string, error) {
	tpl, err := template.New("cli_install").Option("missingkey=error").Parse(cliInstallScriptTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse cli-install template: %w", err)
	}

	data := cliInstallScriptData{
		VaultAddress:    cfg.VaultAddress,
		CommonPrefix:    cfg.CommonPrefix,
		AllowedKeysPath: cfg.AllowedKeysPath,
		ExternalHost:    cfg.ExternalHost,
		ExternalPort:    cfg.ExternalPort,
	}

	var out bytes.Buffer
	if err := tpl.Execute(&out, data); err != nil {
		return "", fmt.Errorf("failed to render cli-install template: %w", err)
	}

	return out.String(), nil
}
