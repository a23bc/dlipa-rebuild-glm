package sap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

const supportedVersion = uint32(200)

var errSignerClosed = errors.New("SAP signer is closed")

type Config struct {
	SetupURL       string
	CertificateURL string
	Version        uint32
	HardwareID     []byte
}

type ActionSigner interface {
	Sign(input []byte) ([]byte, error)
	// KBSync produces the ent/download blob on the signer's own machine. It is
	// part of the interface because the caller must reach the same emulator that
	// holds the session; opening a second one does not fit on iOS.
	KBSync(ctx context.Context, dsid uint64) ([]byte, error)
	Close() error
}

func validateConfig(config Config) error {
	if config.Version != supportedVersion {
		return fmt.Errorf("unsupported SAP version %d", config.Version)
	}

	if len(config.HardwareID) == 0 || len(config.HardwareID) > 20 {
		return errors.New("SAP hardware ID must contain between 1 and 20 bytes")
	}

	if err := validateEndpoint("setup", config.SetupURL); err != nil {
		return err
	}

	if err := validateEndpoint("certificate", config.CertificateURL); err != nil {
		return err
	}

	return nil
}

func validateEndpoint(label, value string) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return fmt.Errorf("SAP %s URL must be an absolute HTTPS URL", label)
	}

	return nil
}
