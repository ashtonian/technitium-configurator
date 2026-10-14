package technitium

import (
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseTokenFile returns the API token a token file holds: the YAML document
// create-token writes, or a bare token, as a mounted Kubernetes Secret key or
// a Docker secret holds it. An empty file, or a document without a token,
// holds none and yields "".
func ParseTokenFile(data []byte) (string, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", nil
	}
	// A bare token is a YAML scalar, which does not decode into the struct.
	var rec CreateTokenResponse
	if err := yaml.Unmarshal(data, &rec); err == nil {
		return rec.Token, nil
	}
	if strings.ContainsAny(text, " \t\r\n") {
		return "", errors.New("it is neither a create-token file nor a bare token")
	}
	return text, nil
}
