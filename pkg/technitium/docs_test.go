package technitium

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// repoRoot is relative to this package's directory, where go test runs.
const repoRoot = "../.."

// notDNSConfig, on the line before a yaml block in a Markdown file, marks a
// block that holds some other YAML, such as a client config file.
const notDNSConfig = "<!-- docs-test: not a DNS config -->"

// TestDocumentedConfigsLoad loads every DNS config the documentation and
// examples show, so that none of them drifts from the schema.
func TestDocumentedConfigsLoad(t *testing.T) {
	var sources []Source
	for _, doc := range []string{"README.md", ".github/DOCKERHUB.md"} {
		sources = append(sources, markdownYAMLBlocks(t, doc)...)
	}
	for _, file := range []string{
		"examples/config.yaml",
		"examples/cluster/primary.yaml",
		"examples/cluster/secondary.yaml",
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot, file))
		require.NoError(t, err)
		sources = append(sources, Source{Name: file, Data: data})
	}
	sources = append(sources, configMapEntry(t, "examples/k8s.yaml", "technitium-config", "config.yaml"))

	for _, src := range sources {
		t.Run(src.Name, func(t *testing.T) {
			_, err := LoadConfig(src)
			assert.NoError(t, err)
		})
	}
}

// markdownYAMLBlocks returns the yaml fenced blocks of a Markdown file, except
// those marked notDNSConfig, each named after the file and the line it starts on.
func markdownYAMLBlocks(t *testing.T, doc string) []Source {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, doc))
	require.NoError(t, err)

	var (
		blocks   []Source
		current  *bytes.Buffer
		indent   string
		start    int
		skip     bool
		previous string
	)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case current == nil && (trimmed == "```yaml" || trimmed == "```yml"):
			current = &bytes.Buffer{}
			indent = line[:len(line)-len(strings.TrimLeft(line, " "))]
			start = n + 1
			skip = previous == notDNSConfig
		case current != nil && trimmed == "```":
			if !skip {
				blocks = append(blocks, Source{Name: fmt.Sprintf("%s (block at line %d)", doc, start), Data: current.Bytes()})
			}
			current = nil
		case current != nil:
			current.WriteString(strings.TrimPrefix(line, indent))
			current.WriteByte('\n')
		}
		if trimmed != "" {
			previous = trimmed
		}
	}
	require.NoError(t, scanner.Err())
	require.Nil(t, current, "%s: unterminated yaml block starting at line %d", doc, start)
	require.NotEmpty(t, blocks, "%s has no yaml blocks", doc)
	return blocks
}

// configMapEntry returns one data entry of a named ConfigMap in a
// multi-document Kubernetes manifest.
func configMapEntry(t *testing.T, file, name, key string) Source {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, file))
	require.NoError(t, err)

	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var object struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Data map[string]string `yaml:"data"`
		}
		err := dec.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if object.Kind == "ConfigMap" && object.Metadata.Name == name {
			entry, ok := object.Data[key]
			require.True(t, ok, "%s: ConfigMap %s has no %s", file, name, key)
			return Source{Name: fmt.Sprintf("%s (ConfigMap %s)", file, name), Data: []byte(entry)}
		}
	}
	require.FailNow(t, "ConfigMap not found", "%s has no ConfigMap %s", file, name)
	return Source{}
}
