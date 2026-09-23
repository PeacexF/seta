package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

const schemaPath = "../../schema/config.v1.json"

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(SchemaURL, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(SchemaURL)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// asJSON converts YAML the way editors do for schema validation: unquoted
// dates stay strings.
func asJSON(t *testing.T, n *yaml.Node) any {
	t.Helper()
	switch n.Kind {
	case yaml.DocumentNode:
		return asJSON(t, n.Content[0])
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			m[n.Content[i].Value] = asJSON(t, n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		var s []any
		for _, c := range n.Content {
			s = append(s, asJSON(t, c))
		}
		return s
	}
	switch n.ShortTag() {
	case "!!int", "!!float":
		return json.Number(n.Value)
	case "!!bool":
		b, err := strconv.ParseBool(n.Value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	case "!!null":
		return nil
	}
	return n.Value
}

func TestSchemaAcceptsValidConfigs(t *testing.T) {
	s := compileSchema(t)
	data, err := os.ReadFile(filepath.Join("testdata", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(asJSON(t, &n)); err != nil {
		t.Errorf("full.yaml: %v", err)
	}
}

func TestSchemaRejects(t *testing.T) {
	s := compileSchema(t)
	for _, src := range []string{
		"targets: [{domain: a.com}]",
		"version: 2\ntargets: [{domain: a.com}]",
		"version: 1\ntargets: []",
		"version: 1\ntargets: [{domain: a.com, chekcs: []}]",
		"version: 1\ntargets: [{domain: a.com}]\ndefaults: {check_timeout: 10}",
		"version: 1\ntargets: [{domain: a.com}]\nseverity_overrides: {email.spf.missing: severe}",
		"version: 1\ntargets: [{domain: a.com}]\nsuppressions: [{check: email.spf.missing}]",
		"version: 1\ntargets: [{domain: a.com}]\nplugins_dir: x",
		"version: 1\ntargets: [{domain: a.com}]\nnotify: [{type: telegram, chat_id: 1}]",
		"version: 1\ntargets: [{domain: a.com}]\nnotify: [{type: slack}]",
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(asJSON(t, &n)); err == nil {
			t.Errorf("schema accepted %q", src)
		}
	}
}

// TestSchemaMatchesStructs keeps the schema's properties and the config
// structs' yaml fields in sync, in both directions.
func TestSchemaMatchesStructs(t *testing.T) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	defs := root["$defs"].(map[string]any)
	resolve := func(s map[string]any) map[string]any {
		if ref, ok := s["$ref"].(string); ok {
			return defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		}
		return s
	}
	var walk func(path string, s map[string]any, typ reflect.Type)
	walk = func(path string, s map[string]any, typ reflect.Type) {
		s = resolve(s)
		switch typ.Kind() {
		case reflect.Pointer:
			walk(path, s, typ.Elem())
		case reflect.Slice:
			if items, ok := s["items"].(map[string]any); ok {
				walk(path+"[]", items, typ.Elem())
			}
		case reflect.Struct:
			if reflect.PointerTo(typ).Implements(unmarshalerType) {
				return
			}
			props, _ := s["properties"].(map[string]any)
			fields := yamlFields(typ)
			var schemaNames, goNames []string
			for name := range props {
				schemaNames = append(schemaNames, name)
			}
			for name := range fields {
				goNames = append(goNames, name)
			}
			slices.Sort(schemaNames)
			slices.Sort(goNames)
			if !slices.Equal(schemaNames, goNames) {
				t.Errorf("%s: schema properties %v, Go fields %v", path, schemaNames, goNames)
			}
			for name, ft := range fields {
				if p, ok := props[name].(map[string]any); ok {
					walk(path+"."+name, p, ft)
				}
			}
		}
	}
	walk("config", root, reflect.TypeFor[Config]())
}
