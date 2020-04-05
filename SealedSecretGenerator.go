package main

import (
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/decrypt"
	"sigs.k8s.io/kustomize/api/ifc"
	"sigs.k8s.io/kustomize/api/kv"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/yaml"
	"strings"
)

type plugin struct {
	h                *resmap.PluginHelpers
	types.ObjectMeta `json:"metadata,omitempty" yaml:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	types.GeneratorOptions
	types.SecretArgs
}

//noinspection GoUnusedGlobalVariable
var KustomizePlugin plugin

func (p *plugin) Config(h *resmap.PluginHelpers, config []byte) (err error) {
	p.GeneratorOptions = types.GeneratorOptions{}
	p.SecretArgs = types.SecretArgs{}
	err = yaml.Unmarshal(config, p)
	if p.SecretArgs.Name == "" {
		p.SecretArgs.Name = p.Name
	}
	if p.SecretArgs.Namespace == "" {
		p.SecretArgs.Namespace = p.Namespace
	}
	p.h = h
	return
}

func (p *plugin) Generate() (resmap.ResMap, error) {
	switch strings.ToLower(p.SecretArgs.Type) {
	case "sealed":
		return p.h.ResmapFactory().FromSecretArgs(
			kv.NewLoader(NewSopsLoader(p.h.Loader()), p.h.Validator()),
			&p.GeneratorOptions, types.SecretArgs{
				GeneratorArgs: p.SecretArgs.GeneratorArgs,
			})
	case "sealed/tls":
		return p.h.ResmapFactory().FromSecretArgs(
			kv.NewLoader(NewSopsLoader(p.h.Loader()), p.h.Validator()),
			&p.GeneratorOptions, types.SecretArgs{
				GeneratorArgs: p.SecretArgs.GeneratorArgs,
				Type:          "kubernetes.io/tls",
			})
	default:
		return p.h.ResmapFactory().FromSecretArgs(
			kv.NewLoader(p.h.Loader(), p.h.Validator()),
			&p.GeneratorOptions, p.SecretArgs)
	}
}

type SopsLoader struct {
	proxy ifc.Loader
}

func NewSopsLoader(proxy ifc.Loader) *SopsLoader {
	return &SopsLoader{proxy: proxy}
}

func (sl *SopsLoader) Root() string {
	return sl.proxy.Root()
}

// New returns Loader located at newRoot.
func (sl *SopsLoader) New(newRoot string) (ifc.Loader, error) {
	p, err := sl.proxy.New(newRoot)
	if err != nil {
		return &SopsLoader{}, err
	}
	return NewSopsLoader(p), nil
}

// Load returns the bytes read from the location or an error.
func (sl *SopsLoader) Load(location string) ([]byte, error) {
	bytes, err := sl.proxy.Load(location)
	if err != nil {
		return nil, err
	}

	return decrypt.DataWithFormat(bytes, formats.FormatForPath(location))
}

// Cleanup cleans the loader
func (sl *SopsLoader) Cleanup() error {
	return sl.proxy.Cleanup()
}
