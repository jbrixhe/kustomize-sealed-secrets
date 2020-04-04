package main_test

import (
	"fmt"
	"testing"

	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/codes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/config"
	"go.mozilla.org/sops/v3/keyservice"
	"go.mozilla.org/sops/v3/version"

	kusttest_test "sigs.k8s.io/kustomize/api/testutils/kusttest"
)

func TestSecretGenerator(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"jbrixhe", "v1", "SecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "a.env", `
ROUTER_PASSWORD=admin
`)
	writeAndEncrypt(th, "b.env", `
DB_PASSWORD=iloveyou
`)

	writeAndEncrypt(th,"longsecret", `
Lorem ipsum dolor sit amet,
consectetur adipiscing elit.
`)

	rm := th.LoadAndRunGenerator(`
apiVersion: jbrixhe/v1
kind: SecretGenerator
metadata:
  name: mySecret
  namespace: whatever
type: sops/Opaque
behavior: merge
envs:
- a.env
- b.env
files:
- obscure=longsecret
literals:
- FRUIT=apple
- VEGETABLE=carrot
`)

	th.AssertActualEqualsExpected(rm, `
apiVersion: v1
data:
  DB_PASSWORD: aWxvdmV5b3U=
  FRUIT: YXBwbGU=
  ROUTER_PASSWORD: YWRtaW4=
  VEGETABLE: Y2Fycm90
  obscure: CkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LApjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQuCg==
kind: Secret
metadata:
  name: mySecret
  namespace: whatever
type: Opaque
`)
}

func writeAndEncrypt(th *kusttest_test.HarnessEnhanced, path, content string) {
	encryptedContent, err := encrypt(path, content)
	if err != nil {
		th.GetT().Fatal(err)
		return
	}
	fmt.Println(string(encryptedContent))
	th.WriteF(path, string(encryptedContent))
}

func encrypt(path, content string) ([]byte, error) {
	format := formats.FormatForPath(path)
	store := common.StoreForFormat(format)

	branches, err := store.LoadPlainFile([]byte(content))
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Error unmarshalling file: %s", err), codes.CouldNotReadInputFile)
	}

	configPath, err := config.FindConfigFile(".")
	if err != nil {
		return nil, err
	}

	conf, err := config.LoadForFile(configPath, path, make(map[string]*string))
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         conf.KeyGroups,
			Version:           version.Version,
			ShamirThreshold:   conf.ShamirThreshold,
		},
		FilePath: path,
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	if len(errs) > 0 {
		return nil, fmt.Errorf("Could not generate data key: %s", errs)
	}

	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	})
	if err != nil {
		return nil, err
	}

	encryptedFile, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}

	return encryptedFile, nil
}
