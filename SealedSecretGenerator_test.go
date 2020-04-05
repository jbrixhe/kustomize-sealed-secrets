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

func TestSealedSecretGenerator(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"sealed.secrets", "v1", "SealedSecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "a.env", `
ROUTER_PASSWORD=admin
`)
	writeAndEncrypt(th, "b.env", `
DB_PASSWORD=iloveyou
`)

	writeAndEncrypt(th, "longsecret", `
Lorem ipsum dolor sit amet,
consectetur adipiscing elit.
`)

	rm := th.LoadAndRunGenerator(`
apiVersion: sealed.secrets/v1
kind: SealedSecretGenerator
metadata:
  name: mySecret
  namespace: whatever
type: Sealed
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

func TestSealedBinarySecrets(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"sealed.secrets", "v1", "SealedSecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "longsecret", `
Lorem ipsum dolor sit amet,
consectetur adipiscing elit.
`)

	rm := th.LoadAndRunGenerator(`
apiVersion: sealed.secrets/v1
kind: SealedSecretGenerator
metadata:
  name: mySecret
  namespace: whatever
type: Sealed
files:
- obscure=longsecret
`)

	th.AssertActualEqualsExpected(rm, `
apiVersion: v1
data:
  obscure: CkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LApjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQuCg==
kind: Secret
metadata:
  name: mySecret
  namespace: whatever
type: Opaque
`)
}

func TestSealedEnvSecret(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"sealed.secrets", "v1", "SealedSecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "a.env", `
ROUTER_PASSWORD=admin
`)
	writeAndEncrypt(th, "b.env", `
DB_PASSWORD=iloveyou
`)

	rm := th.LoadAndRunGenerator(`
apiVersion: sealed.secrets/v1
kind: SealedSecretGenerator
metadata:
  name: mySecret
  namespace: whatever
type: Sealed
envs:
- a.env
- b.env
`)

	th.AssertActualEqualsExpected(rm, `
apiVersion: v1
data:
  DB_PASSWORD: aWxvdmV5b3U=
  ROUTER_PASSWORD: YWRtaW4=
kind: Secret
metadata:
  name: mySecret
  namespace: whatever
type: Opaque
`)
}

func TestSealedJsonFileSecret(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"sealed.secrets", "v1", "SealedSecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "admin-service-account.json", `{"serviceAccount":"admin"}`)
	writeAndEncrypt(th, "router-service-account.json", `{"serviceAccount":"router"}`)

	rm := th.LoadAndRunGenerator(`
apiVersion: sealed.secrets/v1
kind: SealedSecretGenerator
metadata:
  name: mySecret
  namespace: whatever
type: Sealed
files:
- admin-service-account.json
- router-service-account.json
`)

	th.AssertActualEqualsExpected(rm, `
apiVersion: v1
data:
  admin-service-account.json: ewoJInNlcnZpY2VBY2NvdW50IjogImFkbWluIgp9
  router-service-account.json: ewoJInNlcnZpY2VBY2NvdW50IjogInJvdXRlciIKfQ==
kind: Secret
metadata:
  name: mySecret
  namespace: whatever
type: Opaque
`)
}

func TestSealedYmlFileSecret(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"sealed.secrets", "v1", "SealedSecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "admin-service-account.yml", `serviceAccount: admin`)
	writeAndEncrypt(th, "router-service-account.yml", `serviceAccount: router`)

	rm := th.LoadAndRunGenerator(`
apiVersion: sealed.secrets/v1
kind: SealedSecretGenerator
metadata:
  name: mySecret
  namespace: whatever
type: Sealed
files:
- admin-service-account.yml
- router-service-account.yml
`)

	th.AssertActualEqualsExpected(rm, `
apiVersion: v1
data:
  admin-service-account.yml: c2VydmljZUFjY291bnQ6IGFkbWluCg==
  router-service-account.yml: c2VydmljZUFjY291bnQ6IHJvdXRlcgo=
kind: Secret
metadata:
  name: mySecret
  namespace: whatever
type: Opaque
`)
}

func TestSealedTls(t *testing.T) {
	th := kusttest_test.MakeEnhancedHarness(t).BuildGoPlugin(
		"sealed.secrets", "v1", "SealedSecretGenerator")
	defer th.Reset()

	writeAndEncrypt(th, "tls.key", `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

	writeAndEncrypt(th, "tls.crt", `-----BEGIN CERTIFICATE-----
MIIFIjCCAwoCCQC1M98v/fy1ZjANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJG
UjEOMAwGA1UECAwFUGFyaXMxDjAMBgNVBAcMBVBhcmlzMSQwIgYDVQQDDBtLdXN0
b21pemUgU2VhbGVkIGNlcnRpZmljYXQwHhcNMjAwNDA1MTA0NzEyWhcNMjEwNDA1
MTA0NzEyWjBTMQswCQYDVQQGEwJGUjEOMAwGA1UECAwFUGFyaXMxDjAMBgNVBAcM
BVBhcmlzMSQwIgYDVQQDDBtLdXN0b21pemUgU2VhbGVkIGNlcnRpZmljYXQwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDgu7UsOWyBoUC7YdHSZx5NXfIz
2t8r6C/BYqeMGNSsXfbCYzlDGcJeeKX+yRHbNXCXdkeKj3vYapUw1aZ/Ny8N2Ndu
kI7GH0bMswik4vw8AEcwlmxUCv4X+qU6ziCI/gAl7+TSbRrnXP+22H2rBrXM0rWY
JPrPkCCML2jhh6Ae2oEI+VdvpDmGrPkTiH+m6+TskgiA6RsEo5hCH6bxMEb3zoqh
L2/APpwX6DA3Mmo/LEgDAMFIkcwYkfo/BZSPHTSdBa8Aca6oltZPiQ/5UAQxay5m
Lhtn7teMXJ0oBPVecjB+RZBu+n3pJXlvYG+dRna6Q8m+ZE6Gq6bXTw6Orwvn9vun
HpDnztglYCywb3hH3JN6tS6HY2oUMgdyXK8U4EU5Nky1592DQ2TITYTag0eH1VEQ
PkbVs/BQ5etFVgbtL2mCNdmTdQDJG4c4RoOl8CHMm8QTcDhuzIeRYwo9S0ikmqeu
z+0ScKabgCkmtuoD+OUTVDUMhjlB9d6E4Kb7nqI0MuoxHxTKNU+vTru8Sxrmc4oA
Rtwk03eW/md2JxSIR1ZEykwyDu43oy6HKRPDI6JPE2FMaMw5bOz2mZMx3nECT+2k
FQa/s+LtmqnXiVPNpNzxJ3LKEAJ+guwEeNiOLO8Z2N8hfGSzjIVlxcMBIPnMLy1+
y9io71nFudKDgF/FcQIDAQABMA0GCSqGSIb3DQEBBQUAA4ICAQBzpjiDYzpPXTSi
A2KWtdVMpgz6qZnYL8VzqlQeppZ1bP7RblmYPC20UHy1/9RMdrPAX4yaVSR3ZBMl
ospMcRohDKL7FhubOiUaMZHNO2TqCUUxN5sjanle42QCGQUL5fKZ+GXisHn6rvoJ
HHbAowYaNlOoe/jblsiY/4sdnkRB+58deh17wP3QoPiUV2VSi9G61VHqfvNSTr6/
GuqDSnH2G7uRCSndMZbDN2IksykOTPMfdTZb2VZsTlVIoyZTPoyu5Tyothtpagp/
RWv/LQS9UAMzrLmYQuOQmhAjnUmOo5tO/KA0BTQZezg1Rm4EndX1s+K5WPdUkPwC
iHw4tqHbkQNc4o7Xk25G9EZXeGPU6qFXrTMU9m/0aDi3NEkWefJu7O4PPocI43EU
MJcO5w/MAkdV1XoregAnImmLTnW/SkDPe105EqSucD/jNICNiN79sukDGpgxCv7f
z84+ILYehBs85nkvT0oen2AYryOO2VrSmbzzmwzJrmBsVCvHyq0QdFAKCDE9BZkB
kcZTtJlhuD7MM/0bZLVka2sW4SFgf9XHQOmg0W8p8QZyMzvIVtSE/eJXMH+9jYPq
ZB8K9ej9PzC/WCGX3dMgDYYvWnposGoXbShD74OsVnsJQTL5G2lkHfXP12nkavAB
PMEN9s3o1rj+h/Uai7klWDP3WZYMRQ==
-----END CERTIFICATE-----`)

	rm := th.LoadAndRunGenerator(`
apiVersion: sealed.secrets/v1
kind: SealedSecretGenerator
metadata:
  name: mySecret
  namespace: whatever
files:
- tls.crt
- tls.key
type: "Sealed/tls"
`)

	th.AssertActualEqualsExpected(rm, `
apiVersion: v1
data:
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZJakNDQXdvQ0NRQzFNOTh2L2Z5MVpqQU5CZ2txaGtpRzl3MEJBUVVGQURCVE1Rc3dDUVlEVlFRR0V3SkcKVWpFT01Bd0dBMVVFQ0F3RlVHRnlhWE14RGpBTUJnTlZCQWNNQlZCaGNtbHpNU1F3SWdZRFZRUUREQnRMZFhOMApiMjFwZW1VZ1UyVmhiR1ZrSUdObGNuUnBabWxqWVhRd0hoY05NakF3TkRBMU1UQTBOekV5V2hjTk1qRXdOREExCk1UQTBOekV5V2pCVE1Rc3dDUVlEVlFRR0V3SkdVakVPTUF3R0ExVUVDQXdGVUdGeWFYTXhEakFNQmdOVkJBY00KQlZCaGNtbHpNU1F3SWdZRFZRUUREQnRMZFhOMGIyMXBlbVVnVTJWaGJHVmtJR05sY25ScFptbGpZWFF3Z2dJaQpNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUURndTdVc09XeUJvVUM3WWRIU1p4NU5YZkl6CjJ0OHI2Qy9CWXFlTUdOU3NYZmJDWXpsREdjSmVlS1greVJIYk5YQ1hka2VLajN2WWFwVXcxYVovTnk4TjJOZHUKa0k3R0gwYk1zd2lrNHZ3OEFFY3dsbXhVQ3Y0WCtxVTZ6aUNJL2dBbDcrVFNiUnJuWFArMjJIMnJCclhNMHJXWQpKUHJQa0NDTUwyamhoNkFlMm9FSStWZHZwRG1HclBrVGlIK202K1Rza2dpQTZSc0VvNWhDSDZieE1FYjN6b3FoCkwyL0FQcHdYNkRBM01tby9MRWdEQU1GSWtjd1lrZm8vQlpTUEhUU2RCYThBY2E2b2x0WlBpUS81VUFReGF5NW0KTGh0bjd0ZU1YSjBvQlBWZWNqQitSWkJ1K24zcEpYbHZZRytkUm5hNlE4bStaRTZHcTZiWFR3Nk9yd3ZuOXZ1bgpIcERuenRnbFlDeXdiM2hIM0pONnRTNkhZMm9VTWdkeVhLOFU0RVU1Tmt5MTU5MkRRMlRJVFlUYWcwZUgxVkVRClBrYlZzL0JRNWV0RlZnYnRMMm1DTmRtVGRRREpHNGM0Um9PbDhDSE1tOFFUY0RodXpJZVJZd285UzBpa21xZXUKeiswU2NLYWJnQ2ttdHVvRCtPVVRWRFVNaGpsQjlkNkU0S2I3bnFJME11b3hIeFRLTlUrdlRydThTeHJtYzRvQQpSdHdrMDNlVy9tZDJKeFNJUjFaRXlrd3lEdTQzb3k2SEtSUERJNkpQRTJGTWFNdzViT3oybVpNeDNuRUNUKzJrCkZRYS9zK0x0bXFuWGlWUE5wTnp4SjNMS0VBSitndXdFZU5pT0xPOFoyTjhoZkdTempJVmx4Y01CSVBuTUx5MSsKeTlpbzcxbkZ1ZEtEZ0YvRmNRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkJRVUFBNElDQVFCenBqaURZenBQWFRTaQpBMktXdGRWTXBnejZxWm5ZTDhWenFsUWVwcFoxYlA3UmJsbVlQQzIwVUh5MS85Uk1kclBBWDR5YVZTUjNaQk1sCm9zcE1jUm9oREtMN0ZodWJPaVVhTVpITk8yVHFDVVV4TjVzamFubGU0MlFDR1FVTDVmS1orR1hpc0huNnJ2b0oKSEhiQW93WWFObE9vZS9qYmxzaVkvNHNkbmtSQis1OGRlaDE3d1AzUW9QaVVWMlZTaTlHNjFWSHFmdk5TVHI2LwpHdXFEU25IMkc3dVJDU25kTVpiRE4ySWtzeWtPVFBNZmRUWmIyVlpzVGxWSW95WlRQb3l1NVR5b3RodHBhZ3AvClJXdi9MUVM5VUFNenJMbVlRdU9RbWhBam5VbU9vNXRPL0tBMEJUUVplemcxUm00RW5kWDFzK0s1V1BkVWtQd0MKaUh3NHRxSGJrUU5jNG83WGsyNUc5RVpYZUdQVTZxRlhyVE1VOW0vMGFEaTNORWtXZWZKdTdPNFBQb2NJNDNFVQpNSmNPNXcvTUFrZFYxWG9yZWdBbkltbUxUblcvU2tEUGUxMDVFcVN1Y0Qvak5JQ05pTjc5c3VrREdwZ3hDdjdmCno4NCtJTFllaEJzODVua3ZUMG9lbjJBWXJ5T08yVnJTbWJ6em13ekpybUJzVkN2SHlxMFFkRkFLQ0RFOUJaa0IKa2NaVHRKbGh1RDdNTS8wYlpMVmthMnNXNFNGZ2Y5WEhRT21nMFc4cDhRWnlNenZJVnRTRS9lSlhNSCs5allQcQpaQjhLOWVqOVB6Qy9XQ0dYM2RNZ0RZWXZXbnBvc0dvWGJTaEQ3NE9zVm5zSlFUTDVHMmxrSGZYUDEybmthdkFCClBNRU45czNvMXJqK2gvVWFpN2tsV0RQM1daWU1SUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=
  tls.key: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlKSndJQkFBS0NBZ0VBNEx1MUxEbHNnYUZBdTJIUjBtY2VUVjN5TTlyZksrZ3Z3V0tuakJqVXJGMzJ3bU01ClF4bkNYbmlsL3NrUjJ6VndsM1pIaW85NzJHcVZNTldtZnpjdkRkalhicENPeGg5R3pMTUlwT0w4UEFCSE1KWnMKVkFyK0YvcWxPczRnaVA0QUplL2swbTBhNTF6L3R0aDlxd2Exek5LMW1DVDZ6NUFnakM5bzRZZWdIdHFCQ1BsWApiNlE1aHF6NUU0aC9wdXZrN0pJSWdPa2JCS09ZUWgrbThUQkc5ODZLb1M5dndENmNGK2d3TnpKcVB5eElBd0RCClNKSE1HSkg2UHdXVWp4MDBuUVd2QUhHdXFKYldUNGtQK1ZBRU1Xc3VaaTRiWis3WGpGeWRLQVQxWG5Jd2ZrV1EKYnZwOTZTVjViMkJ2blVaMnVrUEp2bVJPaHF1bTEwOE9qcThMNS9iN3B4NlE1ODdZSldBc3NHOTRSOXlUZXJVdQpoMk5xRkRJSGNseXZGT0JGT1RaTXRlZmRnME5reUUyRTJvTkhoOVZSRUQ1RzFiUHdVT1hyUlZZRzdTOXBnalhaCmszVUF5UnVIT0VhRHBmQWh6SnZFRTNBNGJzeUhrV01LUFV0SXBKcW5ycy90RW5DbW00QXBKcmJxQS9qbEUxUTEKRElZNVFmWGVoT0NtKzU2aU5ETHFNUjhVeWpWUHIwNjd2RXNhNW5PS0FFYmNKTk4zbHY1bmRpY1VpRWRXUk1wTQpNZzd1TjZNdWh5a1R3eU9pVHhOaFRHak1PV3pzOXBtVE1kNXhBay90cEJVR3Y3UGk3WnFwMTRsVHphVGM4U2R5CnloQUNmb0xzQkhqWWppenZHZGpmSVh4a3M0eUZaY1hEQVNENXpDOHRmc3ZZcU85WnhiblNnNEJmeFhFQ0F3RUEKQVFLQ0FnQWpoMm1BSVYvM0tvQXFYNitsWE9vY2Z5TEFjZlRnWXlmUm9nQXRGT3ZpaUVSdnZQSWJtcUh3LzQvMgp0T0VlejljS0N3Z0tidDY4ZXpVMDhFSVBVTEVldGs1d3kyZlhDTERQd2VvMjd5L0RhS1BZbVo5c3RnUXYxRTkwCitZdUpQT2JYR0pNTGRYWlFaNUtCM0w0WllNa3pKWWpTRWQ2WkhBY1pRcEdKUGtEaFA5Z3dqQUwzd25YWnhkVG0KOHFpRHdqMkI3U0J0Q08xZGtXT0w2S2NpOEdmMzIyNXRSeXVhc0F0TGVFalBJU2hNN25wQUIwbUhhSTFrd1FkWQpHVkRBUTNUQzhsZ1ZjT09WQWF2R0RUdzZSUjAwbHVaUi95NFVBMTJPY2tIaVJzNW43Uk9ma3UzZnJiaGtPS2wzCkl6N2lGWGJGd2R2T1B0dHZUUW5tZGpndDlKeWo5cWJhZUxrc3I1NkNaYi9zZldYeDkwTlBodldvUUN4VFVmMTQKYTcxWDJJbFJZWmVlWVEwL1JQejJtSnQwVlVlRnpScGRKQkdWZVNta3lmZ1ZWQTJZVURzZGtsc2RlZEx2SnIxbgpKQVY5MzdMVmFKN01rYjVQc1hYR3FoWktVRXVXeis3MWtnZjdwTk1ZUUxhRWxEM0xGRmVVdTVhMEJLSTJrWDBlClNUVWg1UTVQWnNqcTVyNXZ4SktzaTNBWGFEVnVGUmZ3ZVFMdGRjQXFuR1NVNTVNcVV2K25CVm1SWEpFMktSTzQKZXVOY2dIUFdvek5iMDFsZjVBZElTb3drNlM4UFg5WkZVUG5oOXBFNkNnYVI1Wjh6R0dBcFBnUm5pSjN5bnZHOQo0L1J2bVd6MnVoU0l3WDRjNXVldmFZd0pSTHUyK2daQlIrOTlZMXlnSHVoRUcwQnZWUUtDQVFFQS9GQkdSM1JqClh1Ukh3ajlueHFjVk53WEVGMEMyK3lQbE43a1BHckxtQWNzTjFsWktSVjhKVXpjOGdoQzUzc3RrZGViZUtmekkKSTdYajhkRVExa0w5TW1GdkJXOEVvQTBKTGMrUWFEelZxVk1oSE1BSHNuS1pJamF1UkxyTElYWFFyNlVjQnllSApFa1o1ZnUwZkRNd2ZTMmtxYk0wNzIxZkZwcTc1ZkkwQVVZOWUzaEl5aE5ZZW0zOFgxakF6R1V4N2hEU3FRK0RpCnAvZmV1VDRPZElSVGRsUGcxSnNtRVc5czRiOEZMYnpVMVhKL0ZDV1NCYmUrNWRGS2p2YmR2cWlkNGRNZDYxOWUKMTEydm9GRDVKdksxK2dMdWJkR1BkOUxoek9rVVRZZEZZZDFETSs5bSs5OVhPZzdNTGNWQlAyVUFqanBvY3VXUwozYncvNG9oVW1UWTkrd0tDQVFFQTVBUkdWc2xkV3JMb2FHMFJZUzJGMVdHcUFsWi9Namt6R0tETnVERzJBQk44CkgzbC9UM3Y1RGlTY3JsSlVFUWZvMlQ3Ly9FRlJVYkIxQkpYMTFndzVZQ1pNT25TWDgxdU1mcGQyei9SOUxjSzEKWkpLMGxTZmRoekc2TGpreTVYVjBGbHFGaENzZ2o0Qm1UWGJtNkZqZENoOXpVRzI2NURLZkxnSzBlUEhhYjBvRgpFS1JEZnpTelNPam14K3FSSGxEUnptV2hHY0NkV2J5a0VlTkd1NjNJeWZHRHIwNzgzWlZDSTBIMUFlUWdzSkRXCnQzVGdpeUIwd3NZVFUwUW90RHE2TWJuV2RTNXZHMWtzTk9QZ3hyZGE3dVFtZjNuT1VzVHF2ZHdUbFZUbkdkL1oKcnFvNmxuMVljVWpPNGhxdjdPd3g1dGZIQVZjcnBJRVl2ZWV5VmtMS2d3S0NBUUFPOS9RemFRUThMTzdVNTA0UQp5dmpIT3VCWFFNK2FOcGJ5cDFmdURZNzNyRVExNHdpazlPNW9zVzQxaVNoOXZ6TkdpMXZDd2V4ZHNmekQ2OU5ECjR0V0NsNlV1ZlZlWTV5MFVPcXdtZ3ZWcUJqU0FzQ1BFd21lelQrc215SzRrWGdqellxZzNCSEZPOUQ5ZytGQlAKUWd6WlBIUDM0SFVjbmlocnF4WEIvZHQyK3pwMWtqN05BcWJ1TXF3SFdQU3ZHNHA0WFdkOGYycnk3QkdhaThQdgp4YW50Nnl2N2NQamhMK3NWdVc5bE56NnBLeEcrOER1cGV5MG9GVEtIS0w0ZkFZSGNVOW9DakxYanNQc3FWNk53ClhCWFByenpWNXdqTDR3YmlVVEdUSitORjJ3cVJtakpSM3Y0ZHc2TDVWQ3A2eUZNd0hPYjFhZ2s4Zmw2TDRlcWkKN0VUaEFvSUJBRjVhUW4wQklFYzZ4eDhIR3V6NmVHbisydW5TdnhtYVA4R09NUEpxWjZTS2E0OWVxRWJNeHhlSwpJT2VsbTdIY2N3Y0tvY1RSaG9QbUg5WUE4OVJhQkpmNzRRbERXK2xRMWNkQWgrS3ZpZWtZckJUcy9CcklmMHZGClVRUjFtTkVJbER2M3cwNFl4b1Y3SFZvcXZJd2kwWHl4M1BiSUlWRHlmWm45ZG82aGpjRUZnU2tNdi8xd1lrdm0KVERFbnFGdENHRDl2SUlYV2hZWXZvRGppc2s5UkwwZ1pUMk9Jck94SUtqRUt4d2E4VHFhaG1LZ2JqaHNrR0F6TgpDQXdwcFNwSEx1c0t1bXFOQjE3cXZIYzZZTFg2QTMvZEd1MGZDemlHMFpnMDdFbWI4M0ZxaHRwWENKMWpTdWk5CnR4WXE4dWQ0S1lJYmdmYlZDbk10Rkg3bzFJd0xZVjhDZ2dFQUNZWWpRVkRNNFRzbGVSOEVCeWFnVFBvY1ZjbmcKcHlHektjWk9lYnhmMldlR1o2YVp2MFMvT2JUSDUrb1BiSU8yVGNOdGNINjZoQ0FpZ1UxZmtIZnBqYjZJeklnMgpwSE85R3F6VkluM1c3K1YvOFBZMW9RQUo2WXZuOGZlQXRCaFEwcU4vUkRSUWxzZlAwUStnM0ZSeDJMOVVSRURsCkZUcmMzUmRtZDBEbXdFUWs4bXhCbElzQ3FZa08zRnBnOUVVMTEvN2xDRUlJZk9GRzN3UDU0SlNtT0JLZTBYZ0cKcGRBczV5VEZONjR4ZllscjU3b2xrWm51a29FWURkYml3OXlzZHpmbjc5bWZGRDgrQVhhaTQvYkVnWVVWSWVueApiK2lwOVU3a2s1NXA4RElTWHd4bEthZ3htd3pGUEFqWDZPVEJLZFpGTWRnSXU3Tm01TmVqRnA2VWxBPT0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0=
kind: Secret
metadata:
  name: mySecret
  namespace: whatever
type: kubernetes.io/tls
`)
}

func writeAndEncrypt(th *kusttest_test.HarnessEnhanced, path, content string) {
	encryptedContent, err := encrypt(path, content)
	if err != nil {
		th.GetT().Fatal(err)
		return
	}
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
			KeyGroups:       conf.KeyGroups,
			Version:         version.Version,
			ShamirThreshold: conf.ShamirThreshold,
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
