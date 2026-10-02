package features

import (
	"reflect"
	"strings"
	"testing"
)

// realShapeLockfile 照真实 brickkit.yaml 的形态写：注释、sources（含一个带
// authToken 的 market 源——compose 运行期会把 ${MARKET_TOKEN} 换成真值，所以这里
// 直接写成一个看起来像密钥的字面量）、外壳条目、同一组件的 requiredBy 兼容版本、
// 自带 source 的条目、installer 段。
const realShapeLockfile = `# brickkit.yaml — what this project is made of
project: be-assembly-standard

sources:
  - name: local-dev
    type: local
    path: ./components
  - name: market
    type: market
    url: https://market.example.com/api/v1
    authToken: s3cr3t-market-token-value

components:
  - id: mdm/customer
    version: 2.0.0
  - id: infra/iam-casdoor
    version: 2.0.0
  - id: be/go-infra
    version: 1.0.0
    kind: shell
  - id: infra/authz
    version: 2.0.0
  - id: mdm/customer
    version: 1.0.10
    requiredBy: [erp/legacy]
  - id: erp/legacy
    version: 1.0.0
    source:
      type: git
      repo: https://github.com/vendor/erp-legacy.git

installer:
  requireSignature: true
`

func TestFromLockfile_取组件ID跳过外壳去重并排序(t *testing.T) {
	got, err := FromLockfile(realShapeLockfile)
	if err != nil {
		t.Fatalf("真实形态的 brickkit.yaml 应该能解析：%v", err)
	}
	want := []string{"erp/legacy", "infra/authz", "infra/iam-casdoor", "mdm/customer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFromLockfile_结果与条目顺序无关(t *testing.T) {
	reordered := `components:
  - id: mdm/customer
    version: 2.0.0
  - id: infra/authz
    version: 2.0.0
`
	a, errA := FromLockfile(reordered)
	b, errB := FromLockfile(`components:
  - id: infra/authz
    version: 2.0.0
  - id: mdm/customer
    version: 2.0.0
`)
	if errA != nil || errB != nil {
		t.Fatalf("解析失败：%v / %v", errA, errB)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("同一组组件换个顺序，结果应该相同：%q vs %q", a, b)
	}
}

func TestFromLockfile_没有组件时是空清单不是nil(t *testing.T) {
	got, err := FromLockfile("project: empty\ncomponents: []\n")
	if err != nil {
		t.Fatalf("没有组件的项目是合法的：%v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("应该是空切片（JSON 里是 []，不是 null），实际 %#v", got)
	}
}

// 旧的逗号分隔写法、空值、不是 YAML 的内容都是配置错误：模块启动时就失败，
// 而不是带着一份空清单悄悄跑起来（前端会少掉全部菜单，没有任何报错）。
func TestFromLockfile_配置错误一律报错(t *testing.T) {
	cases := map[string]string{
		"空值":              "",
		"只有空白":            "  \n\t\n",
		"旧的逗号分隔写法":        "mdm/customer,erp/sales",
		"不是 YAML":         "components: [unclosed",
		"条目缺 id":          "components:\n  - version: 2.0.0\n",
		"没有 components 段": "project: x\nsources: []\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := FromLockfile(raw); err == nil {
				t.Fatalf("应该报错，实际返回 %q", got)
			}
		})
	}
}

// sources 里的 authToken 等值在运行期是真实密钥：报错信息里一个字都不能带出原文。
func TestFromLockfile_报错信息不带出原文(t *testing.T) {
	broken := strings.Replace(realShapeLockfile, "components:\n", "components: s3cr3t-market-token-value\n  oops: [\n", 1)
	_, err := FromLockfile(broken)
	if err == nil {
		t.Fatal("坏掉的 YAML 应该报错")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("报错信息带出了原文：%v", err)
	}
	_, err = FromLockfile("s3cr3t-market-token-value,erp/sales")
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("旧写法应该报错且不带原文，实际 %v", err)
	}
}
