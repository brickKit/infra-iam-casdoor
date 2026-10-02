// Package features 把 ENABLED_COMPONENTS 的值解析成"本项目装了哪些组件"——
// GET /api/tenant/features 与 gRPC GetTenantFeatures 下发的就是这份清单。
//
// 值是项目 brickkit.yaml 的全文（config 里写 file://brickkit.yaml，brickKit 注入
// 文件内容）。brickkit.yaml 由 brickkit add / remove / upgrade 维护，是"项目里有
// 什么"唯一的真相源；直接读它，就没有"加了组件却忘了重新生成清单"这一步。
//
// ⚠️ 只取 components[].id 与 kind。其余内容（sources、installer…）根本不解码：
// compose 运行期会把 sources[].authToken 里的 ${VAR} 换成真实密钥，这些值不能
// 进内存里的任何结构，更不能进日志或报错信息。
package features

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// lockfile 只声明要用的两个字段；yaml.v3 对没声明的键直接跳过，不保留。
type lockfile struct {
	Components *[]entry `yaml:"components"`
}

type entry struct {
	ID   string `yaml:"id"`
	Kind string `yaml:"kind"`
}

// lineRe 从 yaml 的报错里只取行号——报错正文可能引用出错位置的原文。
var lineRe = regexp.MustCompile(`line \d+`)

// FromLockfile 返回 brickkit.yaml 里全部非外壳组件的 ID：同一组件的多个版本
// （requiredBy 兼容版本）只算一次，按字典序排列。外壳（kind: shell）是部署
// 形态，不是一项功能，不下发。
//
// 空值、旧的逗号分隔写法、不是 YAML、没有 components 段、条目缺 id 都是配置
// 错误，返回 error（模块启动即失败），不退化成空清单。
func FromLockfile(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("ENABLED_COMPONENTS 为空：值应是项目 brickkit.yaml 的内容（config 里写 file://brickkit.yaml）")
	}
	var lf lockfile
	if err := yaml.Unmarshal([]byte(raw), &lf); err != nil {
		where := strings.Join(lineRe.FindAllString(err.Error(), 1), "")
		if where == "" {
			where = "整体结构不对"
		}
		return nil, fmt.Errorf("ENABLED_COMPONENTS 不是 brickkit.yaml 的内容（YAML 解析失败：%s）", where)
	}
	if lf.Components == nil {
		return nil, errors.New("ENABLED_COMPONENTS 里没有 components 段：值应是项目 brickkit.yaml 的内容")
	}

	seen := map[string]bool{}
	out := []string{}
	for i, e := range *lf.Components {
		if e.ID == "" {
			return nil, fmt.Errorf("ENABLED_COMPONENTS：components 第 %d 个条目缺 id", i+1)
		}
		if e.Kind == "shell" || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		out = append(out, e.ID)
	}
	sort.Strings(out)
	return out, nil
}
