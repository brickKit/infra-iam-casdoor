package service

import (
	"encoding/json"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

// webhookUserPayload 宽容解析 Casdoor 的 webhook 投递体。
//
// ⚠️ 诚实的现状（设计计划 §9 第 2 条、AGENTS.md 已知缺口）：本次调研
// 确认了 Casdoor 的 webhook **支持自定义 header**（共享密钥校验的
// 前提），但**没能在真机上实际触发并抓到一条用户增删改事件的真实
// payload**——自助注册需要短信/邮箱验证码，受限环境走不通；管理 API
// 建用户在真机测试里没有观察到 webhook 被调用。所以这里的字段候选是
// 按 Casdoor 开源代码里 `object.Record`/`object.Webhook` 的公开字段名
// 尽力猜的，不是照着抓包结果写的——`json.RawMessage` + 逐个候选尝试
// 是刻意的防御性写法：猜错了字段名不该让整条投递直接报错，而应该在
// webhook_deliveries 里留下"IGNORED，理由是解析不出来"的痕迹，等真的
// 抓到一次真实 payload 之后回来对一遍、把这里改成精确解析。
type webhookUserPayload struct {
	Action       string          `json:"action"`
	Name         string          `json:"name"`
	Owner        string          `json:"owner"`
	Object       json.RawMessage `json:"object"`
	User         json.RawMessage `json:"user"`
	ExtendedUser json.RawMessage `json:"extendedUser"`
}

// casdoorUserFields 是 Casdoor User 对象里本组件关心的字段——字段名
// 已经通过真实签发的 token payload 核对过（sub 对应 "id"，见
// docs/dev/实测踩坑记录.md 或 AGENTS.md 的真机核对记录），比 action/
// object 那层包装可信得多。
type casdoorUserFields struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
}

// Sub 依次尝试 object/user/extendedUser 三个候选位置，返回第一个能解出
// 非空 "id" 字段的结果。三个都失败时返回空字符串——调用方据此把这条
// 投递标记 IGNORED，而不是发一个 sub 为空的事件出去。
func (p webhookUserPayload) Sub() string {
	for _, raw := range [][]byte{p.Object, p.User, p.ExtendedUser} {
		if len(raw) == 0 {
			continue
		}
		var f casdoorUserFields
		if err := json.Unmarshal(raw, &f); err == nil && f.ID != "" {
			return f.ID
		}
	}
	return ""
}

// userFields 返回三个候选位置里第一个解析成功的用户字段——Sub() 已经
// 确认过存在，这里重复解析一次换取更简单的调用方代码（数据量小，不值得
// 为了省一次 Unmarshal 搭一层缓存）。
func (p webhookUserPayload) userFields() casdoorUserFields {
	for _, raw := range [][]byte{p.Object, p.User, p.ExtendedUser} {
		if len(raw) == 0 {
			continue
		}
		var f casdoorUserFields
		if err := json.Unmarshal(raw, &f); err == nil && f.ID != "" {
			return f
		}
	}
	return casdoorUserFields{}
}

// EventSubject 把 Casdoor 的 action 名映射成本组件的事件 subject
// （设计计划 §4）。action 的确切取值集合同样未经真机核对，这里覆盖
// Casdoor 源码里能看到的几个明显候选，认不出的 action 返回 ok=false，
// 调用方标 IGNORED 而不是瞎猜发一条。
func (p webhookUserPayload) EventSubject(action string) (subject string, ok bool) {
	switch action {
	case "add-user", "signup":
		return "infra.iam.user.created.v1", true
	case "update-user":
		return "infra.iam.user.updated.v1", true
	case "delete-user", "forbid-user":
		return "infra.iam.user.disabled.v1", true
	default:
		return "", false
	}
}

// userEventPayload 是三条 infra.iam.user.*.v1 事件共用的 payload 形状
// （契约见 contracts/events/iam.events.json）。disabled 事件不带这些
// 字段（只有 sub），所以下游按 subject 决定要不要读它们。
type userEventPayload struct {
	Sub         string `json:"sub"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	Version     int64  `json:"version,omitempty"` // 仅 updated 事件要求（契约 required）
}

// buildUserEvent 组出 besdk.Event。⚠️ version 用签名时刻的 unix 纳秒——
// 本组件刻意不存用户表（设计计划 §2 末尾），没有一个天然的行版本号可
// 用；纳秒时间戳满足"严格单调递增"这个契约要求（决策 43），代价是它
// 不是一个有业务含义的版本号，但下游（infra-notification）只用它做
// "谁更新"判断，不需要可读性。
func buildUserEvent(subject string, p webhookUserPayload) (besdk.Event, error) {
	fields := p.userFields()
	sub := p.Sub()
	version := time.Now().UnixNano() // 信封与 payload 共用同一个值，见函数注释

	payload := userEventPayload{Sub: sub}
	switch subject {
	case "infra.iam.user.disabled.v1":
		// 契约里这条只要求 sub，其余字段留空。
	case "infra.iam.user.updated.v1":
		payload.DisplayName, payload.Email, payload.Phone = fields.DisplayName, fields.Email, fields.Phone
		payload.Version = version
	default: // infra.iam.user.created.v1
		payload.DisplayName, payload.Email, payload.Phone = fields.DisplayName, fields.Email, fields.Phone
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return besdk.Event{}, err
	}
	return besdk.Event{Subject: subject, AggregateID: sub, Version: version, Payload: body}, nil
}
