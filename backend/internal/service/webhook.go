package service

import (
	"encoding/json"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

// webhookUserPayload 解析 Casdoor 的 webhook 投递体。
//
// 投递体就是 Casdoor 的 Record 对象（2026-10-02 真机抓到过 login 与 update-user 两种）：
// action 是动作名；object 是**被 JSON 编码成字符串**的请求体——调用方发了整个用户对象的
// update-user 时就是那个对象（口令已由 Casdoor 掩码成 "***"），login 时是登录表单，只发
// owner 与 name 的 add-user / delete-user 时也没有用户 id（这几种都标 IGNORED）；
// user 是发起操作的账号名（管理员改别人时是 "admin"，不是被改的人）；extendedUser 在
// isUserExtended=false 时为 null。所以用户字段从 object 里取，字符串与对象两种写法都认。
// 投递 ID 是否稳定仍未核实，去重键用内容哈希（见 http 包的 dedupKeyFor）。
type webhookUserPayload struct {
	Action       string          `json:"action"`
	Name         string          `json:"name"`
	Owner        string          `json:"owner"`
	Object       json.RawMessage `json:"object"`
	User         json.RawMessage `json:"user"`
	ExtendedUser json.RawMessage `json:"extendedUser"`
}

// casdoorUserFields 是 Casdoor User 对象里本组件关心的字段——字段名
// 已经通过真实签发的 token payload 核对过（sub 对应 "id"）。
type casdoorUserFields struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
}

// Sub 返回投递体里被操作用户的 id（即 token 的 sub）；取不到时返回空字符串——
// 调用方据此把这条投递标记 IGNORED，而不是发一个 sub 为空的事件出去。
func (p webhookUserPayload) Sub() string { return p.userFields().ID }

// userFields 依次尝试 object / user / extendedUser 三个位置，返回第一个能解出
// 非空 "id" 的用户字段。每个位置既可能是 JSON 对象，也可能是装着 JSON 的字符串
// （Casdoor 的 object 就是后者）。
func (p webhookUserPayload) userFields() casdoorUserFields {
	for _, raw := range [][]byte{p.Object, p.User, p.ExtendedUser} {
		if f, ok := decodeUser(raw); ok {
			return f
		}
	}
	return casdoorUserFields{}
}

// decodeUser 解一个候选位置：字符串先解出里面的 JSON 文本再解一次。
func decodeUser(raw []byte) (casdoorUserFields, bool) {
	var f casdoorUserFields
	if len(raw) == 0 {
		return f, false
	}
	if raw[0] == '"' {
		var inner string
		if err := json.Unmarshal(raw, &inner); err != nil {
			return f, false
		}
		raw = []byte(inner)
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.ID == "" {
		return casdoorUserFields{}, false
	}
	return f, true
}

// EventSubject 把 Casdoor 的 action 名映射成本组件的事件 subject
// （infra.iam.user.created/updated/disabled.v1）。真机见过 update-user 与 login（login 的 object
// 是登录表单、没有用户 id，在 Sub 那一步就标 IGNORED）；其余几个取自 Casdoor 源码里的动作名。
// 认不出的 action 返回 ok=false，调用方标 IGNORED 而不是瞎猜发一条。
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
// 本组件刻意不存用户表，没有一个天然的行版本号可用；纳秒时间戳满足
// "严格单调递增"这个契约要求（消费者只在严格大于本地值时更新），代价是它
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
