package service

import (
	"encoding/json"

	besdk "github.com/brickKit/be-sdk-go"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
)

// webhookUserPayload 解析 Casdoor 的 webhook 投递体。
//
// 投递体就是 Casdoor 的 Record 对象（2026-10-02 真机抓到过 login、update-user、add-user、
// delete-user）：action 是动作名；object 是**被 JSON 编码成字符串**的请求体——管理界面
// 改人时是整个用户对象（口令已由 Casdoor 掩码成 "***"），login 时是登录表单，用最小请求体
// 调管理 API 的 add-user / delete-user 只有 owner 与 name、没有 id；user 是发起操作的账号名
// （管理员改别人时是 "admin"，不是被改的人）；extendedUser 在 isUserExtended=false 时为 null。
//
// ⚠️ 投递体只用来认出"是谁"，事件内容一律回 Casdoor 读这个人的当前状态（R61，见
// service.go 的 HandleWebhookDelivery）：Casdoor 会把同一秒里的两次修改按新到旧投递，
// 照投递体发事件，下游就留下旧值。
type webhookUserPayload struct {
	Action       string          `json:"action"`
	Object       json.RawMessage `json:"object"`
	ExtendedUser json.RawMessage `json:"extendedUser"`
}

// userRef 是投递里能认出被操作用户的字段：有 id（即 sub）时用 id，否则用 owner/name。
type userRef struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func (r userRef) hasName() bool { return r.Owner != "" && r.Name != "" }

// userRef 依次尝试 object / extendedUser 两个位置，先找带 id 的，再找带 owner 与 name 的。
// 每个位置既可能是 JSON 对象，也可能是装着 JSON 的字符串（Casdoor 的 object 就是后者）。
// 都没有时返回零值。
func (p webhookUserPayload) userRef() userRef {
	var byName userRef
	for _, raw := range [][]byte{p.Object, p.ExtendedUser} {
		ref, ok := decodeUserRef(raw)
		if !ok {
			continue
		}
		if ref.ID != "" {
			return ref
		}
		if !byName.hasName() && ref.hasName() {
			byName = ref
		}
	}
	return byName
}

// decodeUserRef 解一个候选位置：字符串先解出里面的 JSON 文本再解一次。
func decodeUserRef(raw []byte) (userRef, bool) {
	var r userRef
	if len(raw) == 0 {
		return r, false
	}
	if raw[0] == '"' {
		var inner string
		if err := json.Unmarshal(raw, &inner); err != nil {
			return r, false
		}
		raw = []byte(inner)
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return userRef{}, false
	}
	return r, true
}

// actionKind 是投递动作的分类。事件 subject 由它与回读到的当前状态一起决定
// （userEventFor）；认不出的动作（login 等）不回读、不发事件。
type actionKind int

const (
	actionCreated actionKind = iota + 1 // add-user、signup
	actionChanged                       // update-user
	actionRemoved                       // delete-user、forbid-user
)

// kindOf 把 Casdoor 的 action 名分类。真机见过 update-user、add-user、delete-user 与
// login；signup、forbid-user 取自 Casdoor 源码里的动作名。认不出返回 ok=false。
func kindOf(action string) (actionKind, bool) {
	switch action {
	case "add-user", "signup":
		return actionCreated, true
	case "update-user":
		return actionChanged, true
	case "delete-user", "forbid-user":
		return actionRemoved, true
	default:
		return 0, false
	}
}

const (
	subjectUserCreated  = "infra.iam.user.created.v1"
	subjectUserUpdated  = "infra.iam.user.updated.v1"
	subjectUserDisabled = "infra.iam.user.disabled.v1"
)

// userEventPayload 是三条 infra.iam.user.*.v1 事件共用的 payload 形状
// （契约见 contracts/events/iam.events.json）。disabled 事件只有 sub。
type userEventPayload struct {
	Sub         string      `json:"sub"`
	DisplayName string      `json:"display_name,omitempty"`
	Email       string      `json:"email,omitempty"`
	Phone       string      `json:"phone,omitempty"`
	ImAccounts  []imAccount `json:"im_accounts,omitempty"`
	Version     int64       `json:"version,omitempty"` // 仅 updated 事件要求（契约 required），与信封 version 相同
}

type imAccount struct {
	Channel   string `json:"channel"`
	AccountID string `json:"account_id"`
}

// userEventFor 按回读到的当前状态 u 组出事件（u 为 nil 表示 Casdoor 里已经没有这个人）：
//   - 不在了、已停用（isForbidden）、已软删除（isDeleted）→ disabled。契约规定删除也发
//     disabled，不另设 deleted；
//   - 还在、动作是新建 → created；其余（修改，或删除投递到达时人又还在）→ updated，
//     内容是当前状态。
//
// version 由调用方按人取（repo.NextUserEventVersionTx），信封与 updated 的 payload 共用。
func userEventFor(kind actionKind, sub string, u *casdoor.User, version int64) (besdk.Event, error) {
	payload := userEventPayload{Sub: sub}
	var subject string
	switch {
	case u == nil || u.IsForbidden || u.IsDeleted:
		subject = subjectUserDisabled
	case kind == actionCreated:
		subject = subjectUserCreated
	default:
		subject = subjectUserUpdated
		payload.Version = version
	}
	if subject != subjectUserDisabled {
		payload.DisplayName, payload.Email, payload.Phone = u.DisplayName, u.Email, u.Phone
		if u.Dingtalk != "" { // 与 gRPC BatchGetUsers 的 im_accounts 同一个来源
			payload.ImAccounts = []imAccount{{Channel: "dingtalk", AccountID: u.Dingtalk}}
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return besdk.Event{}, err
	}
	return besdk.Event{Subject: subject, AggregateID: sub, Version: version, Payload: body}, nil
}
