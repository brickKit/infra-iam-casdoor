package grpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/brickKit/infra-iam-casdoor/gen/infra/iam/v1"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
)

// fakeCasdoorUsers：/api/login 永远成功；/api/get-user 对 known 里的 sub 回用户，
// 对 failing 里的 sub 回 HTTP 500，其余回 data:null（查不到）。
func fakeCasdoorUsers(t *testing.T, known map[string]string, failing map[string]bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/get-user", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("userId")
		if failing[sub] {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		if name, ok := known[sub]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": map[string]any{"id": sub, "displayName": name}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": nil})
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func serverWith(t *testing.T, baseURL string) iamv1.IamServiceServer {
	t.Helper()
	var holder atomic.Pointer[casdoor.AdminClient]
	c, err := casdoor.NewAdminClient(context.Background(), baseURL, "admin", "pw")
	if err != nil {
		t.Fatal(err)
	}
	holder.Store(c)
	return New(&holder, nil)
}

func TestBatchGetUsers_查不到的sub省略(t *testing.T) {
	s := serverWith(t, fakeCasdoorUsers(t, map[string]string{"a": "甲"}, nil).URL)
	resp, err := s.BatchGetUsers(context.Background(), &iamv1.BatchGetUsersRequest{Subs: []string{"a", "missing"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Users) != 1 || resp.Users[0].Sub != "a" || resp.Users[0].DisplayName != "甲" {
		t.Fatalf("应只返回 a，实际 %+v", resp.Users)
	}
}

// Casdoor 出错（不可达、5xx、会话问题重试后仍失败）时不能把用户当成"查不到"
// 悄悄省略：调用方会以为这个人不存在。整次调用回 Unavailable。
func TestBatchGetUsers_Casdoor出错回Unavailable而不是省略(t *testing.T) {
	s := serverWith(t, fakeCasdoorUsers(t, map[string]string{"a": "甲"}, map[string]bool{"b": true}).URL)
	_, err := s.BatchGetUsers(context.Background(), &iamv1.BatchGetUsersRequest{Subs: []string{"a", "b"}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("期望 codes.Unavailable，实际 %v（%v）", status.Code(err), err)
	}
}

func TestBatchGetUsers_管理会话未就绪回Unavailable(t *testing.T) {
	var holder atomic.Pointer[casdoor.AdminClient]
	_, err := New(&holder, nil).BatchGetUsers(context.Background(), &iamv1.BatchGetUsersRequest{Subs: []string{"a"}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("期望 codes.Unavailable，实际 %v（%v）", status.Code(err), err)
	}
}
