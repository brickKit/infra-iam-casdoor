package casdoor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// fakeCasdoor 是 Casdoor 管理 API 的最小替身：/api/login 发会话 cookie，
// /api/get-user 按会话判断——与真机核对过的行为一致：没有有效会话时对存在的
// 用户回 status:error + "Please login first"，查不到的用户回 status:ok + data:null。
type fakeCasdoor struct {
	server  *httptest.Server
	mu      sync.Mutex
	logins  int
	session string            // 当前有效的会话 cookie 值；置空 = 会话过期
	users   map[string]string // sub -> displayName
	byName  map[string]string // "<owner>/<name>" -> sub
}

func newFakeCasdoor(t *testing.T) *fakeCasdoor {
	f := &fakeCasdoor{users: map[string]string{}, byName: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.logins++
		f.session = "s" + string(rune('0'+f.logins))
		v := f.session
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "casdoor_session_id", Value: v, Path: "/"})
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/get-user", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		sub := r.URL.Query().Get("userId")
		if id := r.URL.Query().Get("id"); id != "" {
			sub = f.byName[id] // id=<owner>/<name> 的查法
		}
		name, ok := f.users[sub]
		if !ok {
			writeJSON(w, map[string]any{"status": "ok", "data": nil})
			return
		}
		c, err := r.Cookie("casdoor_session_id")
		if err != nil || f.session == "" || c.Value != f.session {
			writeJSON(w, map[string]any{"status": "error", "msg": "Please login first", "data": nil})
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "data": map[string]any{"id": sub, "displayName": name}})
	})
	mux.HandleFunc("/api/reject", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "error", "msg": "password or code is incorrect"})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCasdoor) expireSession() { f.mu.Lock(); f.session = ""; f.mu.Unlock() }

func (f *fakeCasdoor) loginCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.logins }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
