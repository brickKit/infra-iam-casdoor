package module

import "testing"

// TestRebaseHost_覆盖协议与host只保留原path 是真机部署时发现的真实坑
// 的回归测试：Casdoor 的 OIDC 发现文档给出的 jwks_uri 是部署级全局
// 唯一的 origin 配置拼出来的，可能与本组件（brickkit 管理的容器）
// 实际能够到 Casdoor 的地址不同——真机复现过 jwks_uri 是
// "http://localhost:8000/.well-known/jwks"，而本组件容器内部连
// "http://localhost:8000" 只会连到自己，永远拿不到真正的 JWKS。
func TestRebaseHost_覆盖协议与host只保留原path(t *testing.T) {
	got := rebaseHost("http://localhost:8000/.well-known/jwks", "http://host.docker.internal:8000")
	want := "http://host.docker.internal:8000/.well-known/jwks"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRebaseHost_带查询参数也保留(t *testing.T) {
	got := rebaseHost("http://localhost:8000/path?a=1&b=2", "http://host.docker.internal:9000")
	want := "http://host.docker.internal:9000/path?a=1&b=2"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRebaseHost_rawURL解析失败时原样返回(t *testing.T) {
	got := rebaseHost("://not a url", "http://host.docker.internal:8000")
	if got != "://not a url" {
		t.Fatalf("解析失败应该原样返回，实际 %q", got)
	}
}
