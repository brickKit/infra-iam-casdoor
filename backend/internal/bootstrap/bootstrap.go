// Package bootstrap 是首次部署初始化：建 Casdoor 组织/应用/webhook
// （设计计划 §1"首次部署初始化"、§9 第 5 条）。
//
// ⚠️ 判据是"每次启动都对账"，不是"只跑一次"（§9 第 5 条的选择，理由
// 同 erp-inventory 的 claim-first：单机测试测不出"跑了一半挂了"的中间
// 态）——每一步都先查 Casdoor 里那个对象是否已经存在，存在就跳过创建，
// 只把本地 bootstrap_state 补齐；不存在才创建。这比维护一个"哪一步做到
// 哪"的状态机更简单，也天然幂等：不管上次跑到第几步就断电，下次启动
// 重新走一遍三步，效果和从头跑一遍完全一样。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/brickKit/infra-iam-casdoor/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/backend/internal/repo"
)

// Config 是跑一遍自举需要的全部外部输入，字段直接对应 configSchema。
type Config struct {
	OrgName                string
	AppName                string
	AppRedirectURIs        []string
	WebhookName            string
	WebhookCallbackURL     string // Casdoor 视角能访问到本组件的地址，见 CreateWebhook 注释
	WebhookSharedHeader    string
	WebhookSharedSecretVal string
}

// Run 依次跑三步，单步失败不阻断后续步骤——比如组织建失败（网络抖动）
// 不该连带跳过 webhook 检查，下一次启动三步都会重新对账一遍。返回值
// 汇总了失败的步骤，调用方（module.Start）只记日志，不阻断组件启动
// （这几步失败只影响"新用户能不能登录"，不影响已经拿到应用 token 的
// 人正常使用别的组件——同 infra-authz 的 EnsureBootstrapAdmin 失败
// 只记日志的判断）。
func Run(ctx context.Context, c *casdoor.AdminClient, r *repo.Repo, cfg Config, logger *slog.Logger) {
	if err := ensureOrganization(ctx, c, r, cfg.OrgName); err != nil {
		logger.Error("自举：确保组织存在失败", "org", cfg.OrgName, "error", err)
	}
	if err := ensureApplication(ctx, c, r, cfg); err != nil {
		logger.Error("自举：确保应用存在失败", "app", cfg.AppName, "error", err)
	}
	if err := ensureWebhook(ctx, c, r, cfg); err != nil {
		logger.Error("自举：确保 webhook 存在失败", "webhook", cfg.WebhookName, "error", err)
	}
}

func ensureOrganization(ctx context.Context, c *casdoor.AdminClient, r *repo.Repo, orgName string) error {
	exists, err := c.OrganizationExists(ctx, orgName)
	if err != nil {
		return fmt.Errorf("查组织是否存在: %w", err)
	}
	if !exists {
		if err := c.CreateOrganization(ctx, orgName, orgName); err != nil {
			return fmt.Errorf("建组织: %w", err)
		}
	}
	return r.MarkBootstrapStepDone(ctx, "casdoor_org", nil)
}

func ensureApplication(ctx context.Context, c *casdoor.AdminClient, r *repo.Repo, cfg Config) error {
	app, err := c.GetApplication(ctx, cfg.AppName)
	if err != nil {
		return fmt.Errorf("查应用是否存在: %w", err)
	}
	if app == nil {
		if err := c.CreateApplication(ctx, cfg.AppName, cfg.OrgName, cfg.AppRedirectURIs); err != nil {
			return fmt.Errorf("建应用: %w", err)
		}
		app, err = c.GetApplication(ctx, cfg.AppName)
		if err != nil || app == nil {
			return fmt.Errorf("建完应用后查询失败: %w", err)
		}
	}
	// clientId 记下来供以后前端配置 OIDC 客户端用（暂时没有消费方——本
	// 阶段还没有前端，见 AGENTS.md）；clientSecret 不落库，登录流程本身
	// 用不上它（浏览器直连 Casdoor 走 authorization_code，本组件从不
	// 代表用户去换 token，见设计计划 §3.2）。
	detail, _ := json.Marshal(map[string]string{"clientId": app.ClientID})
	return r.MarkBootstrapStepDone(ctx, "casdoor_app", detail)
}

func ensureWebhook(ctx context.Context, c *casdoor.AdminClient, r *repo.Repo, cfg Config) error {
	if cfg.WebhookCallbackURL == "" {
		// 留空是合法状态：没配就跳过，不算失败（同 infra-authz 的
		// bootstrapAdminSub 为空时跳过），常见于本组件还没配好带外
		// 网络地址的早期开发阶段。
		return nil
	}
	exists, err := c.WebhookExists(ctx, cfg.WebhookName)
	if err != nil {
		return fmt.Errorf("查 webhook 是否存在: %w", err)
	}
	if !exists {
		if err := c.CreateWebhook(ctx, cfg.WebhookName, cfg.OrgName, cfg.WebhookCallbackURL,
			cfg.WebhookSharedHeader, cfg.WebhookSharedSecretVal); err != nil {
			return fmt.Errorf("建 webhook: %w", err)
		}
	}
	return r.MarkBootstrapStepDone(ctx, "casdoor_webhook", nil)
}
