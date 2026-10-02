package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
)

// ── 投递队列（docs/design.md"投递队列"）────────────────────────────────
//
// Casdoor 从不重发投递（真机核对过：发送失败只记一条 send-webhook 记录）。所以 webhook
// 收到就登记成 RECEIVED、回 200，回 Casdoor 读用户当前状态再发事件交给这里的后台循环：
//   - Casdoor 管理会话还没就绪、或 Casdoor 不可达：投递原样留在队列里、不计次数，整个循环
//     退避，Casdoor 回来以后照常发出（停机多久都不丢）；
//   - Casdoor 在、但对这条投递回错误：计一次，按指数退避再试，满 maxDeliveryAttempts 次
//     标 FAILED、记一条 Warn（重新排队：把 status 改回 RECEIVED、attempts 清零）。

// maxDeliveryAttempts 是一条投递在 Casdoor 回错误时最多试几次。
const maxDeliveryAttempts = 10

// readBackTimeout 是处理一条投递时回读 Casdoor 的总时限（AdminClient 每次调用另有 15 秒
// 上限，会话过期还会重登一次）。认领的行锁、版本号的行锁和一条连接在回读期间都占着，
// 给它一个上限，Casdoor 卡住时不至于一直占着。
const readBackTimeout = 20 * time.Second

// queueTiming 是循环的几个时间参数；测试换成毫秒级。
type queueTiming struct {
	poll      time.Duration // 没有到期投递时多久再看一次（同进程新到的投递会立刻唤醒循环）
	retryBase time.Duration // 一条投递第 n 次失败后等 retryBase·2^(n-1)，封顶 retryMax
	retryMax  time.Duration
	downFirst time.Duration // Casdoor 不可达时整个循环的退避：从 downFirst 起翻倍，封顶 downMax
	downMax   time.Duration
}

var defaultQueueTiming = queueTiming{
	poll: 5 * time.Second, retryBase: 5 * time.Second, retryMax: 10 * time.Minute,
	downFirst: time.Second, downMax: 30 * time.Second,
}

// errSessionNotReady：Casdoor 管理会话还没建立（后台登录还没成功），这一轮什么都不认领。
var errSessionNotReady = errors.New("Casdoor 管理会话尚未就绪")

// casdoorDown 判断一次回读失败是不是"Casdoor 暂时不在"（不可达、超时）——这种失败不算
// 这条投递的次数。
func casdoorDown(err error) bool {
	return casdoor.IsUnreachable(err) || errors.Is(err, context.DeadlineExceeded)
}

// ProcessDueDeliveries 把到期的 RECEIVED 投递一条一条处理完，返回处理成的条数（终态
// PROCESSED / IGNORED）。管理会话没就绪返回 errSessionNotReady；Casdoor 不可达时停下，
// 返回那次的错误（casdoorDown 为 true）；单条投递的其它失败按重试规则记好，不中断这一轮。
func (s *Service) ProcessDueDeliveries(ctx context.Context, logger *slog.Logger) (int, error) {
	n := 0
	for ctx.Err() == nil {
		var users UserReader
		if s.users != nil {
			users = s.users()
		}
		if users == nil {
			return n, errSessionNotReady
		}
		found, handleErr, err := s.repo.ProcessNextDelivery(ctx, s.claimPrefix,
			func(tx *sql.Tx, d repo.Delivery) (string, string, error) { return s.processDelivery(ctx, tx, users, d) },
			func(d repo.Delivery, err error) repo.RetryDecision { return s.retryDecision(logger, d, err) })
		switch {
		case err != nil:
			return n, err
		case !found:
			return n, nil
		case handleErr != nil && casdoorDown(handleErr):
			return n, handleErr
		case handleErr == nil:
			n++
		}
	}
	return n, nil
}

// retryDecision：Casdoor 不可达 → 原样留着；否则计一次，满次数标 FAILED 并记 Warn。
func (s *Service) retryDecision(logger *slog.Logger, d repo.Delivery, err error) repo.RetryDecision {
	if casdoorDown(err) {
		return repo.RetryDecision{Leave: true}
	}
	attempts := d.Attempts + 1
	msg := fmt.Sprintf("第 %d 次处理失败: %s", attempts, err.Error())
	if attempts >= maxDeliveryAttempts {
		logger.Warn("webhook 投递处理多次失败，标 FAILED、不再重试（排查后可把 status 改回 RECEIVED、attempts 清零重新排队）",
			"dedup_key", d.DedupKey, "attempts", attempts, "error", err)
		return repo.RetryDecision{Failed: true, ErrMsg: msg}
	}
	after := s.queue.retryBase << (attempts - 1)
	if after > s.queue.retryMax || after <= 0 {
		after = s.queue.retryMax
	}
	logger.Info("webhook 投递处理失败，稍后重试", "dedup_key", d.DedupKey, "attempts", attempts, "retry_in", after, "error", err)
	return repo.RetryDecision{After: after, ErrMsg: msg}
}

// processDelivery 处理一条已认领的投递：认出是谁 → 回读当前状态 → 发事件（R61 的做法，
// 只是从 webhook 请求里挪到了这里）。认领它的事务已经锁住这一行。
func (s *Service) processDelivery(ctx context.Context, tx *sql.Tx, users UserReader, d repo.Delivery) (string, string, error) {
	var payload webhookUserPayload
	if err := json.Unmarshal(d.Payload, &payload); err != nil {
		return "ERROR", "解析 payload 失败: " + err.Error(), nil
	}
	kind, ok := kindOf(payload.Action)
	if !ok {
		return "IGNORED", "无法从 action 推出事件类型: " + payload.Action, nil
	}
	rctx, cancel := context.WithTimeout(ctx, readBackTimeout)
	defer cancel()
	sub, err := s.resolveSub(ctx, rctx, tx, users, payload.userRef())
	if err != nil {
		return "", "", err
	}
	if sub == "" {
		return "IGNORED", "投递里只有 owner/name，Casdoor 里查不到这个人，本组件也没见过这个名字", nil
	}
	return s.publishCurrentState(ctx, rctx, tx, users, kind, sub)
}

// RunDeliveryLoop 是 Module.Start 的后台循环之一：处理队列直到 ctx 取消（返回 nil）。
// 同进程里新登记的投递会立刻唤醒它；其余时候每 poll 看一次（别的副本登记的、到了重试
// 时刻的）。Casdoor 不可达时整个循环退避，不读唤醒信号（每来一条投递就去敲一次停机的
// Casdoor 没有意义）。
func (s *Service) RunDeliveryLoop(ctx context.Context, logger *slog.Logger) error {
	var down time.Duration
	for {
		_, err := s.ProcessDueDeliveries(ctx, logger)
		wait := s.queue.poll
		switch {
		case ctx.Err() != nil:
			return nil
		case err == nil, errors.Is(err, errSessionNotReady):
			// 会话没就绪由 module 的登录循环记日志，这里安静地等
			down = 0
		case casdoorDown(err):
			if down *= 2; down == 0 {
				down = s.queue.downFirst
			}
			if down > s.queue.downMax {
				down = s.queue.downMax
			}
			wait = down
			logger.Warn("回读 Casdoor 失败（不可达），投递留在队列里，稍后重试", "error", err, "retry_in", wait)
		default:
			down = 0
			logger.Warn("处理 webhook 投递队列失败，稍后重试", "error", err, "retry_in", wait)
		}
		wake := s.wake
		if down > 0 {
			wake = nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-time.After(wait):
		}
	}
}

// wakeLoop 通知本进程的处理循环有新投递（非阻塞：已经有一个待处理的通知就够了）。
func (s *Service) wakeLoop() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
