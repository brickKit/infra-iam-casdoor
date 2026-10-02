package main

import (
	besdk "github.com/brickKit/be-sdk-go"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/module"
)

// ⚠️ 这个文件永远只有这一行：单跑与进外壳走同一个 module.New，装配逻辑一旦写在
// main 里，进外壳后就没有了。
func main() { besdk.RunStandalone(module.New) }
