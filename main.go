// Command infra-iam-casdoor runs the identity member alone (serve, migrate); the shells compile in iam.Definition().
package main

import (
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/infra-iam-casdoor/v3/iam"
)

func main() { launcher.Main(iam.Definition()) }
