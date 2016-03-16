package trust

import (
  "github.com/codegangsta/cli"
)

func NewTrustCertificate () cli.Command {
  return cli.Command{
    Name: "trust",
    Aliases: []string{"t"},
    Usage: "Add a certificate to the trusted root keychain.",
    Flags: []cli.Flag{
      cli.StringFlag{
        Name: "user, u",
        Usage: "Only apply the trust to the current user. Apply to everyone if this is not specified (default).",
      },
    },
    Action: MakeTrust,
  }
}

func MakeTrust (c *cli.Context) {
  println("Trust something. Try the first argument for the path to the cert.")
}
