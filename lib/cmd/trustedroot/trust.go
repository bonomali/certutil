package trustedroot

import (
  "log"
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
        Usage: "Only apply the trust to the current user. Applies to everyone if this is not specified (default).",
      },
    },
    Action: Trust,
  }
}

func NewUntrustCertificate () cli.Command {
  return cli.Command{
    Name: "untrust",
    Aliases: []string{"u"},
    Usage: "Remove a certificate from the trusted root keychain.",
    Flags: []cli.Flag{
      cli.StringFlag{
        Name: "user, u",
        Usage: "Only remove the trust from the current user. Applies to everyone if this is not specified (default).",
      },
    },
    Action: Untrust,
  }
}

func Trust (c *cli.Context) {
  certificate := c.Args()[0]
  var err error
  if c.IsSet("user") {
    err = AddUserKeychainTrust(certificate)
  } else {
    err = AddSystemKeychainTrust(certificate)
  }
  if err != nil {
    log.Fatalf("Error creating trust: %s", err)
  }
}

func Untrust (c *cli.Context) {
  println("Stop trusting that bastard.")
}
