package main

import (
  "os"
  "github.com/codegangsta/cli"
  "./lib/cmd"
  "./lib/cmd/trust"
  // "net"
  // "log"
  // "encoding/json"
  // "os/user"
  // "runtime"
  // "./lib/os"
)

// type Environment struct {
//   mac       string
//   user      string
//   host      string
//   os        string
//   osversion string
//   cpus      int
// }

func main() {
  app := cli.NewApp()
  app.Name = "certutil"
  app.Usage = "localhost certificate manager."
  app.Version = "0.0.1"
  app.Author = "Author.io"

  // app.Flags = []cli.Flag {
  //   cli.StringFlag{
  //     Name: "expires, e",
  //     Value: "3650",
  //     Usage: "Expiration in number of days.",
  //   },
  //   cli.StringFlag{
  //     Name: "ca",
  //     Value: "false",
  //     Usage: "Expiration in number of days.",
  //   },
  // }

  app.Commands = []cli.Command{
    cmd.NewCertificate(),
    trust.NewTrustCertificate(),
    {
      Name: "untrust",
      Aliases: []string{"u"},
      Usage: "Remove certificate from the trusted root keychain.",
      Action: func(c *cli.Context) {
        println("untrusted certificate: ", c.Args().First())
      },
    },
  }

  // app.Action = func(c *cli.Context) {
  //   name := "none"
  //   if c.NArg() > 0 {
  //     cmd = c.Args()[0]
  //   }
  //   if cmd = "create"
  //   if c.String("lang") == "spanish" {
  //     println("Hola", name)
  //   } else {
  //     println("Hello", name)
  //   }
  // }

  app.Run(os.Args)

  // args := os.Args

  // Get the network interfaces
  // ifs, err := net.Interfaces()
  // if err != nil {
  //   fmt.Println(err)
  // }

  // Acquire MAC Address
  // var macaddr string
  // for _, inf := range ifs {
  //   // fmt.Println(inf.Name)
  //   if inf.HardwareAddr != nil && (inf.Name == "eth0" || inf.Name == "en0") {
  //     macaddr = inf.HardwareAddr.String()
  //     break
  //   }
  // }

  // Acquire the current user
  // user, err := user.Current()
  // if err != nil {
  //   fmt.Println(err)
  // }

	// osv, err := osversion.GetSemanticVersion()
	// if err != nil {
	// 	log.Fatalf("Error getting OS version: %v", err)
	// }

	// osname, err := osversion.GetHumanReadable()
	// if err != nil {
	// 	log.Fatalf("Error getting OS version: %v", err)
	// }


  // env := Environment{
  //   user: user.Username,
  //   mac: macaddr,
  //   host: host,
  //   os: osname,
  //   osversion: osv.String(),
  //   cpus: runtime.NumCPU(),
  // }
  //
  // payload, err := json.Marshal(env)
  // if err != nil {
	// 	log.Fatalf("Error generating JSON: %v", err)
	// }
  // fmt.Println(payload)
  // fmt.Println(macaddr)
  // env2 := os.Environ()
  // fmt.Println(env2)

}
