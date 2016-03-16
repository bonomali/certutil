package trust

import (
  "bytes"
  "fmt"
  "log"
	"os/exec"
)

// Add a certificate to the system trust root.
// add-trusted-cert = Add certificate (in DER or PEM format) from certFile to per-user or local Admin Trust Settings.
// -d = Add this certificate to admin certificate store; default is to store it in the user’s keychain.
// -r = Specifies the result you want, in this case you want to use trustRoot (see the security man page for the other options.)
// -k = Specifies the keychain to use, in this case the specified keychain is /Library/Keychains/System.keychain
func AddSystemKeychainTrust(certificate string) error {
  var _stdout bytes.Buffer
  var _stderr bytes.Buffer
  cmd := exec.Command("security", "add-trusted-cert", "-d", "-r trustRoot", "-k '/Library/Keychains/System.keychain'", certificate)
  cmd.Stdout = &output
  cmd.Stderr = &_stderr
  err := cmd.Run()
  if err != nil {
    fmt.Println(_stderr.String())
    return err
  }
  return nil
}

func AddUserKeychainTrust(certificate string) error {
  var _stdout bytes.Buffer
  var _stderr bytes.Buffer
  cmd := exec.Command("security", "add-trusted-cert", "-r trustRoot", "-k '/Library/Keychains/System.keychain'", certificate)
  cmd.Stdout = &output
  cmd.Stderr = &_stderr
  err := cmd.Run()
  if err != nil {
    fmt.Println(_stderr.String())
    return err
  }
  return nil
}

func RemoveSystemKeychainTrust(certificate string) error {
  var _stdout bytes.Buffer
  var _stderr bytes.Buffer
  cmd := exec.Command("security", "remove-trusted-cert", "-d", certificate)
  cmd.Stdout = &output
  cmd.Stderr = &_stderr
  err := cmd.Run()
  if err != nil {
    fmt.Println(_stderr.String())
    return err
  }
  return nil
}

func RemoveUserKeychainTrust(certificate string) error {
  var _stdout bytes.Buffer
  var _stderr bytes.Buffer
  cmd := exec.Command("security", "remove-trusted-cert", certificate)
  cmd.Stdout = &output
  cmd.Stderr = &_stderr
  err := cmd.Run()
  if err != nil {
    fmt.Println(_stderr.String())
    return err
  }
  return nil
}
