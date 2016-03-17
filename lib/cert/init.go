package cert

import (
  "time"
  "net"
  // "os"
  // "encoding/gob"
  "io/ioutil"
  "encoding/pem"
  // "encoding/base64"
  "math/big"
  "fmt"
  "log"
  "crypto/x509"
  "crypto/x509/pkix"
  "crypto/rsa"
  "crypto/rand"
)

type CSR struct {
  CA bool
  Passphrase string
  Size int
  Days int
  Key *rsa.PrivateKey
  CN string // Common Name
  O string // Org
  OU string // Org Unity
  C string // Country
  S string // State/Province
  L string // Locality
  Domains []string // Domains (Comma-separated)
  Email []string // Email Address of Admin
  SignCert string // Path to signing certificate
  SignKey string // Path to signing key
}

func CreatePrivateKey(bit int) *rsa.PrivateKey {
  privatekey, err := rsa.GenerateKey(rand.Reader, bit)
  if err != nil {
    fmt.Println(err)
  }
  return privatekey
}

func Make(csr CSR) (certificate []byte, privatekey []byte) {
  // SerialNumber, Subject, NotBefore, NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid, IsCA, MaxPathLen, SubjectKeyId, DNSNames, PermittedDNSDomainsCritical, PermittedDNSDomains, SignatureAlgorithm
  serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
  serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
  if err != nil {
    log.Fatalf("failed to generate serial number: %s", err)
  }

  template := x509.Certificate{
    BasicConstraintsValid : true,
    // SubjectKeyId : []byte{1,2,3},
    SerialNumber : serialNumber,
    Subject : pkix.Name{
      Country : []string{csr.C},
      Province: []string{csr.S},
      Locality: []string{csr.L},
      Organization: []string{csr.O},
      OrganizationalUnit: []string{csr.OU},
      CommonName: csr.CN,
    },
    NotBefore : time.Now(),
    NotAfter : time.Now().AddDate(0, 0, csr.Days),
    KeyUsage : x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
    ExtKeyUsage : []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
  }

  // Extract IP addresses from SAN list
  var ip []net.IP
  var uri []string
  for _, dom := range csr.Domains {
    addr := net.ParseIP(dom)
    if addr != nil {
      ip = append(ip, addr)
    } else {
      uri = append(uri, dom)
    }
  }

  if len(ip) > 0 {
    template.IPAddresses = ip
  }
  if len(uri) > 0 {
    template.DNSNames = uri
  }

  // Add email addresses
  if len(csr.Email) > 0 {
    template.EmailAddresses = csr.Email
  }

  var raw []byte
  var privkey *rsa.PrivateKey
  if csr.CA {
    // Self Signed Cert
    template.IsCA = true
    template.KeyUsage |= x509.KeyUsageCertSign
    raw, err = x509.CreateCertificate(rand.Reader, &template, &template, &csr.Key.PublicKey, csr.Key)
    privkey = csr.Key
  } else if csr.SignKey != "" {
    // CA Signed Cert
    template.IsCA = false
    parent := ReadCertificate(csr.SignCert)
    var parentkey *rsa.PrivateKey
    if len(csr.Passphrase) > 0 {
      println("Password detected")
      parentkey = ReadEncryptedPrivateKey(csr.SignKey, csr.Passphrase)
    } else {
      parentkey = ReadPrivateKey(csr.SignKey)
    }
    privatekey := CreatePrivateKey(csr.Size | 2048)
    raw, err = x509.CreateCertificate(rand.Reader, &template, parent, &privatekey.PublicKey, parentkey)
    privkey = privatekey
  }

  if err != nil {
    log.Fatalf("Failed to create certificate: %s", err)
  }

  // Optionally encrypt the private key
  var block *pem.Block
  if csr.Passphrase != "" {
    var privkey *rsa.PrivateKey
    block, err = x509.EncryptPEMBlock(rand.Reader,
      "ENCRYPTED PRIVATE KEY",
      x509.MarshalPKCS1PrivateKey(privkey),
      []byte(csr.Passphrase),
      x509.PEMCipherAES256)
    if err != nil {
      log.Fatalf("Failed to encrypt private key: %s", err)
    }
  } else {
    block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privkey)}
  }

  // Generate the PEM content for the certificate and private key
  crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
  pk := pem.EncodeToMemory(block)

  return crt, pk
}

func ReadCertificate(file string) (certificate *x509.Certificate) {
  raw, err := ioutil.ReadFile(file)
  if err != nil {
    log.Fatalf("Failed to read certificate: %s", err)
  }
  block, _ := pem.Decode(raw)
  crt, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    log.Fatalf("Failed to parse certificate: %s", err)
  }
  return crt
}

func ReadPrivateKey(file string) (key *rsa.PrivateKey) {
  raw, err := ioutil.ReadFile(file)
  if err != nil {
    log.Fatalf("Failed to read private key: %s", err)
  }

  pemBlock, _ := pem.Decode(raw)
  pk, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
  if err != nil {
    log.Fatalf("Failed to parse private key: %s", err)
  }

  return pk
}

func ReadEncryptedPrivateKey(file string, secret string) (key *rsa.PrivateKey) {
  raw, err := ioutil.ReadFile(file)
  if err != nil {
    log.Fatalf("Failed to read private key: %s", err)
  }

  block, _ := pem.Decode(raw)
  println("Yo")
fmt.Print(secret)
  der, err := x509.DecryptPEMBlock(block, []byte(secret))
  if err != nil {
    log.Fatalf("Failed to decrypt private key: %s", err)
  }

  parsedkey, err := x509.ParsePKCS1PrivateKey(der)
  if err != nil {
    log.Fatalf("Invalid private key: ", err)
  }

  return parsedkey
}

func ReadPublicKey(file string) (pub interface{}) {
  raw, err := ioutil.ReadFile(file)
  if err != nil {
    log.Fatalf("Failed to read public key: %s", err)
  }
  pubkey, err := x509.ParsePKCS1PrivateKey(raw)
  if err != nil {
    log.Fatalf("Failed to parse public key: %s", err)
  }
  return pubkey
}

// func Make() {
//
// }
//
// func main() {
//
//    // ok, lets populate the certificate with some data
//    // not all fields in Certificate will be populated
//    // see Certificate structure at
//    // http://golang.org/pkg/crypto/x509/#Certificate
//    template := &x509.Certificate {
//             IsCA : true,
//             BasicConstraintsValid : true,
//             SubjectKeyId : []byte{1,2,3},
//             SerialNumber : big.NewInt(1234),
//             Subject : pkix.Name{
//                       Country : []string{"Earth"},
//                       Organization: []string{"Mother Nature"},
//             },
//             NotBefore : time.Now(),
//             NotAfter : time.Now().AddDate(5,5,5),
//             // see http://golang.org/pkg/crypto/x509/#KeyUsage
//             ExtKeyUsage : []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
//             KeyUsage : x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
//    }
//
//    // generate private key
//    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
//
//    if err != nil {
//      fmt.Println(err)
//    }
//
//    publickey := &privatekey.PublicKey
//
//    // create a self-signed certificate. template = parent
//    var parent = template
//    cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey,privatekey)
//
//    if err != nil {
//       fmt.Println(err)
//    }
//
//    // save private key
//    pkey := x509.MarshalPKCS1PrivateKey(privatekey)
//    ioutil.WriteFile("private.key", pkey, 0777)
//    fmt.Println("private key saved to private.key")
//
//    // save public key
//    pubkey, _ := x509.MarshalPKIXPublicKey(publickey)
//    ioutil.WriteFile("public.key", pubkey, 0777)
//    fmt.Println("public key saved to public.key")
//
//    // save cert
//    ioutil.WriteFile("cert.pem", cert, 0777)
//    fmt.Println("certificate saved to cert.pem")
//
//
//    // these are the files save with encoding/gob style
//    privkeyfile, _ := os.Create("privategob.key")
//    privkeyencoder := gob.NewEncoder(privkeyfile)
//    privkeyencoder.Encode(privatekey)
//    privkeyfile.Close()
//
//    pubkeyfile, _ := os.Create("publickgob.key")
//    pubkeyencoder := gob.NewEncoder(pubkeyfile)
//    pubkeyencoder.Encode(publickey)
//    pubkeyfile.Close()
//
//    // this will create plain text PEM file.
//    pemfile, _ := os.Create("certpem.pem")
//    var pemkey = &pem.Block{
//                 Type : "RSA PRIVATE KEY",
//                 Bytes : x509.MarshalPKCS1PrivateKey(privatekey)}
//    pem.Encode(pemfile, pemkey)
//    pemfile.Close()
//
// }
