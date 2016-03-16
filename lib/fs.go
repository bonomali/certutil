package fs

import (
  "os"
  "io"
  "log"
)

func ReadFile (file string) []bytes {
  f, err := os.Open(file)
  if err != nil {
    log.Fatalf("Failed to open file: %s", err)
  }
  defer f.Close()

  // Create a buffer to keep chunks that are read
  buffer := make([]byte, 1024)
  for {
    n, err := file.Read(buffer)
    if err != nil && err != io.EOF { panic(err) }
    if n == 0 { break }
    return buffer[:n]
  }
}
