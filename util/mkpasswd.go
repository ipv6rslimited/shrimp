/*
**
** mkpasswd
** Make and edit passwords in a passwd file for shrimp
**
** Distributed under the COOL License.
**
** Copyright (c) 2024 IPv6.rs <https://ipv6.rs>
** All Rights Reserved
**
*/

package main

import (
  "bufio"
  "flag"
  "fmt"
  "os"
  "strings"
  "golang.org/x/crypto/bcrypt"
)

func main() {
  createFlag := flag.Bool("create", false, "Create a user and password")
  editFlag := flag.Bool("edit", false, "Edit an existing user's password")
  passwdFlag := flag.String("passwd", "passwd", "Path to passwords file")

  flag.Parse()

  if *createFlag || *editFlag {
    if len(flag.Args()) != 2 {
      usage()
    }

    username := flag.Arg(0)
    password := flag.Arg(1)
    passwdFile := *passwdFlag

    if *createFlag {
      createPassword(username, password, passwdFile)
    } else if *editFlag {
      editPassword(username, password, passwdFile)
    } else {
      usage()
    }
  } else {
    usage()
  }
}

func createPassword(username, password, passwdFile string) {
  if _, err := os.Stat(passwdFile); err == nil {
    if userExists(username, passwdFile) {
      fmt.Println("Error: User already exists.")
      os.Exit(1)
    }
  }

  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  if err != nil {
    fmt.Println("Error hashing password:", err)
    os.Exit(1)
  }

  file, err := os.OpenFile(passwdFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
  if err != nil {
    fmt.Println("Error opening passwd file:", err)
    os.Exit(1)
  }
  defer file.Close()

  if _, err = file.WriteString(fmt.Sprintf("%s:%s\n", username, hashedPassword)); err != nil {
    fmt.Println("Error writing to passwd file:", err)
    os.Exit(1)
  }
}

func editPassword(username, password, passwdFile string) {
  if !userExists(username, passwdFile) {
    fmt.Println("Error: User does not exist.")
    os.Exit(1)
  }

  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  if err != nil {
    fmt.Println("Error hashing password:", err)
    os.Exit(1)
  }

  lines, err := readPasswdFile(passwdFile)
  if err != nil {
    fmt.Println("Error reading passwd file:", err)
    os.Exit(1)
  }

  file, err := os.OpenFile(passwdFile, os.O_WRONLY|os.O_TRUNC, 0600)
  if err != nil {
    fmt.Println("Error opening passwd file:", err)
    os.Exit(1)
  }
  defer file.Close()

  for _, line := range lines {
    parts := strings.Split(line, ":")
    if parts[0] == username {
      line = fmt.Sprintf("%s:%s", username, hashedPassword)
    }
    if _, err = file.WriteString(line + "\n"); err != nil {
      fmt.Println("Error writing to passwd file:", err)
      os.Exit(1)
    }
  }
}

func userExists(username, passwdFile string) bool {
  file, err := os.Open(passwdFile)
  if err != nil {
    fmt.Println("Error opening passwd file:", err)
    os.Exit(1)
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    line := scanner.Text()
    parts := strings.Split(line, ":")
    if len(parts) != 2 {
      continue
    }
    if parts[0] == username {
      return true
    }
  }

  if err := scanner.Err(); err != nil {
    fmt.Println("Error reading passwd file:", err)
    os.Exit(1)
  }

  return false
}

func readPasswdFile(passwdFile string) ([]string, error) {
  file, err := os.Open(passwdFile)
  if err != nil {
    return nil, err
  }
  defer file.Close()

  var lines []string
  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    lines = append(lines, scanner.Text())
  }

  if err := scanner.Err(); err != nil {
    return nil, err
  }

  return lines, nil
}

func usage() {
  fmt.Println("Usage: mkpasswd -passwd <passwd file> -create <username> <password>")
  fmt.Println("       mkpasswd -passwd <passwd file> -edit <username> <password>")
  os.Exit(1)
}
