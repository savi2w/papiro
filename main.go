package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/savi2w/papiro/aes"
	"github.com/savi2w/papiro/shred"
	"github.com/savi2w/papiro/util"
	"golang.org/x/term"
)

const EncryptMode = "ENCRYPT"
const FileExtension = ".papiro.enc"
const DecryptMode = "DECRYPT"
const FileMode = 0644

func main() {
	if len(os.Args) != 2 {
		fmt.Println("⛔ You need to provide a file path")
		return
	}

	file := os.Args[1]

	bytes, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("⛔ Error reading file\n%s\n", err.Error())
		return
	}

	if len(bytes) > 128*1024*1024 {
		fmt.Println("⛔ File is too large") // If you want to encrypt large files open a PR using a streaming approach
		return
	}

	mode := EncryptMode
	if strings.HasSuffix(file, FileExtension) {
		mode = DecryptMode

		fmt.Printf("🔓 Your file will be decrypted\n\n")
	} else {
		fmt.Printf("🔒 Your file will be encrypted\n\n")
	}

	fmt.Println("👉 Enter the AES-256-GCM password...")

	open := os.Stdin.Fd()
	password, err := term.ReadPassword(int(open))
	if err != nil {
		fmt.Printf("⛔ Error reading password\n%s\n", err.Error())
		return
	}

	if mode == EncryptMode {
		strong := util.StrongPassword(string(password))

		if !strong {
			fmt.Println("⛔ Password must be at least 20 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
			return
		}

		fmt.Println("👉 Confirm the AES-256-GCM password...")

		confirm, err := term.ReadPassword(int(open))
		if err != nil {
			fmt.Printf("⛔ Error reading password\n%s\n", err.Error())
			return
		}

		if string(password) != string(confirm) {
			fmt.Println("⛔ Passwords do not match")
			return
		}
	}

	switch mode {
	case EncryptMode:
		cipher, err := aes.Encrypt(bytes, password)
		if err != nil {
			fmt.Printf("⛔ Error encrypting file\n%s\n", err.Error())
			return
		}

		if err := os.WriteFile(file+FileExtension, cipher, FileMode); err != nil {
			fmt.Printf("⛔ Error writing encrypted file\n%s\n", err.Error())
			return
		}

		fmt.Println("🔨 Shredding original file, this can take a few seconds...")

		if err := shred.SevenPass(file); err != nil {
			fmt.Printf("⛔ Error shredding original file\n%s\n", err.Error())
			return
		}

		if err := os.Remove(file); err != nil {
			fmt.Printf("⛔ Error removing original file\n%s\n", err.Error())
			return
		}

		fmt.Println("✨ File encrypted successfully!")
	case DecryptMode:
		plain, err := aes.Decrypt(bytes, password)
		if err != nil {
			if strings.Contains(err.Error(), "message authentication") {
				fmt.Println("⛔ Invalid file or password")
				return
			}

			fmt.Printf("⛔ Error decrypting file\n%s\n", err.Error())
			return
		}

		if err := os.WriteFile(strings.TrimSuffix(file, FileExtension), plain, FileMode); err != nil {
			fmt.Printf("⛔ Error writing decrypted file\n%s\n", err.Error())
			return
		}

		if err := os.Remove(file); err != nil {
			fmt.Printf("⛔ Error removing encrypted file\n%s\n", err.Error())
			return
		}

		fmt.Println("✨ File decrypted successfully!")
	default:
		fmt.Printf("⛔ Invalid mode `%s`\n", mode)
		return
	}
}
