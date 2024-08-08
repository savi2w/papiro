package util

import "unicode"

func StrongPassword(str string) bool {
	length := false
	uppercase := false
	lowercase := false
	number := false
	special := false

	if len(str) >= 20 {
		length = true
	}

	for _, char := range str {
		switch {
		case unicode.IsUpper(char):
			uppercase = true
		case unicode.IsLower(char):
			lowercase = true
		case unicode.IsNumber(char):
			number = true
		case unicode.IsPunct(char):
			special = true
		case unicode.IsSymbol(char):
			special = true
		}
	}

	criteria := []bool{length, uppercase, lowercase, number, special}
	for _, criterion := range criteria {
		if !criterion {
			return false
		}
	}

	return true
}
