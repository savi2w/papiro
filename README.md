# Papiro

Papiro is a CLI tool for encrypting some of my most personal files. It uses AES-256-GCM + PBKDF2 and 102.400 iterations to ensure a solid encryption.

## Installation

1. Make sure you have `$HOME/go/bin` in your `$PATH`
2. Run `go install github.com/savi2w/papiro@v0.1.0`

## Usage

```bash
$ papiro FILE...
```

## License

This project is distributed under the [MIT license](LICENSE).
