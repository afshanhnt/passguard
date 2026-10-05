# 🔐 PassGuard

A Python command-line toolkit for password security: **check** how strong a password is, **generate** secure passwords and passphrases, and **store** credentials in an **AES-256 encrypted vault**.

Built as a hands-on project to learn applied cryptography and secure-coding practices.

## Features

| Feature | What it does |
|---|---|
| Strength checker | Estimates entropy, flags common passwords, sequences (`abcd`, `qwer`) and repeats |
| Generator | Uses Python's `secrets` (CSPRNG), never `random`, for passwords and passphrases |
| Encrypted vault | AES-256-GCM encryption, scrypt key derivation, tamper detection |

## Security design

- **Key derivation:** scrypt (memory-hard, resists GPU brute-forcing) turns the master password into a 256-bit key. Never store or reuse the password directly as a key.
- **Authenticated encryption:** AES-GCM encrypts *and* verifies integrity, so a modified vault file is rejected.
- **Unique salt and nonce:** a random 16-byte salt per vault and a fresh 12-byte nonce on every save. Reusing a nonce with GCM would be catastrophic.
- **No secrets in shell history:** passwords are read with `getpass`, not command arguments.
- **File permissions:** the vault is created with `0600` (owner only).

## Install

```bash
git clone https://github.com/afshanhnt/passguard.git
cd passguard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
# Check a password
python -m passguard check

# Generate
python -m passguard generate -l 20          # random password
python -m passguard generate --passphrase   # e.g. mirror-flint-falcon-orbit-olive

# Vault
python -m passguard vault init
python -m passguard vault add github -u alice
python -m passguard vault get github
python -m passguard vault list
python -m passguard vault delete github
```

## Run the tests

```bash
pytest -v
```

## Project structure

```
passguard/
├── passguard/
│   ├── strength.py     # entropy + pattern analysis
│   ├── generator.py    # secure generation
│   ├── vault.py        # scrypt + AES-GCM vault
│   └── cli.py          # argparse interface
└── tests/
```

## Limitations and future work

- Entropy is an estimate; real attackers use dictionaries and rule-based cracking (consider integrating `zxcvbn`).
- Add a clipboard auto-clear after `vault get`.
- Check passwords against the Have I Been Pwned API using k-anonymity.
- Replace the demo wordlist with the EFF large wordlist.
- Add a simple GUI or a Flask web version.

## Disclaimer

Educational project. For real-world secrets, use an audited password manager.

## License

MIT
