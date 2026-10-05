"""Command-line interface for PassGuard."""
import argparse
import getpass
import sys

from . import __version__
from .generator import generate_passphrase, generate_password
from .strength import analyze
from .vault import Vault, VaultError

DEFAULT_VAULT = "vault.pg"


def cmd_check(args):
    pw = args.password or getpass.getpass("Password to check: ")
    r = analyze(pw)
    print(f"Strength : {r.label} ({r.score}/4)")
    print(f"Entropy  : ~{r.entropy_bits} bits")
    for tip in r.feedback:
        print(f"  - {tip}")


def cmd_generate(args):
    if args.passphrase:
        print(generate_passphrase(args.words))
    else:
        print(generate_password(args.length, symbols=not args.no_symbols))


def cmd_vault(args):
    vault = Vault(args.file)
    try:
        if args.action == "init":
            master = getpass.getpass("Choose master password: ")
            if getpass.getpass("Confirm master password: ") != master:
                sys.exit("Passwords do not match.")
            result = analyze(master)
            if result.score < 2:
                print(f"Warning: master password is {result.label.lower()}.")
            vault.init(master)
            print(f"Vault created at {args.file}")
            return
        master = getpass.getpass("Master password: ")
        if args.action == "add":
            pw = getpass.getpass("Entry password (blank to generate): ") or generate_password(20)
            vault.add(master, args.name, args.username or "", pw)
            print(f"Saved '{args.name}'.")
        elif args.action == "get":
            e = vault.get(master, args.name)
            print(f"Username: {e['username']}\nPassword: {e['password']}")
        elif args.action == "list":
            names = vault.list_names(master)
            print("\n".join(names) if names else "(vault is empty)")
        elif args.action == "delete":
            vault.delete(master, args.name)
            print(f"Deleted '{args.name}'.")
    except VaultError as e:
        sys.exit(f"Error: {e}")


def build_parser():
    p = argparse.ArgumentParser(prog="passguard", description="Password toolkit")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="Analyze password strength")
    c.add_argument("password", nargs="?", help="Omit to be prompted securely")
    c.set_defaults(func=cmd_check)

    g = sub.add_parser("generate", help="Generate a password or passphrase")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("-p", "--passphrase", action="store_true")
    g.add_argument("-w", "--words", type=int, default=5)
    g.set_defaults(func=cmd_generate)

    v = sub.add_parser("vault", help="Encrypted password vault")
    v.add_argument("action", choices=["init", "add", "get", "list", "delete"])
    v.add_argument("name", nargs="?")
    v.add_argument("-u", "--username")
    v.add_argument("-f", "--file", default=DEFAULT_VAULT)
    v.set_defaults(func=cmd_vault)
    return p


def main():
    args = build_parser().parse_args()
    if args.command == "vault" and args.action in ("add", "get", "delete") and not args.name:
        sys.exit("Error: this action needs an entry name.")
    args.func(args)
