#!/usr/bin/env python3

import sys
import shlex
import readline

from common.validation import validate_params
from client.command import process_command

HISTORY_FILE = ".client_history"
HISTORY_SIZE = 100


def setup_readline():
    # Load command history
    try:
        readline.read_history_file(HISTORY_FILE)
    except FileNotFoundError:
        pass

    # Set history length
    readline.set_history_length(HISTORY_SIZE)

    # Readline configuration
    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind("set blink-matching-paren on")


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 -m client.main <CERT_FILE> <PKCS12_FILE> <HOST:PORT>")
        sys.exit(1)

    # TODO Start connection with server

    setup_readline()

    while True:
        try:
            command = input("> ").strip()
            if not command:
                continue
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            break

        args = shlex.split(command)
        print(f"Arguments: {args}")

        if args[0] == "exit":
            break

        try:
            packet = process_command(args)
            # TODO Encrypt packet
            # TODO Send encrypted packet to the server
            # TODO Receive response from the server
        except Exception as e:
            print(e)
            continue

    print("\nExiting...")
    readline.write_history_file(HISTORY_FILE)


if __name__ == "__main__":
    main()
