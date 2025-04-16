#!/usr/bin/env python3

import sys
import shlex
import readline

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
    if len(sys.argv) != 3:
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
        # TODO Process command and send packet to server

    print("\nExiting...")
    readline.write_history_file(HISTORY_FILE)


if __name__ == "__main__":
    main()
