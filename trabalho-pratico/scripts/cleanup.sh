#!/bin/sh

# Removes the default config, logs and vault files from the server directory.

# If the -f flag is passed don't ask for confirmation.
I_FLAG="-i"
while getopts "f" opt; do
    case $opt in
        f)
            I_FLAG=""
            ;;
        *)
            echo "Usage: $0 [-f]"
            exit 1
            ;;
    esac
done

# Run this script from the "trabalho-pratico" directory.
if [ "$(basename "$PWD")" != "trabalho-pratico" ]; then
    echo "Run this script from the root of the repository."
    exit 1
fi

# Execute function that prints the command
execute() {
    echo "$*"
    "$@"
}

# Remove the default config, logs and vault files from the server directory.
execute rm $I_FLAG server/*.json
execute rm $I_FLAG -r server/vault/
