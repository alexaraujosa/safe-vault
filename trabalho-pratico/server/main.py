#!/usr/bin/env python3

from server.config     import Config
from server.operations import Operations
from common.exceptions import (
    # UserNotFound,
    UserExists,
)


CONFIG_PATH = "server/config.json"
VAULT_PATH = "server/vault"


def main():
    # Load the JSON config file
    config = Config(CONFIG_PATH)

    # Initalize server operations class
    operations = Operations(config.config, VAULT_PATH)

    # Examples
    try:
        operations.create_user("user1")
    except UserExists as e:
        print(e.message)

    operations.add_file_to_user("user1", "file1.txt", b"Hello, world!", "1")
    operations.delete_user("user1")

    # Save the config file
    config.save(config=operations.config)


if __name__ == "__main__":
    main()
