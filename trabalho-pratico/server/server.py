#!/usr/bin/env python3

from config import Config
from operations import Operations


CONFIG_PATH = "config.json"
VAULT_PATH = "vault"


def main():
    # Load the JSON config file
    config = Config(CONFIG_PATH)

    # Initalize server operations class
    operations = Operations(config.config, VAULT_PATH)

    # Save the config file
    config.save(config=operations.config)


if __name__ == "__main__":
    main()
