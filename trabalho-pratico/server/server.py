#!/usr/bin/env python3

from config import Config
from operations import Operations


CONFIG_PATH = "config.json"
VALUT_PATH = "vault"


def main():
    # Load the JSON config file
    config = Config(CONFIG_PATH)

    # Initalize server operations class
    operations = Operations(config.config, VALUT_PATH)


if __name__ == "__main__":
    main()
