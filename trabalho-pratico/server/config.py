import json


class Config:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = {}

        try:
            # Load the configuration file
            self.load()
        except FileNotFoundError:
            # If the file does not exist, create a new config
            self.save({
                "users": {},
                "groups": {},
                "files": {
                    "users": {},
                    "groups": {},
                }
            })
        except Exception as e:
            print(f"Error initializing config: {e}")

    def save(self, config=None):
        # Save the configuration to the file
        if config is None:
            config = self.config

        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=4)

        # Update the current config
        self.config = config

    def load(self):
        # Load the configuration from the file
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)

    def __str__(self):
        return json.dumps(self.config, indent=4, ensure_ascii=False)
