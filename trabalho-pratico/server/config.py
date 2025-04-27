import json


class Config:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = {}

        try:
            # Load the configuration file
            self.load()
        except FileNotFoundError:
            print(f"Config file not found at {self.config_path}. Initializing a new config.")
            # If the file does not exist, create a new config
            self.save({
                "users": {},
                "groups": {},
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

        n_users  = len(self.config.get('users', []))
        n_groups = len(self.config.get('groups', []))
        print(f"Loaded {n_users} user{'s' if n_users > 1 else ''} and "
              f"{n_groups} group{'s' if n_groups > 1 else ''} from {self.config_path}")

    def __str__(self):
        return json.dumps(self.config, ensure_ascii=False, indent=4)
