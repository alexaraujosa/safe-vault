import json
from enum import Enum, auto

class Logs:
    def __init__(self, logs_path):
        self.logs_path = logs_path
        self.logs = {}

        try:
            # Load the logs file
            self.load()
        except FileNotFoundError:
            print(f"Log file not found at {self.logs_path}. Initializing a new one.")
            # If the file does not exist, create a new log file
            self.save({
                "users": {},
                "groups": {},
            })
        except Exception as e:
            print(f"Error initializing log file: {e}")

    def save(self, logs=None):
        # Save logs to the file
        if logs is None:
            logs = self.logs

        with open(self.logs_path, 'w', encoding='utf-8') as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)

        # Update current logs
        self.logs = logs

    def load(self):
        # Load logs from the file
        with open(self.logs_path, 'r', encoding='utf-8') as f:
            self.logs = json.load(f)

        n_users  = len(self.logs.get('users', []))
        n_groups = len(self.logs.get('groups', []))
        print(f"Loaded {n_users} user{'s' if n_users != 1 else ''} and "
              f"{n_groups} group{'s' if n_groups != 1 else ''} logs entries from {self.logs_path}")

    def __str__(self):
        return json.dumps(self.logs, ensure_ascii=False, indent=4)
