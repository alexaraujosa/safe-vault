import json
from enum import Enum, auto
from server.operations import get_current_timestamp


class Status(Enum):
    SUCCESS = auto()
    FAILURE = auto()


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
              f"{n_groups} group{'s' if n_groups != 1 else ''} logs from {self.logs_path}")

    def __str__(self):
        return json.dumps(self.logs, ensure_ascii=False, indent=4)

    # User logs
    def add_user_entry(self,
                       user_id: str,
                       command: str,
                       success: bool,
                       file_id: str = None,
                       group_id: str = None,
                       executor_id: str = None) -> None:
        log_entry = {
            "executor": executor_id if executor_id else user_id,
            "time": get_current_timestamp(),
            "success": success,
            "command": command
        }

        if file_id is not None:
            log_entry["file_id"] = file_id

        if group_id is not None:
            log_entry["group_id"] = group_id

        if user_id not in self.logs["users"]:
            self.logs["users"][user_id] = []
        self.logs["users"][user_id].append(log_entry)

    def add_group_entry(self,
                        executor_id: str,
                        group_id: str,
                        command: str,
                        success: bool) -> None:
        log_entry = {
            "executor": executor_id,
            "time": get_current_timestamp(),
            "success": success,
            "command": command
        }

        if group_id not in self.logs["groups"]:
            self.logs["groups"][group_id] = []
        self.logs["groups"][group_id].append(log_entry)
