import os
import datetime


###
# Auxiliary Functions
###

def is_valid_permission(permissions: str) -> bool:
    valid_permissions = ["r", "w", "rw"]
    return permissions in valid_permissions


def get_current_timestamp() -> str:
    "Get the current timestamp in ISO 8601 format."
    return datetime.datetime.now().isoformat()


###
# Operations Class
###

class Operations:
    def __init__(self, config: dict, vault_path: str):
        self.config = config
        self.vault_path = vault_path

        # Create vault directory if it doesn't exist
        if not os.path.exists(vault_path):
            os.mkdir(vault_path, 0o700)

    ###
    # User Operations TODO
    ###

    ###
    # Group Operations
    ###

    def create_group(self, group_name: str, user_id: str):
        # Check if the group already exists
        if group_name in self.config["groups"]:
            raise ValueError(f"Group {group_name} already exists.")

        # Create the group
        self.config["groups"][group_name] = {
            "owner": user_id,
            "created_at": get_current_timestamp(),
            "moderators": [],
            "members": {},
            "own_files": []
        }

    def delete_group(self, group_id: str):
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise ValueError(f"Group {group_id} does not exist.")

        # TODO check if the user is the owner of the group

        # Delete the group
        del self.config["groups"][group_id]

    def add_user_to_group(self, user_id: str, group_id: str, permissions: str):
        # Check if the permissions are valid
        permissions = permissions.lower()
        if not is_valid_permission(permissions):
            raise ValueError(f"Invalid permissions: {permissions}.\n"
                             "Valid permissions are: r, w, rw.")

        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise ValueError(f"Group {group_id} does not exist.")

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise ValueError(f"User {user_id} does not exist.")

        # TODO Check if user adding is the owner or moderator of the group

        # Check if the user is already in the group
        if user_id in self.config["groups"][group_id]["members"]:
            print(f"User {user_id} is already in group {group_id}.\n"
                  f"Updating permissions to {permissions}.")

        # Add the user to the group with the given permissions
        self.config["groups"][group_id]["members"][user_id] = permissions

        # Add the group to the user's groups
        self.config["users"][user_id]["groups"].append(group_id)

    def remove_user_from_group(self, group_id: str, user_id: str):
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise ValueError(f"Group {group_id} does not exist.")

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise ValueError(f"User {user_id} does not exist.")

        # Check if the user is not in the group
        if user_id not in self.config["groups"][group_id]["members"]:
            raise ValueError(f"User {user_id} is not in group {group_id}.")

        # TODO Check if user removing is the owner or moderator of the group

        # Remove the user from the group
        del self.config["groups"][group_id]["members"][user_id]

        # Remove the group from the user's groups
        self.config["users"][user_id]["groups"].remove(group_id)

    def list_user_groups(self, user_id: str) -> dict:
        # Check if the user exists
        if user_id not in self.config["users"]:
            raise ValueError(f"User {user_id} does not exist.")

        # Get the user's groups
        user_groups = self.config["users"][user_id]["groups"]

        # Get the permissions for each group
        groups_permissions = {}
        for group_id in user_groups:
            groups_permissions[group_id] = self.config["groups"][group_id]["members"][user_id]

        return groups_permissions

    # TODO: add_file_to_group securely
    def add_file_to_group(self, group_id: str, file_id: str):
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise ValueError(f"Group {group_id} does not exist.")

        # Check if the file exists
        if file_id not in self.config["files"]:
            raise ValueError(f"File {file_id} does not exist.")

        # TODO check if the user has permission to read the file
        # TODO check if user has permision to add files to the group
        # TODO remove the ownership of the file from the user and pass it to the group

        # Add the file to the group
        self.config["groups"][group_id]["own_files"].append(file_id)

        # TODO return the new file id: group_id:file_id

    # TODO Moderator Operations

    ###
    # File Operations TODO
    ###
