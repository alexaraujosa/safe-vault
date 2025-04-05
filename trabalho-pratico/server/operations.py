import os
import datetime
from exceptions import (
    PermissionDenied,
    GroupNotFound,
    UserNotFound,
    InvalidPermission,
    UserNotMemberOfGroup,
    FileNotFound,
    GroupAlreadyExists
)


###
# Auxiliary Functions
###

def is_valid_permission(permissions: str) -> bool:
    "Check if the given permissions are valid, i.e., 'r', 'w', or 'rw'."
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

    def create_group(self,
                     current_user_id: str,
                     group_name: str):
        # Check if the group already exists
        if group_name in self.config["groups"]:
            raise GroupAlreadyExists(group_name)

        # Create the group
        self.config["groups"][group_name] = {
            "owner": current_user_id,
            "created_at": get_current_timestamp(),
            "moderators": [],
            "members": {},
            "files": []
        }

    def delete_group(self,
                     current_user_id: str,
                     group_id: str) -> None:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user is the owner of the group
        if self.config["groups"][group_id]["owner"] != current_user_id:
            raise PermissionDenied(f"User {current_user_id} is not the owner of group {group_id}.")

        # Delete the group
        del self.config["groups"][group_id]

        # TODO Delete the group files?

    def add_user_to_group(self,
                          current_user_id: str,
                          group_id: str,
                          user_id: str,
                          permissions: str) -> None:
        # Check if the permissions are valid
        permissions = permissions.lower()
        if not is_valid_permission(permissions):
            raise InvalidPermission(permissions)

        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

        # Check if current user is the owner or moderator of the group
        if not (current_user_id == self.config["groups"][group_id]["owner"] or
                current_user_id not in self.config["groups"][group_id]["moderators"]):
            raise PermissionDenied(f"User {current_user_id} is not the owner or "
                                   f"moderator of group {group_id}.")

        # Check if the user is already in the group
        if user_id in self.config["groups"][group_id]["members"]:
            print(f"User {user_id} is already in group {group_id}.\n"
                  f"Updating permissions to {permissions}.")

        # Add the user to the group with the given permissions
        self.config["groups"][group_id]["members"][user_id] = permissions

        # Add the group to the user's groups
        self.config["users"][user_id]["groups"].append(group_id)

    def remove_user_from_group(self,
                               current_user_id: str,
                               group_id: str,
                               user_id: str) -> None:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

        # Check if current user is the owner or moderator of the group
        if not (current_user_id == self.config["groups"][group_id]["owner"] or
                current_user_id not in self.config["groups"][group_id]["moderators"]):
            raise PermissionDenied(f"User {current_user_id} is not the owner or "
                                   f"moderator of group {group_id}.")

        # Check if the user is not in the group
        if user_id not in self.config["groups"][group_id]["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

        # Remove the user from the group
        del self.config["groups"][group_id]["members"][user_id]

        # Remove the group from the user's groups
        self.config["users"][user_id]["groups"].remove(group_id)

        # TODO remove file permissions for the user removed?

    def list_user_groups(self, current_user_id: str) -> dict:
        # Get the user's groups
        user_groups = self.config["users"][current_user_id]["groups"]

        # Get the permissions for each group
        groups = {}
        for group_id in user_groups:
            groups[group_id] = self.config["groups"][group_id]["members"][current_user_id]

        return groups

    def add_file_to_group(self,
                          current_user_id: str,
                          group_id: str,
                          file_path: str) -> str:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the file exists
        if not os.path.exists(file_path):
            raise FileNotFound(file_path)

        # Check if the user can write to the group
        # (aka the owner, moderator or a member with write permissions)
        group = self.config["groups"][group_id]
        if not (current_user_id == group["owner"] or
                current_user_id in group["moderators"] or
                (current_user_id in group["members"] and
                 group["members"][current_user_id] == "w")):
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to write to group {group_id}.")

        # INFO não seria mais fácil confirmar aqui se o user já tem um ficheiro com esse nome?
        # Assim evitávamos a separação dos files por users e por groups

        # TODO Check if the file is already in the group

        # TODO Add file to the vault (files > groups > group_id > file_id)

        # TODO Add the file to the group
        # self.config["groups"][group_id]["files"].append(file_id)

        # TODO return the new file id: group_id:file_id

    # TODO Moderator Operations

    ###
    # File Operations TODO
    ###
