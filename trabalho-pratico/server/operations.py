import os
import datetime
from exceptions import (
    PermissionDenied,
    GroupNotFound,
    UserNotFound,
    InvalidPermissions,
    UserNotMemberOfGroup,
    UserNotModeratorOfGroup,
    GroupAlreadyExists
)


###
# Auxiliary Functions
###

def is_valid_permissions(permissions: str) -> bool:
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
                     group_name: str) -> str:
        # Check if the group already exists
        if group_name in self.config["groups"]:
            raise GroupAlreadyExists(group_name)

        # Create the group
        self.config["groups"][group_name] = {
            "owner": current_user_id,
            "created": get_current_timestamp(),
            "moderators": [],
            "members": {},
            "files": {}
        }

        return group_name  # group_id

    def delete_group(self,
                     current_user_id: str,
                     group_id: str) -> None:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user is the owner of the group
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]

        if not is_owner:
            raise PermissionDenied(f"User {current_user_id} is not the owner of group {group_id}.")

        # Delete the group from the user's own groups
        self.config["users"][current_user_id]["own_groups"].remove(group_id)

        # Delete the group from other user's groups
        users = self.config["users"]

        for group_member in group["members"]:
            if group_id in users[group_member]["groups"]:
                self.config["users"][group_member]["groups"].remove(group_id)

        # Delete the group from the user's moderator groups
        for group_moderator in group["moderators"]:
            if group_id in users[group_moderator]["moderator_groups"]:
                self.config["users"][group_moderator]["moderator_groups"].remove(group_id)

        # Delete the group
        del self.config["groups"][group_id]

    def add_user_to_group(self,
                          current_user_id: str,
                          group_id: str,
                          user_id: str,
                          permissions: str) -> None:
        # Check if the given permissions are valid
        permissions = permissions.lower()
        if not is_valid_permissions(permissions):
            raise InvalidPermissions(permissions)

        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

        # Check if current user is the owner or moderator of the group
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]
        is_moderator = current_user_id in group["moderators"]

        if not (is_owner or is_moderator):
            raise PermissionDenied(f"User {current_user_id} is not the owner or "
                                   f"moderator of group {group_id}.")

        # Check if the user is the owner of the group
        if user_id == group["owner"]:
            raise PermissionDenied(f"User {user_id} is the owner of group {group_id}.")

        # Check if the user is a moderator of the group
        if user_id in group["moderators"]:
            raise PermissionDenied(f"Cannot add user {user_id} as a member of group {group_id}.\n"
                                   f"User is already a moderator.")

        # Check if the user is already in the group
        if user_id in group["members"]:
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
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]
        is_moderator = current_user_id in group["moderators"]

        if not (is_owner or is_moderator):
            raise PermissionDenied(f"User {current_user_id} is not the owner or "
                                   f"moderator of group {group_id}.")

        # Check if the user is not a member of the group
        if user_id not in group["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

        # Check if the user is not the owner of the group
        if user_id == group["owner"]:
            raise PermissionDenied(f"User {user_id} is the owner of group {group_id}.")

        # Only allow the owner to remove other moderators
        if is_moderator and user_id in group["moderators"]:
            raise PermissionDenied("Only the owner can remove moderators.")

        # Remove the user from the group and the group from the user,
        # based on whether the user removed is a moderator or not
        if user_id in group["moderators"]:
            # Remove the user from the moderators list
            group["moderators"].remove(user_id)

            # Remove the group from the user's moderator groups
            self.config["users"][user_id]["moderator_groups"].remove(group_id)
        else:
            # Remove the user from the group
            del self.config["groups"][group_id]["members"][user_id]

            # Remove the group from the user's groups
            self.config["users"][user_id]["groups"].remove(group_id)

    def change_user_group_permissions(self,
                                      current_user_id: str,
                                      group_id: str,
                                      user_id: str,
                                      permissions: str) -> None:
        # Check if the given permissions are valid
        permissions = permissions.lower()
        if not is_valid_permissions(permissions):
            raise InvalidPermissions(permissions)

        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

        # Check if current user is the owner or moderator of the group
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]
        is_moderator = current_user_id in group["moderators"]

        if not (is_owner or is_moderator):
            raise PermissionDenied(f"User {current_user_id} is not the owner or "
                                   f"moderator of group {group_id}.")

        # Check if the user is a member of the group
        if user_id not in group["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

        # Change the user's permissions in the group
        self.config["groups"][group_id]["members"][user_id] = permissions

    def list_user_groups(self, current_user_id: str) -> dict:
        results = {
            "own_groups": [],
            "moderator_groups": [],
            "member_groups": {}
        }

        user_meta = self.config["users"][current_user_id]

        # Save the user's own groups
        results["own_groups"] = user_meta["own_groups"]

        # Save the user's moderator groups
        results["moderator_groups"] = user_meta["moderator_groups"]

        # Save the user's member groups with the respective permissions
        groups = self.config["groups"]
        for group_id in user_meta["groups"]:
            results["member_groups"][group_id] = {
                "permissions": groups[group_id]["members"][current_user_id],
            }

        return results

    def add_file_to_group(self,
                          current_user_id: str,
                          group_id: str,
                          file_name: str,
                          file_contents: bytes) -> str:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user can write to the group
        # (aka the owner, a moderator or a member with write permissions)
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]
        is_moderator = current_user_id in group["moderators"]
        is_member_with_write_permissions = current_user_id in group["members"] and \
            "w" in group["members"][current_user_id]

        if not (is_owner or is_moderator or is_member_with_write_permissions):
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to write to group {group_id}.")

        # Check if user already has a file with the same name
        user_files = self.config["users"][current_user_id]["files"]
        if file_name in user_files:
            raise PermissionDenied(f"User {current_user_id} already has a file "
                                   f"with the name {file_name}.")

        # Write the file contents to the vault
        file_id = f"{current_user_id}:{file_name}"
        file_path = os.path.join(self.vault_path, file_id)
        try:
            with open(file_path, "wb") as file:
                file.write(file_contents)
        except Exception as e:
            raise PermissionDenied(f"Failed to write file contents to vault: {e}")

        # Add file to the vault metadata
        current_timestamp = get_current_timestamp()
        self.config["users"][current_user_id]["files"][file_name] = {
            "owner": current_user_id,
            "created": current_timestamp,
            "last_modified": current_timestamp,
            "last_accessed": current_timestamp,
            "acl": {}
        }

        # Add the file to the group
        if current_user_id not in self.config["groups"][group_id]["files"]:
            self.config["groups"][group_id]["files"][current_user_id] = []

        self.config["groups"][group_id]["files"][current_user_id].append(file_id)

        return file_id

    def delete_file_from_group(self,
                               current_user_id: str,
                               group_id: str,
                               file_id: str) -> None:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Extract the user and file name from the file ID
        # INFO this assumes that usernames can't contain ':', but file names can
        user_id, _, file_name = file_id.partition(":")

        # Check if the current user is the owner of the file or the owner of the group
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]
        is_file_owner = current_user_id == user_id

        if not (is_owner or is_file_owner):
            raise PermissionDenied(f"User {current_user_id} is not the owner of file {file_id} "
                                   f"or the owner of group {group_id}.")

        # Check if the file exists in the user's files
        user_files = self.config["users"][current_user_id]["files"]
        if file_name not in user_files:
            raise PermissionDenied(f"User {current_user_id} does not have a file "
                                   f"with the name {file_name}.")

        # Check if the file exists in the group
        group_files = self.config["groups"][group_id]["files"]
        if current_user_id not in group_files or file_id not in group_files[current_user_id]:
            raise PermissionDenied(f"File {file_id} does not exist in group {group_id}.")

        # Delete the file from the vault
        file_path = os.path.join(self.vault_path, file_id)
        try:
            os.remove(file_path)
        except Exception as e:
            raise PermissionDenied(f"Failed to delete file from vault: {e}")

        # Remove the file from the user's files
        del self.config["users"][current_user_id]["files"][file_name]

        # Remove the file from the group's files
        del self.config["groups"][group_id]["files"][current_user_id][file_name]

    ###
    # Group Moderator Operations
    ###

    def add_moderator_to_group(self,
                               current_user_id: str,
                               group_id: str,
                               user_id: str) -> None:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

        # Check if current user is the owner of the group
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]

        if not is_owner:
            raise PermissionDenied("Only the group owner can add moderators.")

        # Check if the user is already a moderator
        if user_id in group["moderators"]:
            # INFO We can throw an exception, print a message
            # or just ignore this case by returning nothing.
            print(f"User {user_id} was already a moderator of group {group_id}.")
            return

        # Add the user to the moderators list
        self.config["groups"][group_id]["moderators"].append(user_id)

    def remove_moderator_from_group(self,
                                    current_user_id: str,
                                    group_id: str,
                                    user_id: str) -> None:
        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        # Check if the user exists
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

        # Check if current user is the owner of the group
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]

        if not is_owner:
            raise PermissionDenied("Only the group owner can remove moderators.")

        # Check if the user is a moderator of the group
        if user_id not in group["moderators"]:
            raise UserNotModeratorOfGroup(user_id, group_id)

        # Remove the user from the moderators list
        self.config["groups"][group_id]["moderators"].remove(user_id)

    def change_moderator_to_member(self,
                                   current_user_id: str,
                                   group_id: str,
                                   user_id: str,
                                   permissions: str) -> None:
        self.remove_moderator_from_group(current_user_id, group_id, user_id)
        self.add_user_to_group(current_user_id, group_id, user_id, permissions)

    ###
    # File Operations TODO
    ###

    # INFO
    # When deleting files that can be in one or more groups,
    # their file name will be in the config["groups"][group_id]["files"][current_user_id] list,
    # we can avoid looking for the file in all existing groups by
    # storing the group ids in the file metadata for that user:
    # config["users"][current_user_id]["files"][file_name] = {
    #   ... existing metadata ...
    #   "groups": [group_id1, group_id2, ...]
    # }
    # This way, we know exactly in which groups to remove the file from.
