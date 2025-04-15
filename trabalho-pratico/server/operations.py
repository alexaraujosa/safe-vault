import os
import datetime
from exceptions import (
    PermissionDenied,
    GroupNotFound,
    UserNotFound,
    InvalidPermissions,
    UserNotMemberOfGroup,
    UserNotModeratorOfGroup,
    GroupAlreadyExists,
    FileNotFoundOnVault,
    UserAlreadyExists,
    SharedUserNotFound,
    InvalidGroupName,
    InvalidFileName,
    InvalidParameter
)

# Considerations:
# - Concurrency:
#       If this operations are called by threads we need to add a lock to the config
#       as well as to the file operations, such as reading, writing and deleting files.
# - Data Corruption (TODO):
#       If the server crashes while writing to the file, the file may be corrupted.
#       To avoid this we can use atomic writes, which means writing to a temporary file
#       and then renaming it to the original file name.
# - Logging:
#       Logging can be implemented by the caller of this operations,
#       in order to keep this critical code clean and simple.


###
# Auxiliary Functions
###

def get_current_timestamp() -> str:
    "Get the current timestamp in ISO 8601 format."
    return datetime.datetime.now().isoformat()


def is_valid_name(name: str) -> bool:
    return isinstance(name, str) and len(name.strip()) > 0 and name.isalnum()


def is_valid_permissions(permissions: str) -> bool:
    "Check if the given permissions are valid, i.e., 'r', 'w', or 'rw'."
    valid_permissions = ["r", "w", "rw"]
    return permissions in valid_permissions


def validate_params(**kwargs):
    for key, value in kwargs.items():
        if value is None or len(value) == 0:
            raise InvalidParameter(key, value)

###
# Operations Class
###

# INFO Most operations assume that the current user exists in the metadata file


class Operations:
    def __init__(self, config: dict, vault_path: str):
        self.config = config
        self.vault_path = vault_path

        # Create vault directory if it doesn't exist
        if not os.path.exists(vault_path):
            os.mkdir(vault_path, 0o700)

    ###
    # User Operations
    ###

    def create_user(self,
                    username: str) -> str:
        # Validate parameters
        validate_params(username=username)

        # Check if the username already exists
        if username in self.config["users"]:
            raise UserAlreadyExists(username)

        # Check valid username
        if not is_valid_name(username):
            raise InvalidParameter(username)

        self.config["users"][username] = {
            "created": get_current_timestamp(),
            "groups": [],
            "own_groups": [],
            "moderator_groups": [],
            "files": {},
            "shared_files": {}
        }

        return username  # user id

    def add_file_to_user(self,
                         current_user_id: str,
                         file_name: str,
                         file_contents: bytes) -> None:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        file_name=file_name)

        # Check valid filename
        if not is_valid_name(file_name):
            raise InvalidFileName(file_name)

        # Check if the file already exists on user vault
        if file_name in self.config["users"][current_user_id]["files"]:
            raise FileExistsError(f"File '{file_name}' already exists in "
                                  f"the user '{current_user_id}' vault.")

        # Write file contents to the vault directory
        file_id = f"{current_user_id}:{file_name}"
        file_path = os.path.join(self.vault_path, file_id)
        try:
            with open(file_path, "wb") as file:
                file.write(file_contents)
        except Exception as e:
            raise PermissionDenied(f"Failed to write file contents to vault: {e}")

        # Add file to user metadata
        current_timestamp = get_current_timestamp()
        self.config["users"][current_user_id]["files"][file_name] = {
            "owner": current_user_id,
            "created": current_timestamp,
            "last_modified": current_timestamp,
            "last_accessed": current_timestamp,
            "acl": {
                "users": {},
                "groups": []
            }
        }

    def list_user_personal_files(self,
                                 current_user_id: str) -> list:
        # Validate parameters
        validate_params(current_user_id=current_user_id)

        return list(self.config["users"][current_user_id]["files"].keys())  # filenames

    def list_user_shared_files(self,
                               current_user_id: str,
                               shared_by_user_id: str) -> list:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        shared_by_user_id=shared_by_user_id)

        # Check if the shared user exists
        if shared_by_user_id not in self.config["users"]:
            raise UserNotFound(shared_by_user_id)

        # Check if exists shared user entry
        shared_files = self.config["users"][current_user_id]["shared_files"]

        if shared_by_user_id not in shared_files:
            raise SharedUserNotFound(current_user_id, shared_by_user_id)

        return list(shared_files[shared_by_user_id].items())

    def list_user_group_files(self,
                              current_user_id: str,
                              group_id: str) -> list:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id)

        # Check if the group exists
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

        files = []

        user = self.config["users"][current_user_id]
        group_files = self.config["groups"][group_id]["files"]

        if group_id in user["own_groups"] + user["moderator_groups"]:
            for file_owner in group_files:
                for filename in group_files[file_owner]:
                    files.append((filename, "rw"))

        elif group_id in user["groups"]:
            user_permissions = self.config["groups"][group_id]["members"][current_user_id]
            for file_owner in group_files:
                for filename in group_files[file_owner]:
                    files.append((filename, user_permissions))

        else:
            raise UserNotMemberOfGroup(current_user_id, group_id)

        return files

    def share_user_file(self,
                        current_user_id: str,
                        file_id: str,
                        user_id_to_share: str,
                        permissions: str) -> None:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        file_id=file_id,
                        user_id_to_share=user_id_to_share,
                        permissions=permissions)

        # Check if the given permissions are valid
        permissions = permissions.lower()
        if not is_valid_permissions(permissions):
            raise InvalidPermissions(permissions)

        # Check if the user to share the file with exists
        if user_id_to_share not in self.config["users"]:
            raise UserNotFound(user_id_to_share)

        # Check if the file exists on metadata file
        # This will also check if the current user is the owner of the file
        file_name = file_id.partition(":")[2]

        if file_name not in self.config["users"][current_user_id]["files"]:
            raise FileNotFoundOnVault(file_name, current_user_id)

        # Add the respective permissions in ACL to the file being shared
        self.config["users"][current_user_id]["files"][file_name]["acl"]["users"][user_id_to_share] = permissions

        # Add the shared file entry to the user who is receiving the file sharing
        if not self.config["users"][user_id_to_share]["shared_files"].get(current_user_id):
            self.config["users"][user_id_to_share]["shared_files"][current_user_id] = {}

        self.config["users"][user_id_to_share]["shared_files"][current_user_id][file_name] = permissions

    def revoke_user_file_permissions(self,
                                     current_user_id: str,
                                     file_id: str,
                                     user_id_to_revoke: str) -> None:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        file_id=file_id,
                        user_id_to_revoke=user_id_to_revoke)

        # Check if the user to revoke the file permissions from exists
        if user_id_to_revoke not in self.config["users"]:
            raise UserNotFound(user_id_to_revoke)

        # Check if the file exists on metadata file
        # This will also check if the current user is the owner of the file
        file_name = file_id.partition(":")[2]

        if file_name not in self.config["users"][current_user_id]["files"]:
            raise FileNotFoundOnVault(file_name, current_user_id)

        # Revoke the file access ACL entry
        if user_id_to_revoke in self.config["users"][current_user_id]["files"][file_name]["acl"]["users"]:
            del self.config["users"][current_user_id]["files"][file_name]["acl"]["users"][user_id_to_revoke]

        # Revoke user access to the file
        if file_name in self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]:
            del self.config["users"][user_id_to_revoke]["shared_files"][current_user_id][file_name]

            # Delete revoked user entry if it's empty
            if not self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]:
                del self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]

    ###
    # Group Operations
    ###

    def create_group(self,
                     current_user_id: str,
                     group_name: str) -> str:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_name=group_name)

        # Check if the group_name is valid
        if not is_valid_name(group_name):
            raise InvalidGroupName(group_name)

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

        # Add the group to the user's own groups
        self.config["users"][current_user_id]["own_groups"].append(group_name)

        return group_name  # group_id

    def delete_group(self,
                     current_user_id: str,
                     group_id: str) -> None:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id)

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
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        user_id=user_id,
                        permissions=permissions)

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
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        user_id=user_id)

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

        # Check if the user is not the owner of the group
        if user_id == group["owner"]:
            raise PermissionDenied(f"User {user_id} is the owner of group {group_id}.")

        # Check if the user is not a member of the group
        if user_id not in group["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

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
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        user_id=user_id,
                        permissions=permissions)

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
        # INFO this check allows to change permissions for members only.
        # The group owner or moderators are not allowed to have explicit permissions
        if user_id not in group["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

        # Change the user's permissions in the group
        self.config["groups"][group_id]["members"][user_id] = permissions

    def list_user_groups(self,
                         current_user_id: str) -> dict:
        # Validate parameters
        validate_params(current_user_id=current_user_id)

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
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        file_name=file_name)

        # Check if file name is valid
        if not is_valid_name(file_name):
            raise InvalidFileName(file_name)

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
            "acl": {
                "users": {},
                "groups": [group_id]
            }
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
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        file_id=file_id)

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
        user_files = self.config["users"][user_id]["files"]
        if file_name not in user_files:
            raise PermissionDenied(f"User {current_user_id} does not have a file "
                                   f"with the name {file_name}.")

        # Check if the file exists in the group
        group_files = self.config["groups"][group_id]["files"]
        if user_id not in group_files or file_id not in group_files[user_id]:
            raise PermissionDenied(f"File {file_id} does not exist in group {group_id}.")

        # Delete the file from the vault
        file_path = os.path.join(self.vault_path, file_id)
        try:
            os.remove(file_path)
        except Exception as e:
            raise PermissionDenied(f"Failed to delete file from vault: {e}")

        # Remove the file from the user's files
        del self.config["users"][user_id]["files"][file_name]

        # Remove the file from the group's files
        self.config["groups"][group_id]["files"][user_id].remove(file_id)
        if len(self.config["groups"][group_id]["files"][user_id]) == 0:
            del self.config["groups"][group_id]["files"][user_id]

    ###
    # Group Moderator Operations
    ###

    def add_moderator_to_group(self,
                               current_user_id: str,
                               group_id: str,
                               user_id: str) -> None:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        user_id=user_id)

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

        # Check if user was previously a member of the group
        if user_id in group["members"]:
            print(f"User {user_id} was a member of group {group_id}.\n"
                  "Changing user from member to moderator.")

            # Remove the user from the members list
            del self.config["groups"][group_id]["members"][user_id]

            # Remove the group from the user's groups
            self.config["users"][user_id]["groups"].remove(group_id)

            # Add the group to the user's moderator groups
            self.config["users"][user_id]["moderator_groups"].append(group_id)

        # Add the user to the moderators list
        self.config["groups"][group_id]["moderators"].append(user_id)

    def remove_moderator_from_group(self,
                                    current_user_id: str,
                                    group_id: str,
                                    user_id: str) -> None:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        group_id=group_id,
                        user_id=user_id)

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
    # File Operations
    ###

    def read_file(self,
                  current_user_id: str,
                  file_id: str) -> bytes:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        file_id=file_id)

        # Extract the user and file name from the file ID
        file_owner_id, _, file_name = file_id.partition(":")

        # Check if the file exists in the user's files
        if file_owner_id not in self.config["users"]:
            raise UserNotFound(file_owner_id)

        # Check if the file exists in the user's files
        if file_name not in self.config["users"][file_owner_id]["files"]:
            raise FileNotFoundOnVault(file_name, file_owner_id)

        # Check if the user has permission to read the file
        if current_user_id != file_owner_id:
            # Check if the file owner has shared any files with the current user
            if file_owner_id not in self.config["users"][current_user_id]["shared_files"]:
                raise PermissionDenied(f"User {file_owner_id} has not shared "
                                       f"any files with {current_user_id}.")

            # Check if the file entry exists in the respective shared files
            if file_name not in self.config["users"][current_user_id]["shared_files"][file_owner_id]:
                raise PermissionDenied(f"The file {file_name} is not shared with "
                                       f"user {current_user_id}.")

            # Check if the user has read permissions
            permissions = self.config["users"][current_user_id]["shared_files"][file_owner_id][file_name]
            if "r" not in permissions:
                raise PermissionDenied(f"User {current_user_id} does not have "
                                       "permission to read the file.")

        # TODO check if file is in a group where the current user is a member

        # Update the last accessed timestamp
        current_timestamp = get_current_timestamp()
        self.config["users"][file_owner_id]["files"][file_name]["last_accessed"] = current_timestamp

        # Read the file contents from the vault
        file_path = os.path.join(self.vault_path, file_id)
        try:
            with open(file_path, "rb") as file:
                file_contents = file.read()
        except Exception as e:
            raise PermissionDenied(f"Failed to read file contents from vault: {e}")

        return file_contents

    def file_details(self,
                     current_user_id: str,
                     file_id: str) -> dict:
        # Validate parameters
        validate_params(current_user_id=current_user_id,
                        file_id=file_id)

        # Extract the user and file name from the file ID
        file_owner_id, _, file_name = file_id.partition(":")

        # Check owner existance
        if file_owner_id not in self.config["users"]:
            raise UserNotFound(file_owner_id)

        # Check if the file exists in the user's files
        if file_name not in self.config["users"][file_owner_id]["files"]:
            raise FileNotFoundOnVault(file_name, file_owner_id)

        # Check if the user has permission to read or write the file
        if current_user_id != file_owner_id:
            # Check if the file owner has shared any files with the current user
            if file_owner_id not in self.config["users"][current_user_id]["shared_files"]:
                raise PermissionDenied(f"User {file_owner_id} has not shared "
                                       f"any files with {current_user_id}.")

            # Check if the file entry exists in the respective shared files
            if file_name not in self.config["users"][current_user_id]["shared_files"][file_owner_id]:
                raise PermissionDenied(f"The file {file_name} is not shared with "
                                       f"user {current_user_id}.")

            # INFO if the shared file exists in the current user's shared files,
            # then the user has some type of permission to it.

        # TODO check if file is in a group where the current user is a member

        # Get file details
        file_metadata = self.config["users"][file_owner_id]["files"][file_name]

        file_details = {}
        file_details["file_id"] = file_id
        file_details["file_name"] = file_name
        file_details["file_owner"] = file_owner_id
        # TODO file size
        file_details["file_created"] = file_metadata["created"]
        file_details["file_last_modified"] = file_metadata["last_modified"]
        file_details["file_last_accessed"] = file_metadata["last_accessed"]
        file_details["acl"] = file_metadata["acl"]
        # TODO get group permissions where the file exists

        # Return file details
        return file_details

    def delete_file(self,
                    current_user_id: str,
                    file_id: str) -> None:
        validate_params(current_user_id=current_user_id,
                        file_id=file_id)

        file_owner_id, _, file_name = file_id.partition(":")

        # Check owner existance
        if file_owner_id not in self.config["users"]:
            raise InvalidFileName(file_id)

        # Validate file existance
        if file_name not in self.config["users"][file_owner_id]["files"]:
            raise FileNotFoundOnVault(file_id, file_owner_id)

        # Current user is the owner
        if current_user_id == file_owner_id:

            # Remove users entries
            for user_id in self.config["users"][current_user_id]["files"][file_name]["acl"]["users"]:
                del self.config["users"][user_id]["shared_files"][current_user_id][file_name]
                if len(self.config["users"][user_id]["shared_files"][current_user_id]) == 0:
                    del self.config["users"][user_id]["shared_files"][current_user_id]
                del self.config["users"][current_user_id]["files"][file_name]["acl"][user_id]
            # Remove groups entries
            for group_id in self.config["users"][current_user_id]["files"][file_name]["acl"]["groups"]:
                del self.config["groups"][group_id]["files"][current_user_id][file_id]
                if len(self.config["groups"][group_id]["files"][current_user_id]) == 0:
                    del self.config["groups"][group_id]["files"][current_user_id]
                self.config["users"][current_user_id]["files"][file_name]["acl"]["groups"][group_id]
            # Remove owner entry
            del self.config["users"][current_user_id]["files"][file_name]
            # Remove file from vault
            os.remove(os.path.join(self.vault_path, file_id))
        else:
            if file_owner_id in self.config["users"][current_user_id]["shared_files"]:
                del self.config["users"][current_user_id]["shared_files"][file_owner_id][file_name]
                if len(self.config["users"][current_user_id]["shared_files"][file_owner_id]) == 0:
                    del self.config["users"][current_user_id]["shared_files"][file_owner_id]

            # Current user is a group owner
            for group_id in self.config["users"][file_owner_id]["files"][file_name]["acl"]["groups"]:
                if current_user_id == self.config["groups"][group_id]["owner"]:
                    del self.config["groups"][group_id]["files"][file_owner_id][file_id]
                    if len(self.config["groups"][group_id]["files"][file_owner_id]) == 0:
                        del self.config["groups"][group_id]["files"][file_owner_id]
                    del self.config["users"][file_owner_id]["files"][file_name]["acl"]["groups"][group_id]

    # TODO replace functions

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
