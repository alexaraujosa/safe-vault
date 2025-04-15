import os
import datetime
from exceptions import (
    PermissionDenied,
    UserExists,
    UserNotFound,
    SharedUserNotFound,
    GroupExists,
    GroupNotFound,
    UserNotMemberOfGroup,
    UserNotModeratorOfGroup,
    FileNotFoundOnVault,
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


def write_file(file_path: str, file_contents: bytes) -> None:
    """
    Atomically write the file contents to the given file path.

    Raises OSError if the file cannot be written.
    """
    # Create the temporary file path
    tmp_file_path = f"{file_path}.tmp"
    try:
        # Write the file contents to the temporary file
        with open(tmp_file_path, "wb") as tmp_file:
            tmp_file.write(file_contents)

        # Rename the temporary file to the original file name
        os.rename(tmp_file_path, file_path)
    except Exception as e:
        # Remove the temporary file if it exists
        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)

        raise OSError(f"Failed to write file contents to vault: {e}")


def is_valid_name(name: str) -> bool:
    "Check if the given name is valid, i.e., not empty and alphanumeric."
    return isinstance(name, str) and len(name) > 0 and name.isalnum()


def is_valid_user_id(user_id: str) -> bool:
    "Check if the given user ID is valid name and does not contain any ':'."
    return is_valid_name(user_id) and ':' not in user_id


def is_valid_file_id(file_id: str) -> bool:
    """
    Check if the given file ID is valid, i.e., in the format 'user_id:file_name',
    where "user_id" is a valid user ID and "file_name" is a valid name.
    """
    if not isinstance(file_id, str):
        return False

    partitioned_value = file_id.partition(":")
    if (
        partitioned_value[1] != ":"
        or not is_valid_user_id(partitioned_value[0])
        or not is_valid_name(partitioned_value[2])
    ):
        return False
    return True


def is_valid_permissions(permissions: str) -> bool:
    "Check if the given permissions are valid, i.e., 'r' or 'w'."
    return permissions in ["r", "w"]


def is_valid_key(key: str) -> bool:
    """
    Check if the given key is valid, i.e., not empty.
    TODO In the future validate key characters and size.
    """
    return isinstance(key, str) and len(key) > 0


def validate_params(**kwargs) -> None:
    """
    Validate the given parameters.

    Supported parameters:
    - user_ids:    list(str)
    - user_id:     str
    - group_id:    str
    - file_id:     str
    - file_name:   str
    - permissions: str
    - key:         str

    Raises:
    - ValueError for the first validation error found.
    - InvalidParameter for unsupported parameters.
    """
    for key, value in kwargs.items():
        match key:
            case "user_ids":
                for user in value:
                    if not is_valid_user_id(user):
                        raise ValueError(f"Invalid user ID: {user}")
            case "user_id":
                if not is_valid_user_id(user):
                    raise ValueError(f"Invalid user ID: {user}")
            case "group_id":
                if not is_valid_name(value):
                    raise ValueError(f"Invalid group ID: {value}")
            case "file_id":
                if not is_valid_file_id(value):
                    raise ValueError(f"Invalid file ID: {value}")
            case "file_name":
                if not is_valid_name(value):
                    raise ValueError(f"Invalid file name: {value}")
            case "permissions":
                if not is_valid_permissions(value):
                    raise ValueError(f"Invalid permissions: {value}")
            case "key":
                if not is_valid_key(value):
                    raise ValueError(f"Invalid key: {value}")
            case _:
                raise InvalidParameter(key)


###
# Operations Class
###

# TODO Update Group, Moderator and File operations methods
# TODO Don't assume owners or moderators have omitted permissions

class Operations:
    def __init__(self, config: dict, vault_path: str):
        self.config = config
        self.vault_path = vault_path

        # Create vault directory if it doesn't exist
        if not os.path.exists(vault_path):
            os.mkdir(vault_path, 0o700)

    ###
    # Auxiliary Functions
    ###

    def user_exists(self, user_id: str) -> None:
        """
        Check if the user exists in the metadata file.

        Raises UserNotFound if the user does not exist.
        """
        if user_id not in self.config["users"]:
            raise UserNotFound(user_id)

    def group_exists(self, group_id: str) -> None:
        """
        Check if the group exists in the metadata file.

        Raises GroupNotFound if the group does not exist.
        """
        if group_id not in self.config["groups"]:
            raise GroupNotFound(group_id)

    def file_exists(self, user_id: str, file_name: str) -> None:
        """
        Check if the file exists in the user's vault.

        Raises FileNotFoundOnVault if the file does not exist.
        """
        if file_name not in self.config["users"][user_id]["files"]:
            raise FileNotFoundOnVault(file_name, user_id)

    ###
    # User Operations
    ###

    def create_user(self,
                    username: str) -> str:

        validate_params(user_id=username)

        # Check if the username already exists
        if username in self.config["users"]:
            raise UserExists(username)

        self.config["users"][username] = {
            "created": get_current_timestamp(),
            "groups": [],
            "own_groups": [],
            "moderator_groups": [],
            "files": {},
            "shared_files": {}
        }

        return username  # user_id

    def add_file_to_user(self,
                         current_user_id: str,
                         file_name: str,
                         file_contents: bytes,
                         key: str) -> None:

        validate_params(user_id=current_user_id,
                        file_name=file_name,
                        key=key)
        self.user_exists(current_user_id)

        # Check if the file already exists on user vault
        if file_name in self.config["users"][current_user_id]["files"]:
            raise FileExistsError(f"File '{file_name}' already exists in "
                                  f"the user '{current_user_id}' vault.")

        # Write file contents to the vault directory
        file_id = f"{current_user_id}:{file_name}"
        file_path = os.path.join(self.vault_path, file_id)
        write_file(file_path, file_contents)

        # Add file to user metadata
        current_timestamp = get_current_timestamp()
        self.config["users"][current_user_id]["files"][file_name] = {
            "owner": current_user_id,
            "size": len(file_contents),
            "created": current_timestamp,
            "last_modified": current_timestamp,
            "last_accessed": current_timestamp,
            "key": key,
            "acl": {
                "users": {},
                "groups": []
            }
        }

    def list_user_personal_files(self,
                                 current_user_id: str) -> list:

        validate_params(user_id=current_user_id)
        self.user_exists(current_user_id)
        return list(self.config["users"][current_user_id]["files"].keys())  # filenames

    def list_user_shared_files(self,
                               current_user_id: str,
                               shared_by_user_id: str) -> list[tuple[str, str]]:

        validate_params(user_ids=[current_user_id, shared_by_user_id])
        self.user_exists(current_user_id)
        self.user_exists(shared_by_user_id)

        # Check if the shared user entry exists in the current user metadata
        shared_files = self.config["users"][current_user_id]["shared_files"]
        if shared_by_user_id not in shared_files:
            raise SharedUserNotFound(current_user_id, shared_by_user_id)

        # Return the list with the (filename, permissions) tuples
        return [
            (filename, shared_files[shared_by_user_id][filename]["permissions"])
            for filename in shared_files[shared_by_user_id]
        ]

    def list_user_group_files(self,
                              current_user_id: str,
                              group_id: str) -> list:

        validate_params(user_id=current_user_id,
                        group_id=group_id)
        self.user_exists(current_user_id)
        self.group_exists(group_id)

        # List the user files in groups he's a member of
        files = []
        user = self.config["users"][current_user_id]
        group_files = self.config["groups"][group_id]["files"]

        if group_id in user["groups"]:
            # Get the user permissions in the group
            permissions = self.config["groups"][group_id]["members"][current_user_id]

            # List all files in the group
            for file_owner in group_files:
                for filename in group_files[file_owner]:
                    files.append((filename, permissions))
        else:
            raise UserNotMemberOfGroup(current_user_id, group_id)

        return files

    def share_user_file(self,
                        current_user_id: str,
                        file_id: str,
                        user_id_to_share: str,
                        permissions: str,
                        key: str) -> None:

        validate_params(user_ids=[current_user_id, user_id_to_share],
                        file_id=file_id,
                        permissions=permissions,
                        key=key)
        self.user_exists(current_user_id)
        self.user_exists(user_id_to_share)

        # INFO This will implicitly check if the current user is the file owner
        file_name = file_id.partition(":")[2]
        self.file_exists(current_user_id, file_name)

        # Add the respective permissions in ACL to the file being shared
        self.config["users"][current_user_id]["files"][file_name]["acl"]["users"][user_id_to_share] = permissions

        # Add the shared file entry to the user who is receiving the file sharing
        if not self.config["users"][user_id_to_share]["shared_files"].get(current_user_id):
            self.config["users"][user_id_to_share]["shared_files"][current_user_id] = {}

        self.config["users"][user_id_to_share]["shared_files"][current_user_id][file_name] = {
            "permissions": permissions,
            "key": key
        }

    def revoke_user_file_permissions(self,
                                     current_user_id: str,
                                     file_id: str,
                                     user_id_to_revoke: str) -> None:

        validate_params(user_ids=[current_user_id, user_id_to_revoke],
                        file_id=file_id)
        self.user_exists(current_user_id)
        self.user_exists(user_id_to_revoke)

        # INFO This will implicitly check if the current user is the file owner
        file_name = file_id.partition(":")[2]
        self.file_exists(current_user_id, file_name)

        # Revoke the file access ACL entry
        if user_id_to_revoke in self.config["users"][current_user_id]["files"][file_name]["acl"]["users"]:
            del self.config["users"][current_user_id]["files"][file_name]["acl"]["users"][user_id_to_revoke]

        # Revoke user access to the file
        if file_name in self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]:
            del self.config["users"][user_id_to_revoke]["shared_files"][current_user_id][file_name]

            # Delete revoked user entry if it's empty
            if not self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]:
                del self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]

        # TODO File reencryption for safety!
        # 1. Server sends the following to the client:
        #   - Request to reencrypt file
        #   - File contents
        #   - File metadata (to store the symmetric key with the name of the file_id) [Alternatively: just the file_id]
        #   - Encrypted symmetric key
        #   - Dictionary of public keys of the users that have access to the file
        # 2. Client decrypts symmetric key and file contents
        # 3. Client generates a new AES symmetric key
        # 4. Client reencrypts the file contents with the new symmetric key
        # 5. Client encrypts the symmetric key for each user public key received and himself
        # 6. Client sends the following to the server:
        #   - Reencrypt request response
        #   - File contents
        #   - Owner encrypted symmetric key
        #   - Dictionary of the symmetric keys encrypted with the public keys of the users
        # 7. Server stores the new file contents and the new symmetric keys

    ###
    # Group Operations
    ###

    def create_group(self,
                     current_user_id: str,
                     group_name: str) -> str:

        validate_params(user_id=current_user_id,
                        group_id=group_name)
        self.user_exists(current_user_id)

        # Check if the group already exists
        if group_name in self.config["groups"]:
            raise GroupExists(group_name)

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

        validate_params(user_id=current_user_id,
                        group_id=group_id)
        self.user_exists(current_user_id)
        self.group_exists(group_id)

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

        validate_params(user_ids=[current_user_id, user_id],
                        group_id=group_id,
                        permissions=permissions)
        self.user_exists(current_user_id)
        self.user_exists(user_id)
        self.group_exists(group_id)

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

        validate_params(user_ids=[current_user_id, user_id],
                        group_id=group_id)
        self.user_exists(current_user_id)
        self.user_exists(user_id)
        self.group_exists(group_id)

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

        validate_params(user_ids=[current_user_id, user_id],
                        group_id=group_id,
                        permissions=permissions)
        self.user_exists(current_user_id)
        self.user_exists(user_id)
        self.group_exists(group_id)

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

        validate_params(user_id=current_user_id)
        self.user_exists(current_user_id)

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

        validate_params(user_id=current_user_id,
                        group_id=group_id,
                        file_name=file_name)
        self.user_exists(current_user_id)
        self.group_exists(group_id)

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

        validate_params(user_id=current_user_id,
                        group_id=group_id,
                        file_id=file_id)
        self.user_exists(current_user_id)
        self.group_exists(group_id)

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

        validate_params(user_ids=[current_user_id, user_id],
                        group_id=group_id)
        self.user_exists(current_user_id)
        self.user_exists(user_id)
        self.group_exists(group_id)

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

        validate_params(user_ids=[current_user_id, user_id],
                        group_id=group_id)
        self.user_exists(current_user_id)
        self.user_exists(user_id)
        self.group_exists(group_id)

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

        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

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

        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

        # Extract the user and file name from the file ID
        file_owner_id, _, file_name = file_id.partition(":")

        # Check if file owner exists
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

        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

        file_owner_id, _, file_name = file_id.partition(":")

        # Check if file owner exists
        if file_owner_id not in self.config["users"]:
            raise UserNotFound(file_owner_id)

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
