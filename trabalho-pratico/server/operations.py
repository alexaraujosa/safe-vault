import os
import datetime
from common.validation import validate_params
from common.exceptions import (
    PermissionDenied,
    UserExists,
    UserNotFound,
    SharedUserNotFound,
    GroupExists,
    GroupNotFound,
    UserNotMemberOfGroup,
    UserNotModeratorOfGroup,
    FileNotFoundOnVault,
    NeedConfirmation
)

# Considerations:
# - Data Corruption
#       If the server crashes while writing to the file, the file may be corrupted.
#       To avoid this we can use atomic writes, which means writing to a temporary file
#       and then renaming it to the original file name.
# - Logging:
#       Logging can be implemented by the caller of this operations,
#       in order to keep this critical code clean and simple.
# - Concurrency:
#       If this operations are called by threads we need to add a lock to the config
#       as well as to the file operations, such as reading, writing and deleting files.


###
# Auxiliary Functions
###

def get_current_timestamp() -> str:
    "Get the current timestamp in YYYY/MM/DD HH:MM:SS format."
    return datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")


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

    def authenticate_user(self,
                          username: str) -> None:
        
        try:
            self.create_user(username)
        except Exception:
            pass


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
                         key: str,
                         size: int) -> None:

        validate_params(user_id=current_user_id,
                        file_name=file_name,
                        key=key,
                        size=size)
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
            "size": size,
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

    # INFO before calling this function the server must send the shared user public key
    # so the client returns us the encrypted symmetric key for that user receiving the share
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

        file_owner_id, _, file_name = file_id.partition(":")
        self.user_exists(file_owner_id)
        self.file_exists(current_user_id, file_name)

        # Check if the user being shared is not the owner
        if user_id_to_share == file_owner_id:
            raise PermissionDenied(f"User {user_id_to_share} is the owner of file {file_id}.")

        # Check if the current user is the owner of the file
        if current_user_id != file_owner_id:
            raise PermissionDenied(f"User {current_user_id} is not the owner of file {file_id}.")

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

        file_owner_id, _, file_name = file_id.partition(":")
        self.user_exists(file_owner_id)
        self.file_exists(current_user_id, file_name)

        # Check if the user being revoked is not the owner
        if user_id_to_revoke == file_owner_id:
            raise PermissionDenied(f"User {user_id_to_revoke} is the owner of file {file_id}.")

        # Check if the current user is the owner of the file
        if current_user_id != file_owner_id:
            raise PermissionDenied(f"User {current_user_id} is not the owner of file {file_id}.")

        # Check if the user being revoked is not a shared user
        file_acl = self.config["users"][current_user_id]["files"][file_name]["acl"]
        if user_id_to_revoke not in file_acl["users"]:
            raise PermissionDenied(f"User {user_id_to_revoke} does not have access to file {file_id}.")
        else:  # Revoke the file access ACL entry
            del self.config["users"][current_user_id]["files"][file_name]["acl"]["users"][user_id_to_revoke]

        # Revoke user access to the file
        if file_name in self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]:
            del self.config["users"][user_id_to_revoke]["shared_files"][current_user_id][file_name]

            # Delete revoked user entry if it's empty
            if not self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]:
                del self.config["users"][user_id_to_revoke]["shared_files"][current_user_id]

        # INFO Process for file reencryption
        # 1. Server sends the following to the client:
        #   - Request to reencrypt file
        #   - File contents
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

    def delete_user(self,
                    current_user_id: str) -> None:

        validate_params(user_id=current_user_id)
        self.user_exists(current_user_id)

        # Delete the user's files from the vault
        for file_name in self.config["users"][current_user_id]["files"]:
            # Delete the file from shared users
            for user_id in self.config["users"][current_user_id]["files"][file_name]["acl"]["users"]:
                del self.config["users"][user_id]["shared_files"][current_user_id][file_name]

            # Delete the file from groups
            for group_id in self.config["users"][current_user_id]["files"][file_name]["acl"]["groups"]:
                self.config["groups"][group_id]["files"][current_user_id].remove(file_name)
                if not self.config["groups"][group_id]["files"][current_user_id]:
                    del self.config["groups"][group_id]["files"][current_user_id]

            # Delete the file from the vault
            file_id = f"{current_user_id}:{file_name}"
            file_path = os.path.join(self.vault_path, file_id)
            try:
                os.remove(file_path)
            except Exception as e:
                raise OSError(f"Failed to delete file from vault: {e}")

        # Delete the user from the groups where he is a member
        for group_id in self.config["users"][current_user_id]["groups"]:
            del self.config["groups"][group_id]["members"][current_user_id]

        # Delete the user from the groups where he is a moderator
        for group_id in self.config["users"][current_user_id]["moderator_groups"]:
            self.config["groups"][group_id]["moderators"].remove(current_user_id)

        # Delete groups owned by the user
        for group_id in self.config["users"][current_user_id]["own_groups"]:
            del self.config["groups"][group_id]

        # Delete the user from the metadata
        del self.config["users"][current_user_id]

    ###
    # Group Operations
    ###

    def create_group(self,
                     current_user_id: str,
                     group_name: str,
                     group_key: str) -> str:

        validate_params(user_id=current_user_id,
                        group_id=group_name,
                        key=group_key)
        self.user_exists(current_user_id)

        # Check if the group already exists
        if group_name in self.config["groups"]:
            raise GroupExists(group_name)

        # Create the group adding the current user as owner and member
        self.config["groups"][group_name] = {
            "owner": current_user_id,
            "created": get_current_timestamp(),
            "moderators": [],
            "members": {
                current_user_id: {
                    "permissions": "w",
                    "key": group_key
                }
            },
            "files": {}
        }

        # Add the group to the user's own groups
        self.config["users"][current_user_id]["own_groups"].append(group_name)

        # Add the group to the user's groups
        self.config["users"][current_user_id]["groups"].append(group_name)

        return group_name

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

        # Delete the group from file acl groups metadata
        # INFO The file owner and respective shared users will still have file access
        for owner_id in group["files"]:
            for file_name in group[owner_id]:
                self.config["users"][owner_id]["files"][file_name]["acl"]["groups"].remove(group_id)

        # Delete the group from the user's own groups
        self.config["users"][current_user_id]["own_groups"].remove(group_id)

        # Delete the group from the user's groups
        self.config["users"][current_user_id]["groups"].remove(group_id)

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

    # INFO The group key is the master group key encrypted with the user to be added public key
    # INFO If the user is already a member of the group, the key and permissions will be updated
    def add_user_to_group(self,
                          current_user_id: str,
                          group_id: str,
                          user_id: str,
                          permissions: str,
                          group_key: str) -> None:

        validate_params(user_ids=[current_user_id, user_id],
                        group_id=group_id,
                        permissions=permissions,
                        key=group_key)
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

        # Check if the user being added is the owner
        if user_id == group["owner"]:
            raise PermissionDenied(f"User {user_id} is the owner of group {group_id}.")

        # Check if the user being added is a moderator
        if user_id in group["moderators"]:
            raise PermissionDenied(f"User {user_id} is already a moderator of group {group_id}.")

        # Check if the user is already in the group
        if user_id in group["members"]:
            # TODO replace this print to sent this message to the client
            print(f"User {user_id} is already in group {group_id}.\n"
                  f"Updating permissions to {permissions}.")

        # Add the user to the group with the given permissions
        self.config["groups"][group_id]["members"][user_id] = {
            "permissions": permissions,
            "key": group_key
        }

        # Add the group to the user's groups
        self.config["users"][user_id]["groups"].append(group_id)

    # INFO if the user is a moderator, he will also be removed from the moderators list
    # INFO if the user being removed is the owner of any files in the group,
    # the files will be deleted from the group but kept in that user's vault
    # INFO This function check if `config["groups"][group_id]["files"][user_id]`
    # exists if so raise NeedConfirmation exception since group members will
    # loose access to the files
    def remove_user_from_group(self,
                               current_user_id: str,
                               group_id: str,
                               user_id: str,
                               confirm: bool) -> None:

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

        # Only allow the owner to remove other moderators
        if is_moderator and user_id in group["moderators"]:
            raise PermissionDenied("Only the owner can remove moderators.")

        # Check if the user is not a member of the group
        if user_id not in group["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

        # Check if there were any files owned by the user being removed
        if user_id in group["files"] and not confirm:
            raise NeedConfirmation(f"User {user_id} has files in group {group_id}.\n"
                                   "Please confirm the deletion of the files.")

        # Delete the user files from the group if any
        if user_id in group["files"]:
            del self.config["groups"][group_id]["files"][user_id]

        # Remove the user from the group members and the user's groups
        del self.config["groups"][group_id]["members"][user_id]
        self.config["users"][user_id]["groups"].remove(group_id)

        # Remove the user from the group moderators if he is one
        if user_id in group["moderators"]:
            self.config["groups"][group_id]["moderators"].remove(user_id)
            self.config["users"][user_id]["moderator_groups"].remove(group_id)

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

        # Check if the user with the new permissions is the owner
        if user_id == group["owner"]:
            raise PermissionDenied(f"User {user_id} is the owner of group {group_id}.")

        # Check if the user with the new permissions is a moderator
        if user_id in group["moderators"]:
            raise PermissionDenied(f"User {user_id} is a moderator of group {group_id}.")

        # Check if the user is a member of the group
        if user_id not in group["members"]:
            raise UserNotMemberOfGroup(user_id, group_id)

        # Change the user's permissions in the group
        self.config["groups"][group_id]["members"][user_id]["permissions"] = permissions

    def list_user_groups(self,
                         current_user_id: str) -> dict:

        validate_params(user_id=current_user_id)
        self.user_exists(current_user_id)

        results = {}

        for group_id in self.config["users"][current_user_id]["groups"]:
            group = self.config["groups"][group_id]
            results[group_id] = {
                "permissions": group["members"][current_user_id]["permissions"],
            }

        return results

    def add_file_to_group(self,
                          current_user_id: str,
                          group_id: str,
                          file_name: str,
                          file_contents: bytes,
                          size: int,
                          group_key: str) -> str:

        validate_params(user_id=current_user_id,
                        group_id=group_id,
                        file_name=file_name,
                        key=group_key,
                        size=size)
        self.user_exists(current_user_id)
        self.group_exists(group_id)

        # Check if the user is a member with write permissions in the group
        group = self.config["groups"][group_id]
        is_member = current_user_id in group["members"]
        has_write_permissions = group["members"][current_user_id]["permissions"] == "w"

        if not (is_member and has_write_permissions):
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to write to group {group_id}.")

        # Add file to the user
        self.add_file_to_user(current_user_id, file_name, file_contents, group_key, size)

        # Add group to the file acl groups metadata
        file_id = f"{current_user_id}:{file_name}"
        self.config["users"][current_user_id]["files"][file_name]["acl"]["groups"].append(group_id)

        # Add the file to the group
        if current_user_id not in self.config["groups"][group_id]["files"]:
            self.config["groups"][group_id]["files"][current_user_id] = []
        self.config["groups"][group_id]["files"][current_user_id].append(file_name)

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
        user_id, _, file_name = file_id.partition(":")
        self.user_exists(user_id)
        self.file_exists(user_id, file_name)

        # Check if the current user is the owner of the group or the file
        group = self.config["groups"][group_id]
        is_owner = current_user_id == group["owner"]
        is_file_owner = current_user_id == user_id

        if not (is_owner or is_file_owner):
            raise PermissionDenied(f"User {current_user_id} is not the owner of file {file_id} "
                                   f"or the owner of group {group_id}.")

        # Check if the file exists in the group
        group_files = self.config["groups"][group_id]["files"]
        if user_id not in group_files or file_id not in group_files[user_id]:
            raise PermissionDenied(f"File {file_id} does not exist in group {group_id}.")

        # Delete the file from the group metadata
        self.config["groups"][group_id]["files"][user_id].remove(file_name)
        if not self.config["groups"][group_id]["files"][user_id]:
            del self.config["groups"][group_id]["files"][user_id]

    ###
    # Group Moderator Operations
    ###

    def add_moderator_to_group(self,
                               current_user_id: str,
                               group_id: str,
                               user_id: str,
                               group_key: str) -> None:

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
            # or just ignore this case by returning None.
            print(f"User {user_id} is already a moderator of group {group_id}.")
            return

        # Add the user as member with write permissions
        self.config["groups"][group_id]["members"][user_id] = {
            "permissions": "w",
            "key": group_key
        }

        # Add the group to the user's groups
        if group_id not in self.config["users"][user_id]["groups"]:
            self.config["users"][user_id]["groups"].append(group_id)

        # Add the user to the moderators list
        self.config["groups"][group_id]["moderators"].append(user_id)

        # Add the group to the user's moderator groups
        self.config["users"][user_id]["moderator_groups"].append(group_id)

    # NOTE calling this function only remove the user as a moderator and
    # will leave the user in the group members list with previous write permissions
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
        if current_user_id != self.config["groups"][group_id]["owner"]:
            raise PermissionDenied("Only the group owner can remove moderators.")

        # Check if the user is a moderator of the group
        if user_id not in self.config["groups"][group_id]["moderators"]:
            raise UserNotModeratorOfGroup(user_id, group_id)

        # Remove the user from the moderators list
        self.config["groups"][group_id]["moderators"].remove(user_id)

        # Remove the group from the user's moderator groups
        self.config["users"][user_id]["moderator_groups"].remove(group_id)

    ###
    # File Operations
    ###

    def read_file(self,
                  current_user_id: str,
                  file_id: str) -> dict:

        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

        # Extract the user and file name from the file ID
        file_owner_id, _, file_name = file_id.partition(":")
        self.user_exists(file_owner_id)
        self.file_exists(file_owner_id, file_name)

        # Determine if the current user can read the file, meaning
        # he is the owner, a shared user or member of a group with that file
        is_owner = current_user_id == file_owner_id
        is_shared_user = file_owner_id in self.config["users"][current_user_id]["shared_files"]
        is_group_member = False
        for group_id in self.config["users"][file_owner_id]["files"][file_name]["acl"]["groups"]:
            if current_user_id in self.config["groups"][group_id]["members"]:
                is_group_member = True
                break

        if not (is_owner or is_shared_user or is_group_member):
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to read the file {file_id}.")

        # Get the key for the user reading the file
        key = None
        if is_owner:
            key = self.config["users"][file_owner_id]["files"][file_name]["key"]
        elif is_shared_user:
            key = self.config["users"][file_owner_id]["shared_files"][current_user_id][file_name]["key"]
        elif is_group_member:
            for group_id in self.config["users"][file_owner_id]["files"][file_name]["acl"]["groups"]:
                if current_user_id in self.config["groups"][group_id]["members"]:
                    key = self.config["groups"][group_id]["members"][current_user_id]["key"]
                    break
        else:
            raise PermissionDenied(f"User {current_user_id} cannot access his key "
                                   f"for the file {file_id}.\n"
                                   "Debug info:\n"
                                   f"  File_id: {file_id}\n"
                                   f"  is_owner: {is_owner}\n"
                                   f"  is_shared_user: {is_shared_user}\n"
                                   f"  is_group_member: {is_group_member}")

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

        return {
            "file_id": file_id,
            "file_contents": file_contents,
            "key": key
        }

    def replace_file(self,
                     current_user_id: str,
                     file_id: str,
                     file_contents: bytes,
                     size: int) -> None:
        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

        # INFO If the current user is a member in 2 groups,
        # one with write permissions and another with read permissions,
        # The user will write to the file anyways!
        # "It's a feature, not a bug."

        # Extract the user and file name from the file ID
        file_owner_id, _, file_name = file_id.partition(":")
        self.user_exists(file_owner_id)
        self.file_exists(file_owner_id, file_name)

        file_acl = self.config["users"][file_owner_id]["files"][file_name]["acl"]

        # Determine if the current user can replace the file, meaning
        # he is the owner, a shared user with write permissions or
        # a member with write permissions of a group with that file
        can_write = current_user_id == file_owner_id
        can_write |= file_acl["users"].get(current_user_id) == "w"
        for group_id in file_acl["groups"]:
            members = self.config["groups"][group_id]["members"]
            if members.get(current_user_id).get("permissions") == "w":
                can_write = True
                break

        if not can_write:
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to replace the file {file_id}.")

        # Write the new file contents to the vault
        file_path = os.path.join(self.vault_path, file_id)
        write_file(file_path, file_contents)

        # Update metadata
        self.config["users"][file_owner_id]["files"][file_name]["size"] = size
        self.config["users"][file_owner_id]["files"][file_name]["last_modified"] = get_current_timestamp()

    def file_details(self,
                     current_user_id: str,
                     file_id: str) -> dict:

        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

        # Extract the user and file name from the file ID
        file_owner_id, _, file_name = file_id.partition(":")
        self.user_exists(file_owner_id)
        self.file_exists(file_owner_id, file_name)

        file_details = {}

        # Determine if the current user has access to the file, meaning
        # he is the owner, a shared user or member of a group with that file
        is_owner = current_user_id == file_owner_id
        is_shared_user = file_owner_id in self.config["users"][current_user_id]["shared_files"]
        is_group_member = False
        for group_id in self.config["users"][file_owner_id]["files"][file_name]["acl"]["groups"]:
            if current_user_id in self.config["groups"][group_id]["members"]:
                is_group_member = True
                break

        if not (is_owner or is_shared_user or is_group_member):
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to access the file {file_id} details.")

        # Retrive file details (owner, size, created, last_modified, last_accessed)
        file_details = self.config["users"][file_owner_id]["files"][file_name]

        # Retrieve the users where the file is shared
        file_details["shared_with"] = {}
        for shared_user_id in file_details["acl"]["users"]:
            file_details["shared_with"][shared_user_id] = {
                "permissions": file_details["acl"]["users"][shared_user_id]
            }

        # Retrieve the groups where the file is shared
        file_details["group_members"] = {}
        for group_id in file_details["acl"]["groups"]:
            file_details["group_members"][group_id] = {}
            group = self.config["groups"][group_id]
            for group_member_id in group["members"]:
                file_details["group_members"][group_id][group_member_id] = {
                    "permissions": group["members"][group_member_id]["permissions"]
                }

        del file_details["key"]  # remove the key from the details
        del file_details["acl"]  # remove the acl from the details

        return file_details

    def delete_file(self,
                    current_user_id: str,
                    file_id: str) -> None:

        validate_params(user_id=current_user_id,
                        file_id=file_id)
        self.user_exists(current_user_id)

        file_owner_id, _, file_name = file_id.partition(":")
        self.user_exists(file_owner_id)
        self.file_exists(file_owner_id, file_name)

        file_acl = self.config["users"][file_owner_id]["files"][file_name]["acl"]

        # Determine if the current user can delete the file, meaning
        # he is the owner, a shared user or owner of a group with that file
        is_owner = current_user_id == file_owner_id
        is_shared_user = file_owner_id in self.config["users"][current_user_id]["shared_files"]
        groups_to_remove_file = []  # list of groups that have the file and the current user is the group owner
        for group_id in file_acl["groups"]:
            if current_user_id == self.config["groups"][group_id]["owner"]:
                groups_to_remove_file.append(group_id)

        if not (is_owner or is_shared_user or len(groups_to_remove_file) > 0):
            raise PermissionDenied(f"User {current_user_id} does not have permission "
                                   f"to delete the file {file_id}.")

        # Delete the file based on the user type
        if is_owner:
            # Delete the file from the vault
            file_path = os.path.join(self.vault_path, file_id)
            try:
                os.remove(file_path)
            except Exception as e:
                raise OSError(f"Failed to delete file from vault: {e}")

            # Delete the file from shared users entries
            for shared_user_id in file_acl["users"]:
                del self.config["users"][shared_user_id]["shared_files"][file_owner_id][file_name]
                if len(self.config["users"][shared_user_id]["shared_files"][file_owner_id]) == 0:
                    del self.config["users"][shared_user_id]["shared_files"][file_owner_id]

            # Delete the file from groups entries
            for group_id in file_acl["groups"]:
                self.config["groups"][group_id]["files"][file_owner_id].remove(file_name)
                if len(self.config["groups"][group_id]["files"][file_owner_id]) == 0:
                    del self.config["groups"][group_id]["files"][file_owner_id]

            # Delete the file from the user metadata
            del self.config["users"][file_owner_id]["files"][file_name]

        elif is_shared_user:
            # Delete the file from the shared user entries
            del self.config["users"][current_user_id]["shared_files"][file_owner_id][file_name]
            if len(self.config["users"][current_user_id]["shared_files"][file_owner_id]) == 0:
                del self.config["users"][current_user_id]["shared_files"][file_owner_id]

        elif len(groups_to_remove_file) > 0:
            # Delete the file from the group entries
            for group_id in groups_to_remove_file:
                self.config["groups"][group_id]["files"][file_owner_id].remove(file_name)
                if len(self.config["groups"][group_id]["files"][file_owner_id]) == 0:
                    del self.config["groups"][group_id]["files"][file_owner_id]
