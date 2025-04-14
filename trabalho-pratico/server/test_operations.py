import unittest
import os, shutil, datetime
from operations import Operations
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

class TestOperations(unittest.TestCase):

    def setUp(self):
        self.vault_path = "test_vault"
        self.config = {
            "users": {},
            "groups": {}
        }
        self.timestamp = datetime.datetime.now().isoformat()
        self.operations = Operations(self.config, self.vault_path)

        # Clear test vault
        if os.path.exists(self.vault_path):
            shutil.rmtree(self.vault_path)
        
        # Create test vault
        os.mkdir(self.vault_path)

    def tearDown(self):
        # Remove test vault
        if os.path.exists(self.vault_path):
            shutil.rmtree(self.vault_path)
        
    #region User Methods

    def test_create_user(self):
        expected_user = {
            "created": self.timestamp,
            "groups": [],
            "own_groups": [],
            "moderator_groups": [],
            "files": {},
            "shared_files": {}
        }

        # Valid username
        user_id = self.operations.create_user("test123")
        self.assertIn(user_id, self.config["users"])

        self.config["users"][user_id]["created"] = self.timestamp
        self.assertEqual(expected_user, self.config["users"][user_id])

        # Empty username
        with self.assertRaises(InvalidParameter):
            self.operations.create_user("")
        # Non-alphanumeric username
            self.operations.create_user("   ")
            self.operations.create_user("test!")
            self.operations.create_user("test:")

        # Duplicated username
        with self.assertRaises(UserAlreadyExists):
            self.operations.create_user("test123")

    def test_add_file_to_user(self):
        # Setup config
        user_id = self.operations.create_user("test123")

        expected_entry = {
            "owner": user_id,
            "created": self.timestamp,
            "last_modified": self.timestamp,
            "last_accessed": self.timestamp,
            "acl": {}
        }
        filename = "file"
        content = b"1092okasnd0ij12naod"

        # Valid file
        self.operations.add_file_to_user(user_id, filename, content)
        self.assertIn(filename, self.config["users"][user_id]["files"])

        self.config["users"][user_id]["files"][filename]["created"] = self.timestamp
        self.config["users"][user_id]["files"][filename]["last_modified"] = self.timestamp
        self.config["users"][user_id]["files"][filename]["last_accessed"] = self.timestamp
        self.assertEqual(expected_entry, self.config["users"][user_id]["files"][filename])

        # Non-alphanumeric filename
        with self.assertRaises(InvalidFileName):
            self.operations.add_file_to_user(user_id, "invalid:filename", b"")

        # Duplicated file
        with self.assertRaises(FileExistsError):
            self.operations.add_file_to_user(user_id, filename, content)
        
    def test_share_user_file(self):
        # Setup config
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        filename = "file"
        file_id = "test1:file"
        permissions = "rw"
        self.operations.add_file_to_user(user_id, filename, b"0ij12i0djjs01")

        # Invalid user id to share
        with self.assertRaises(UserNotFound):
            self.operations.share_user_file(user_id, file_id, "test3", "r")
        
        # File doesn't belong to the user
        with self.assertRaises(FileNotFoundOnVault):
            self.operations.share_user_file(user_id, "invalid_fileid", user_id2, "r")
        
        # Invalid permissions
        with self.assertRaises(InvalidPermissions):
            self.operations.share_user_file(user_id, file_id, user_id2, "-rw")
            self.operations.share_user_file(user_id, file_id, user_id2, "a")
            self.operations.share_user_file(user_id, file_id, user_id2, "rwx")
            self.operations.share_user_file(user_id, file_id, user_id2, "rr")

        # Valid first share to the user
        self.assertNotIn(user_id, self.config["users"][user_id2]["shared_files"])
        self.operations.share_user_file(user_id, file_id, user_id2, permissions)
        self.assertIn(user_id, self.config["users"][user_id2]["shared_files"])
        self.assertEqual({filename: permissions}, self.config["users"][user_id2]["shared_files"][user_id])

        # Valid second share to the user (Replace permissions)
        permissions = "r"
        self.assertNotEqual({filename: permissions}, self.config["users"][user_id2]["shared_files"][user_id])
        self.operations.share_user_file(user_id, file_id, user_id2, permissions)
        self.assertEqual({filename: permissions}, self.config["users"][user_id2]["shared_files"][user_id])


    def test_revoke_user_file_permissions(self):
        # Setup config
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        filename = "file"
        file_id = "test1:file"
        permissions = "rw"
        self.operations.add_file_to_user(user_id, filename, b"0ij12i0djjs01")
        self.operations.share_user_file(user_id, file_id, user_id2, permissions)

        # Invalid revoke user id
        with self.assertRaises(UserNotFound):
            self.operations.revoke_user_file_permissions(user_id, file_id, "invalid_user_id")

        # Invalid file id
        with self.assertRaises(FileNotFoundOnVault):
            self.operations.revoke_user_file_permissions(user_id, "invalid_file_id", user_id2)

        # Valid revoke
        self.assertIn(user_id2, self.config["users"][user_id]["files"][filename]["acl"])
        self.assertIn(filename, self.config["users"][user_id2]["shared_files"][user_id])
        self.operations.revoke_user_file_permissions(user_id, file_id, user_id2)
        self.assertNotIn(user_id2, self.config["users"][user_id]["files"][filename]["acl"])
        self.assertNotIn(user_id, self.config["users"][user_id2]["shared_files"])


    def test_list_user_personal_files(self):
        # Setup config
        user_id = self.operations.create_user("test1")
        
        # Empty file list
        self.assertEqual([], self.operations.list_user_personal_files(user_id))

        # Non-Empty file list
        self.operations.add_file_to_user(user_id, "file", b"912juisnd9h1njasd1")
        self.assertEqual(["file"], self.operations.list_user_personal_files(user_id))
    
    # TODO List methods.\

    #endregion

    #region Group Methods

    def test_create_group(self):
        # Config setup
        user_id = self.operations.create_user("test")

        # Valid group
        self.assertNotIn("test", self.config["groups"])
        group_id = self.operations.create_group(user_id, "test")
        self.assertIn("test", self.config["groups"])
        self.config["groups"][group_id]["created"] = self.timestamp
        expected_data = {
            "owner": user_id,
            "created": self.timestamp,
            "moderators": [],
            "members": {},
            "files": {}
        }
        self.assertEqual(expected_data, self.config["groups"][group_id])

        # Empty group name
        with self.assertRaises(InvalidParameter):
            self.operations.create_group(user_id, "")

        # Non-alphanumeric group name
        with self.assertRaises(InvalidGroupName):
            self.operations.create_group(user_id, "invalid:groupname")

        # Group name duplicated
        with self.assertRaises(GroupAlreadyExists):
            self.operations.create_group(user_id, "test")
        
    def test_delete_group(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        group_id = self.operations.create_group(user_id, "test")

        # Group doesn't exist
        with self.assertRaises(GroupNotFound):
            self.operations.delete_group(user_id, "invalid_group")
        
        # Group doesn't belong to the user
        with self.assertRaises(PermissionDenied):
            self.operations.delete_group(user_id2, group_id)
        
        # TODO Verify if owner/members/moderators group entry disappears?

        # Valid delete
        self.assertIn(group_id, self.config["groups"])
        self.operations.delete_group(user_id, group_id)
        self.assertNotIn(group_id, self.config["groups"])
        
    def test_add_user_to_group(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        group_id = self.operations.create_group(user_id, "test")

        # Invalid group
        with self.assertRaises(GroupNotFound):
            self.operations.add_user_to_group(user_id, "invalid_group", user_id2, "r")

        # Invalid user
        with self.assertRaises(UserNotFound):
            self.operations.add_user_to_group(user_id, group_id, "invalid_user", "r")
        
        # Group doesn't belong to the user
        with self.assertRaises(PermissionDenied):
            self.operations.add_user_to_group(user_id2, group_id, user_id2, "r")
        
        # Self add to the group
        with self.assertRaises(PermissionDenied):
            self.operations.add_user_to_group(user_id, group_id, user_id, "rw")
        
        # Invalid permissions
        with self.assertRaises(InvalidPermissions):
            self.operations.add_user_to_group(user_id, group_id, user_id2, "-r")
            self.operations.add_user_to_group(user_id, group_id, user_id2, "o")

        # Valid add
        self.assertNotIn(user_id2, self.config["groups"][group_id]["members"])
        self.assertNotIn(user_id2, self.config["groups"][group_id]["moderators"])
        self.operations.add_user_to_group(user_id, group_id, user_id2, "r")
        self.assertIn(user_id2, self.config["groups"][group_id]["members"])
        self.assertNotIn(user_id2, self.config["groups"][group_id]["moderators"])
        self.assertEqual("r", self.config["groups"][group_id]["members"][user_id2])

        # Change member permissions
        self.assertEqual("r", self.config["groups"][group_id]["members"][user_id2])
        self.operations.add_user_to_group(user_id, group_id, user_id2, "w")
        self.assertEqual("w", self.config["groups"][group_id]["members"][user_id2])

        # Invalid add a member that already is an moderator
        self.operations.add_moderator_to_group(user_id, group_id, user_id2)
        with self.assertRaises(PermissionDenied):
            self.operations.add_user_to_group(user_id, group_id, user_id2, "r")

    def test_remove_user_from_group(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        user_id3 = self.operations.create_user("test3")
        group_id = self.operations.create_group(user_id, "test")

        # Invalid group
        with self.assertRaises(GroupNotFound):
            self.operations.remove_user_from_group(user_id, "invalid_group", user_id)
        
        # Group doesn't belong to the user
        with self.assertRaises(PermissionDenied):
            self.operations.remove_user_from_group("invalid_owner", group_id, user_id)
        
        # Invalid member
        with self.assertRaises(UserNotMemberOfGroup):
            self.operations.remove_user_from_group(user_id, group_id, user_id2)
        
        # Self remove
        with self.assertRaises(PermissionDenied):
            self.operations.remove_user_from_group(user_id, group_id, user_id)

        # Valid remove of a member
        self.operations.add_user_to_group(user_id, group_id, user_id2, "r")
        self.assertIn(user_id2, self.config["groups"][group_id]["members"])
        self.operations.remove_user_from_group(user_id, group_id, user_id2)
        self.assertNotIn(user_id2, self.config["groups"][group_id]["members"])

        # User tries to remove a moderator
        self.operations.add_user_to_group(user_id, group_id, user_id2, "r")
        self.operations.add_moderator_to_group(user_id, group_id, user_id2)
        self.operations.add_user_to_group(user_id, group_id, user_id3, "w")
        with self.assertRaises(PermissionDenied):
            self.operations.remove_user_from_group(user_id3, group_id, user_id2)

        # User tries to remove the owner
        with self.assertRaises(PermissionDenied):
            self.operations.remove_user_from_group(user_id3, group_id, user_id)

        # Invalid remove of a moderator
        with self.assertRaises(UserNotMemberOfGroup):
            self.operations.remove_user_from_group(user_id, group_id, user_id2)
    
    def test_change_user_group_permissions(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        user_id3 = self.operations.create_user("test3")
        group_id = self.operations.create_group(user_id, "test")
        self.operations.add_user_to_group(user_id, group_id, user_id2, "w")
        self.operations.add_moderator_to_group(user_id, group_id, user_id2)

        # Invalid group
        with self.assertRaises(GroupNotFound):
            self.operations.change_user_group_permissions(user_id, "invalid:group", user_id2, "r")
        
        # Group doesn't belong to the user
        with self.assertRaises(PermissionDenied):
            self.operations.change_user_group_permissions(user_id3, group_id, user_id2, "r")
        
        # User not member of the group
        with self.assertRaises(UserNotMemberOfGroup):
            self.operations.change_user_group_permissions(user_id, group_id, user_id3, "r")

        # User is a moderator
        with self.assertRaises(UserNotMemberOfGroup):
            self.operations.change_user_group_permissions(user_id, group_id, user_id2, "r")

        # Invalid permissions
        self.operations.add_user_to_group(user_id, group_id, user_id3, "w")
        with self.assertRaises(InvalidPermissions):
            self.operations.change_user_group_permissions(user_id, group_id, user_id3, "rwx")

        # Privilege escalation
        with self.assertRaises(PermissionDenied):
            self.operations.change_user_group_permissions(user_id3, group_id, user_id3, "rw")

        # Valid change permissions from owner 
        self.operations.change_user_group_permissions(user_id, group_id, user_id3, "r")
        self.assertEqual("r", self.config["groups"][group_id]["members"][user_id3])

        # Valid change permissions from a moderator
        self.operations.change_user_group_permissions(user_id2, group_id, user_id3, "w")
        self.assertEqual("w", self.config["groups"][group_id]["members"][user_id3])

    def test_list_user_groups(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")

        # Empty groups
        groups = self.operations.list_user_groups(user_id)
        expected_data = {
            "own_groups": [],
            "moderator_groups": [],
            "member_groups": {}
        }
        self.assertEqual(expected_data, groups)

        # Owner group
        group_id = self.operations.create_group(user_id, "test")
        expected_data["own_groups"].append(group_id)
        groups = self.operations.list_user_groups(user_id)
        self.assertEqual(expected_data, groups)

        # Member group
        expected_data["own_groups"].remove(group_id)
        expected_data["member_groups"][group_id] = {"permissions": "rw"}
        self.operations.add_user_to_group(user_id, group_id, user_id2, "rw")
        groups = self.operations.list_user_groups(user_id2)
        self.assertEqual(expected_data, groups)

        # Moderator group
        del expected_data["member_groups"][group_id]
        expected_data["moderator_groups"].append(group_id)
        self.operations.add_moderator_to_group(user_id, group_id, user_id2)
        groups = self.operations.list_user_groups(user_id2)
        self.assertEqual(expected_data, groups)
    
    def test_add_file_to_group(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        group_id = self.operations.create_group(user_id, "test")
        filename = "file"
        content = b"oi12jiwsndc90j1"

        # User not member of the group
        with self.assertRaises(PermissionDenied):
            self.operations.add_file_to_group(user_id2, group_id, filename, content)
        
        # User without write permissions
        self.operations.add_user_to_group(user_id, group_id, user_id2, "r")
        with self.assertRaises(PermissionDenied):
            self.operations.add_file_to_group(user_id2, group_id, filename, content)

        # Invalid filename
        with self.assertRaises(InvalidFileName):
            self.operations.add_file_to_group(user_id2, group_id, "invalid:filename", content)

        # Invalid group
        with self.assertRaises(GroupNotFound):
            self.operations.add_file_to_group(user_id2, "invalid:group", filename, content)
        
        # Valid add
        self.operations.add_user_to_group(user_id, group_id, user_id2, "w")
        self.assertNotIn(user_id2, self.config["groups"][group_id]["files"])
        self.operations.add_file_to_group(user_id2, group_id, filename, content)
        self.assertIn(user_id2, self.config["groups"][group_id]["files"])
        self.assertIn(f"{user_id2}:{filename}", self.config["groups"][group_id]["files"][user_id2])
        self.assertIn(filename, self.config["users"][user_id2]["files"])

        # Duplicated filename
        with self.assertRaises(PermissionDenied):
            self.operations.add_file_to_group(user_id2, group_id, filename, b"other_content")
    
    def test_delete_file_from_group(self):
        # Config setup
        user_id = self.operations.create_user("test1")
        user_id2 = self.operations.create_user("test2")
        user_id3 = self.operations.create_user("test3")
        group_id = self.operations.create_group(user_id, "test")
        self.operations.add_user_to_group(user_id, group_id, user_id2, "w")
        filename = "file1"
        content = b"102jidms012msd"

        # File doesn't exists on user vault or group vault
        with self.assertRaises(PermissionDenied):
            self.operations.delete_file_from_group(user_id2, group_id, filename)
        
        self.operations.add_file_to_group(user_id2, group_id, filename, content)

        # Invalid group
        with self.assertRaises(GroupNotFound):
            self.operations.delete_file_from_group(user_id2, "invalid:group", filename)
        
        # User not owner of the file
        with self.assertRaises(PermissionDenied):
            self.operations.delete_file_from_group(user_id3, group_id, filename)
        
        # Invalid filename
        with self.assertRaises(PermissionDenied):
            self.operations.delete_file_from_group(user_id2, group_id, "invalid:filename")

        # Insufficient delete permissions from a moderator
        self.operations.add_moderator_to_group(user_id, group_id, user_id3)
        with self.assertRaises(PermissionDenied):
            self.operations.delete_file_from_group(user_id3, group_id, f"{user_id2}:{filename}")

        # Valid delete from the file owner
        self.operations.delete_file_from_group(user_id2, group_id, f"{user_id2}:{filename}")
        self.assertNotIn(user_id2, self.config["groups"][group_id]["files"])

        # Valid delete from the group owner
        self.operations.add_file_to_group(user_id2, group_id, filename, content)
        self.assertIn(user_id2, self.config["groups"][group_id]["files"])
        self.operations.delete_file_from_group(user_id, group_id, f"{user_id2}:{filename}")
        self.assertNotIn(user_id2, self.config["groups"][group_id]["files"])
        
        # TODO Moderator operations
    #endregion 
        
if __name__ == "__main__":
    unittest.main()