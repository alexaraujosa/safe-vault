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
        # TODO

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
        # TODO

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
        
if __name__ == "__main__":
    unittest.main()