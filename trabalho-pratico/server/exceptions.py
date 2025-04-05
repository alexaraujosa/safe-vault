class PermissionDenied(Exception):
    """Raised when a user lacks required permissions for an operation."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class GroupNotFound(Exception):
    """Raised when a group is not found in the system."""

    def __init__(self, group_id: str):
        """Initialize the exception with a group ID."""
        self.message = f"Group {group_id} does not exist."
        super().__init__(self.message)


class UserNotFound(Exception):
    """Raised when a user is not found in the system."""

    def __init__(self, user_id: str):
        self.message = f"User {user_id} does not exist."
        super().__init__(self.message)


class InvalidPermission(Exception):
    """Raised when an invalid permission is provided."""

    def __init__(self, permission: str):
        self.message = f"Invalid permission: {permission}.\n" \
                       "Valid permissions are: r, w, rw."
        super().__init__(self.message)


class UserNotMemberOfGroup(Exception):
    """Raised when a user is not a member of a group."""

    def __init__(self, user_id: str, group_id: str):
        self.message = f"User {user_id} is not a member of group {group_id}."
        super().__init__(self.message)


class FileNotFound(Exception):
    """Raised when a file is not found in the system."""

    def __init__(self, file_id: str):
        self.message = f"File {file_id} does not exist."
        super().__init__(self.message)
