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


class InvalidPermissions(Exception):
    """Raised when invalid permissions are provided."""

    def __init__(self, permission: str):
        self.message = f"Invalid permission: {permission}.\n" \
                       "Valid permissions are: 'r', 'w' and 'rw'."
        super().__init__(self.message)


class UserNotMemberOfGroup(Exception):
    """Raised when a user is not a member of a group."""

    def __init__(self, user_id: str, group_id: str):
        self.message = f"User {user_id} is not a member of group {group_id}."
        super().__init__(self.message)


class UserNotModeratorOfGroup(Exception):
    """Raised when a user is not a moderator of a group."""

    def __init__(self, user_id: str, group_id: str):
        self.message = f"User {user_id} is not a moderator of group {group_id}."
        super().__init__(self.message)


class GroupAlreadyExists(Exception):
    """Raised when a group already exists in the system."""

    def __init__(self, group_id: str):
        self.message = f"Group {group_id} already exists."
        super().__init__(self.message)
