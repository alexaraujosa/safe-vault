class PermissionDenied(Exception):
    """Raised when a user lacks required permissions for an operation."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class UserExists(Exception):
    """Raised when a user already exists in the system."""

    def __init__(self, user_id: str):
        self.message = f"User {user_id} already exists."
        super().__init__(self.message)


class UserNotFound(Exception):
    """Raised when a user is not found in the system."""

    def __init__(self, user_id: str):
        self.message = f"User {user_id} does not exist."
        super().__init__(self.message)


class SharedUserNotFound(Exception):
    """Raised when a user doesn't have the shared user entry."""

    def __init__(self, user_id: str, shared_user_id: str):
        self.message = f"User {user_id} doesn't have any files shared by {shared_user_id}."
        super().__init__(self.message)


class GroupExists(Exception):
    """Raised when a group already exists in the system."""

    def __init__(self, group_id: str):
        self.message = f"Group {group_id} already exists."
        super().__init__(self.message)


class GroupNotFound(Exception):
    """Raised when a group is not found in the system."""

    def __init__(self, group_id: str):
        """Initialize the exception with a group ID."""
        self.message = f"Group {group_id} does not exist."
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


class FileNotFoundOnVault(Exception):
    """Raised when a file is not found in a user vault."""

    def __init__(self, file_id: str, user_id: str):
        self.message = f"File {file_id} does not exists on user {user_id} vault."
        super().__init__(self.message)


class InvalidParameter(Exception):
    """Raised when a unsupported parameter is passed to a function."""

    def __init__(self, name: str):
        self.message = f"Unsupported parameter: {name}."
        super().__init__(self.message)


class NeedConfirmation(Exception):
    """Raised when a user needs to confirm an action."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
