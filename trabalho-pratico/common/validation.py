from common.exceptions import InvalidParameter
import os


def is_valid_name(name: str) -> bool:
    "Check if the given name is valid, i.e., not empty and alphanumeric."
    return isinstance(name, str) and len(name) > 0 and name.isalnum()


def is_valid_file_name(file_name: str) -> bool:
    "Check if the given file name is valid, i.e., not empty."
    return isinstance(file_name, str) and len(file_name) > 0


def is_valid_file(file_path: str) -> bool:
    "Check if the given file path exists."
    return os.path.exists(file_path)


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
        or not is_valid_name(partitioned_value[0])
        or not is_valid_file_name(partitioned_value[2])
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


def is_valid_size(size: int) -> bool:
    "Check if the given size is valid, i.e., greater than 0."
    return isinstance(size, int) and size > 0


def is_valid_file_path(file_path: str) -> bool:
    "Check if the given path is valid."
    return os.path.exists(file_path)


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
    - size:        int
    - file_path:   string

    Raises:
    - ValueError for the first validation error found.
    - InvalidParameter for unsupported parameters.
    """
    for key, value in kwargs.items():
        match key:
            case "user_ids":
                for user in value:
                    if not is_valid_name(user):
                        raise ValueError(f"Invalid user ID: '{user}'")
            case "user_id":
                if not is_valid_name(value):
                    raise ValueError(f"Invalid user ID: '{value}'")
            case "group_id":
                if not is_valid_name(value):
                    raise ValueError(f"Invalid group ID: '{value}'")
            case "file_id":
                if not is_valid_file_id(value):
                    raise ValueError(f"Invalid file ID: '{value}'")
            case "file_name":
                if not is_valid_file_name(value):
                    raise ValueError(f"Invalid file name: '{value}'")
            case "permissions":
                if not is_valid_permissions(value):
                    raise ValueError(f"Invalid permissions: '{value}'")
            case "key":
                if not is_valid_key(value):
                    raise ValueError(f"Invalid key: '{value}'")
            case "size":
                if not is_valid_size(value):
                    raise ValueError(f"Invalid size: '{value}'")
            case "file_path":
                if not is_valid_file_path(value):
                    raise ValueError(f"Invalid file path: '{value}'")
            case _:
                raise InvalidParameter(key)
