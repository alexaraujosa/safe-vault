# TODO add logs

# Client commands usage
_add                    = "add <file-path>"
_list                   = "list [-u user_id | -g group_id]"
_share                  = "share <file-id> <user-id> <permissions>"
_delete                 = "delete <file-id>"
_replace                = "replace <file-id> <file-path>"
_details                = "details <file-id>"
_revoke                 = "revoke <file-id> <user-id>"
_read                   = "read <file-id>"

# Group commands usage
_group_create           = "group create <group-name>"
_group_delete           = "group delete <group-id>"
_group_add_user         = "group add-user <group-id> <user-id> <permissions>"
_group_delete_user      = "group delete-user <group-id> <user-id>"
_group_list             = "group list"
_group_add              = "group add <group-id> <file-path>"
_group_delete_file      = "group delete <group-id> <file-id>"
_group_add_moderator    = "group add-moderator <group-id> <user-id>"
_group_remove_moderator = "group remove-moderator <group-id> <user-id>"

_group = f"""
Group commands usage:
    {_group_create}
    {_group_delete}
    {_group_add_user}
    {_group_delete_user}
    {_group_list}
    {_group_add}
    {_group_delete_file}
    {_group_add_moderator}
    {_group_remove_moderator}
"""

# Full usage
_full = f"""
Client commands usage:
    {_add}
    {_list}
    {_share}
    {_delete}
    {_replace}
    {_details}
    {_revoke}
    {_read}
{_group}
Logs commands usage:
    TODO
Other commands:
    exit
"""
