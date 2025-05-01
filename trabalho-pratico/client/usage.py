# Client commands usage
_add                      = "add <file-path>"
_list                     = "list [-u user_id | -g group_id]"
_share                    = "share <file-id> <user-id> <permissions>"
_delete                   = "delete <file-id>"
_replace                  = "replace <file-id> <file-path>"
_details                  = "details <file-id>"
_revoke                   = "revoke <file-id> <user-id>"
_read                     = "read <file-id>"

# Group commands usage
_group_create             = "group create <group-name>"
_group_delete             = "group delete <group-id>"
_group_add_user           = "group add-user <group-id> <user-id> <permissions>"
_group_delete_user        = "group delete-user <group-id> <user-id>"
_group_list               = "group list"
_group_add                = "group add <group-id> <file-path>"
_group_delete_file        = "group delete-file <group-id> <file-id>"
_group_change_permissions = "group change-permissions <group-id> <user-id> <permissions>"
_group_add_moderator      = "group add-moderator <group-id> <user-id>"
_group_remove_moderator   = "group remove-moderator <group-id> <user-id>"

# Log commands usage
_logs_user_global  = "logs global [-g group_id]"
_logs_user_file    = "logs file <file-id>"
_logs_user_group   = "logs group <group-id>"

_group = f"""
Group commands usage:
    {_group_create}
    {_group_delete}
    {_group_add_user}
    {_group_delete_user}
    {_group_list}
    {_group_add}
    {_group_delete_file}
    {_group_change_permissions}
    {_group_add_moderator}
    {_group_remove_moderator}
"""

_logs = f"""
Log commands usage:
    {_logs_user_global}
    {_logs_user_file}
    {_logs_user_group}
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
{_logs}
Other commands:
    exit
"""
