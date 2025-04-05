# Project Architecture v1.0.0

## Vault File Structure
- Content is held on the main file. Metadata and ACL is kept on a sidecar file.

### Main File
- `FILE_ID`: The ID of the file. Used to pair with the sidecar.
- `CONTENT`: The encrypted content of the file.

### Meta File (sidecar)
- `FILE_ID`: The ID of the file. Used to pair with the main file.
- `FILE_NAME`: The cleartext name of the file.
- `CREATED_AT`: The Unix Timestamp for the date this file was created at.
- `LAST_MODIFIED_AT`: The Unix Timestamp for the date this file was last modified at.
- `LAST_ACCESSED_AT`: The Unix Timestamp for the date this file was last accessed at.
- `OWNER_ID`: The UUID for the user/group that owns this file.
- `ACL`: The Access Control List for this file. Each entry must be kept in sync with the corresponding user's `SHARED_FILES`.
  - `<LINE>`: `<UUID>`:`<PERM>`
    - `UUID`: The UUID for the foreign user that has access to this file.
    - `PERM`: The permission the foreign user has over this file. Can `READ`, `WRITE` or both.


# User meta.inf File
- `USER_ID`: The ID of the user.
- `USERNAME`: The cleartext username for this user. Must be unique.
- `CREATED_AT`: The Unix Timestamp for the date this user was created at.
- `GROUPS`: The list of groups the user is in. Kept in sync with the group's `USERS`.
  - `<LINE>`: `<GUUID>`:`<PERM>`
    - `GUUID`: The Group ID.
    - `PERM`: The permission the foreign user has on the group. Can `READ`, `WRITE` or both.
- `OWN_FILES`:
  - `<LINE>`: `<FUUID>`
    - `FUUID`: The File ID.
- `SHARED_FILES`: The list of foreign files shared with this user. Kept in sync with the File's ACL.
  - `<LINE>`: `<UUUID>`:`<FUUID>`:`<PERM>`
    - `UUUID`: The User ID of the file owner.
    - `FUUID`: The File ID.
    - `PERM`: The permission the foreign user has over the file. Can `READ`, `WRITE` or both.

# Group meta.inf File
- `GROUP_ID`: The ID of the group.
- `GROUPNAME`: The cleartext group name. Must be unique.
- `OWNER_ID`: The User ID of the the group's owner.
- `CREATED_AT`: The Unix Timestamp for the date this group was created at.
- `USERS`: The list of users that belong to this group. Must be kept in sync with each corresponding user's `GROUPS`.
  - `<UUUID>`:`<PERM>`
    - `UUID`: The UUID for the user.
    - `PERM`: The permission the user has over files under this group's ownership. Can `READ`, `WRITE` or both.
- `OWN_FILES`:
  - `<LINE>`: `<FUUID>`
    - `FUUID`: The File ID.

# File Structure
- `users`: A directory containing entries for every user in the system.
  - `<UUUID>`: The User ID for the entry.
    - `meta.inf`: The user's [Meta-Info File](#user-metainf-file).
    - `own`: A directory containing the user's own files.
      - `<FUUID>.vf` (and `<FUUID>.vfmeta`): A [Vault file](#vault-file-structure).
    - `shared`: A directory containing data pertaining to files shared with the user.
      - `<UUUID>_<FUUID>.vfkey`: The shared key for the file `FFUID`, shared by the user `UUID`.
- `groups`: A directory containing entries for every group in the system.
  - `<GUUID>`: The Group ID for the entry.
    - `meta.inf`: The groups's [Meta-Info File](#group-metainf-file).
    - `own`: A directory containing the groups's files.
      - `<FUUID>`: A directory containing data pertaining to a given file.
        - `<FUUID>.vf` (and `<FUUID>.vfmeta`): A [Vault file](#vault-file-structure).
        - `keys`: A directory containing the key for each group's user, for the given file.
          - `<UUUID>.vfkey`: The key for the user `UUUID`.