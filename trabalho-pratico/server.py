import sys, uuid, os, datetime, re
from server.setup import startup, setupUserDirectory, setupGroupDirectory
from server.meta import deleteGroup, addFileToUser, getFilesOfUser, shareFileWithUser, getFilesSharedOfUser, deleteFile

VAULT_PATH = ""

def main(argv):
    global VAULT_PATH
    VAULT_PATH = startup(argv[1])

    # User creation
    uuuid = setupUserDirectory(VAULT_PATH, "bloody")
    snduuuid = setupUserDirectory(VAULT_PATH, "bloody2")

    # Add file to user
    fileuuid = addFileToUser(VAULT_PATH, uuuid, "primeiro", "nadaDeMais1.0")
    file2uuid = addFileToUser(VAULT_PATH, uuuid, "segundo", "nadaDeMais2.0")
    print(f"File 1: {fileuuid}")
    print(f"File 2: {file2uuid}")

    # Share file with user
    shareFileWithUser(VAULT_PATH, uuuid, fileuuid, snduuuid, "r")
    # shareFileWithUser(VAULT_PATH, uuuid, fileuuid, snduuuid, "rw")
    shareFileWithUser(VAULT_PATH, uuuid, file2uuid, snduuuid, "w")

    # # List shared files
    # print(f"Shared files: {getFilesSharedOfUser(VAULT_PATH, snduuuid, uuuid)}")

    # # Delete file
    # deleteFile(VAULT_PATH, uuuid, file2uuid)

    # # List own files
    # print(f"User own files: {getFilesOfUser(VAULT_PATH, uuuid)}")
    # # List shared files
    # print(getFilesSharedOfUser(VAULT_PATH, snduuuid, uuuid))

    # guuid = setupGroupDirectory(VAULT_PATH, "anonymous", uuuid)
    # deleteGroup(VAULT_PATH, guuid, uuuid)
    

if __name__ ==  "__main__":
    main(sys.argv)