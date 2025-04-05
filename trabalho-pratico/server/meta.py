import os
import configparser
import uuid
import datetime
from common.io import createFileWithData

###########################
#          GERAL          #
########################### 

config = configparser.ConfigParser()

def saveIniFile(path):
    with open(path, "w", encoding="utf-8") as file:
        config.write(file)

###########################
#          GROUPS         #
########################### 

def deleteGroup(vaultPath, groupUUID, userUUID):
    metaPath = os.path.join(vaultPath, "groups", str(groupUUID), "meta.info")

    try:
        config.read(metaPath, encoding="utf-8")
        if config["group"]["owner_id"] == str(userUUID):
            members = config["users"]
            for member in members:
                print(member)
                # ir ao diretorio do membro e remover o ficheiro
        else:
            return False
    except (KeyError, FileNotFoundError):
        print(f"Error while reading meta.info file at: {metaPath}")
        exit(1)

###########################
#          USERS          #
########################### 

def addFileToUser(vaultPath, userUUID, filename, content):
    metaPath = os.path.join(vaultPath, "users", str(userUUID), "meta.info")
    fileUUID = uuid.uuid4()
    date = datetime.datetime.now().isoformat()

    try:
        config.read(metaPath, encoding="utf-8")
        config.set("own", str(fileUUID), "")
        saveIniFile(metaPath)
    except (KeyError, FileNotFoundError):
        print(f"Error while editing meta.info file at: {metaPath}")
        exit(1)
    
    fileDir = os.path.join(vaultPath, "users", str(userUUID), "own", str(fileUUID))
    os.mkdir(fileDir, 0o775)
    createFileWithData(os.path.join(fileDir, str(fileUUID)) + ".vf", content)
    data = f"""[file]
file_id = {fileUUID}
file_name = {filename}
created_at = {date}
last_modified_at = {date}
last_accessed_at = {date}
owner_id = {userUUID}

[acl]
"""
    createFileWithData(os.path.join(fileDir, str(fileUUID)) + ".vfmeta", data)
    return fileUUID



def getFilesOfUser(vaultPath, userUUID):
    metaPath = os.path.join(vaultPath, "users", str(userUUID), "meta.info")

    try:
        config.read(metaPath, encoding="utf-8")
        files = []
        for n, _ in config.items("own"):
            files.append(n)
        return files
    except (KeyError, FileNotFoundError):
        print(f"Error while reading meta.info file at: {metaPath}")
        exit(1)



def getFilesSharedOfUser(vaultPath, userUUID, ownerUUID):
    metaPath = os.path.join(vaultPath, "users", str(userUUID), "meta.info")

    try:
        config.read(metaPath, encoding="utf-8")
        files = []
        for n, v in config.items("shared"):
            if n == str(ownerUUID):
                fuuid = v.split(":")[0].strip()
                perm = v.split(":")[1].strip()
                files.append((fuuid, perm))
        return files
    except (KeyError, FileNotFoundError):
        print(f"Error while reading meta.info file at: {metaPath}")
        exit(1)



# TODO Test this function
def getFilesGroupOfUser(vaultPath, userUUID, groupUUID):
    metaPath = os.path.join(vaultPath, "users", str(userUUID), "meta.info")

    try:
        config.read(metaPath, encoding="utf-8")
        files = []
        for guuid, perm in config.items("shared"):
            groupMetaPath = os.path.join(vaultPath, "groups", str(guuid), "meta.info")
            groupConfig = config.read(groupMetaPath, encoding="utf-8")
            for filename in groupConfig.items("own"):
                files.append((filename, perm))
        return files
    except (KeyError, FileNotFoundError):
        print(f"Error while reading meta.info file at: {metaPath}")
        exit(1)



# TODO verify permissions value
def shareFileWithUser(vaultPath, ownerUUID, fileUUID, userUUID, permissions):
    metaPath = os.path.join(vaultPath, "users", str(ownerUUID), "meta.info")
    fileUUID = str(fileUUID)

    try:
        # Verify file existance on owner sidecar
        # TODO Fazer a validacao se o ficheiro realmente existe no os. Se nao existir, e' um erro a mostrar ao utilizador
        config.read(metaPath, encoding="utf-8")
        exists = config.has_option("own", fileUUID)

        if exists:
            # Add entry to the acl
            fileMetaPath = os.path.join(vaultPath, "users", str(ownerUUID), "own", fileUUID, fileUUID + ".vfmeta")
            config.clear()
            config.read(fileMetaPath, encoding="utf-8")
            found = config.has_option("acl", str(userUUID))
            
            if found:
                print(f"File {fileUUID} found on ACL! Appending permissions...")
                oldPermissions = config.get("acl", str(userUUID))
                permissions = "".join(sorted(set(oldPermissions + permissions)))

            config.set("acl", str(userUUID), permissions)
            saveIniFile(fileMetaPath)

            # Add entry to shared user sidecar
            sharedUserMetaPath = os.path.join(vaultPath, "users", str(userUUID), "meta.info")
            config.clear()
            config.read(sharedUserMetaPath, encoding="utf-8")
            # TODO Corrigir esta adicao. Utilizar a ',' para separar os ficheiros que sejam do mesmo dono
            # assim ele nao vai dar overwrite do value
            # TODO ir ao getFilesSharedOfUser e adicionar esta parte da ','
            config.set("shared", str(ownerUUID), f"{fileUUID} : {permissions}")
            saveIniFile(sharedUserMetaPath)

            # Add entry to shared folder of the shared user
            keySharedUserPath = os.path.join(vaultPath, "users", str(userUUID), "shared", str(ownerUUID) + "_" + str(fileUUID) + ".vfkey")
            createFileWithData(keySharedUserPath, "chaveMisteriosa")
        else:
            print(f"File '{fileUUID}' doesn't have an entry at user '{ownerUUID}' sidecar.") 

    except (KeyError, FileNotFoundError):
        print(f"Error while reading meta.info file at: {metaPath}")
        exit(1)



def deleteFile(vaultPath, userUUID, fileUUID):
    metaPath = os.path.join(vaultPath, "users", str(userUUID), "meta.info")
    try:
        config.read(metaPath, encoding="utf-8")
        if config.has_option("own", str(fileUUID)):
            print("File is located at the user personal vault.")
            fileMetaPath = os.path.join(vaultPath, "users", str(userUUID), "own", str(fileUUID), str(fileUUID) + ".vfmeta")
            config.clear()
            config.read(fileMetaPath, encoding="utf-8")
            acl = config.items("acl")
            for sharedUserUUID, _ in acl:
                sharedUserMetaPath = os.path.join(vaultPath, "users", sharedUserUUID, "meta.info")
                config.clear()
                config.read(sharedUserMetaPath, encoding="utf-8")
                config.remove_option("shared", str(fileUUID))
                sharedUserFileDir = os.path.join(vaultPath, "users", str(sharedUserUUID), "shared", str(userUUID) + "_" + str(fileUUID) + ".vfkey")
                os.remove(sharedUserFileDir)

    except (KeyError, FileNotFoundError) as e:
        print(e)
        exit(1)