import os, sys
import uuid
import datetime
from common.io import createFileWithData
import configparser

def startup(path):
    if path[-1] != "/":
        path += "/"

    dirNames = ["users", "groups"]
    if not os.path.isdir(path):
        os.mkdir(path, 0o775)
        for name in dirNames:
            os.mkdir(os.path.join(path, name), 0o775)
    else:
        for name in dirNames:
            if not os.path.isdir(os.path.join(path, name)):
                print(f"Server startup failed. Found corrupted directory at: '{path + name}'.")
                sys.exit(1)

    print("Server startup concluded.")
    return path
    


def checkGroupExistance(vaultPath, groupName):
    config = configparser.ConfigParser()
    groupsPath = os.path.join(vaultPath, "groups")
    groupsDirName = os.listdir(groupsPath)

    for dirName in groupsDirName:
        metaPath = os.path.join(groupsPath, dirName, "meta.info")
        try:
            config.read(metaPath, encoding="utf-8")
            if config["group"]["group_name"] == groupName:
                return True
        except (KeyError, FileNotFoundError):
            print(f"Error while reading meta.info file at: {metaPath}")
            exit(1)
    return False



def checkUserExistance(vaultPath, userName):
    config = configparser.ConfigParser()
    usersPath = os.path.join(vaultPath + "users")
    usersDirName = os.listdir(usersPath)

    for dirName in usersDirName:
        metaPath = os.path.join(usersPath, dirName, "meta.info")
        try:
            config.read(metaPath, encoding="utf-8")
            if config["user"]["username"] == userName:
                return True
        except (KeyError, FileNotFoundError):
            print(f"Error while reading meta.info file at: {metaPath}")
            exit(1)
    return False



def setupUserDirectory(vaultPath, username):
    if not checkUserExistance(vaultPath, username):
        userUUID = uuid.uuid4()
        date = datetime.datetime.now().isoformat()
        userDir = os.path.join(vaultPath, "users", str(userUUID))
        dirNames = ["own", "shared"]
        
        os.makedirs(userDir, 0o775)
        for name in dirNames:
            os.mkdir(os.path.join(userDir, name), 0o775)

        data = f"""[user]
user_id = {userUUID}
username = {username}
created_at = {date}

[groups]

[own]

[shared]
"""
    
        createFileWithData(os.path.join(userDir, "meta.info"), data)
        print(f"User {username} - {userUUID} directory created.")
        return userUUID
    else:
        print(f"User with name '{username}' already exists.")



def setupGroupDirectory(vaultPath, groupName, ownerUUID):
    if not checkGroupExistance(vaultPath, groupName):
        groupUUID = uuid.uuid4()
        date = datetime.datetime.now().isoformat()
        groupDir = os.path.join(vaultPath, "groups", str(groupUUID))

        os.makedirs(os.path.join(groupDir, "own"), 0o775)
        data = f"""[group]
group_id = {groupUUID}
group_name = {groupName}
owner_id = {ownerUUID}
created_at = {date}

[users]
macaco : rw
macaco2 : r
macaco3 : w

[files]
"""
        createFileWithData(os.path.join(groupDir, "meta.info"), data)
        print(f"Group {groupName} directory created.")
        return groupUUID
    else:
        print(f"Group with name '{groupName}' already exists.")