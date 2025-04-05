
def createFileWithData(path, data):
    with open(path, "w", encoding="utf-8") as file:
        file.write(data)