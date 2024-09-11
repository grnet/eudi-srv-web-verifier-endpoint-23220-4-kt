import cbor2

project = {
        "name": "Marios",
        "language": "Python",
        }

with open("project.cbor", "wb") as f:
    cbor2.dump(project, f)
