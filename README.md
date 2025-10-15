# keepassxc-protocol
Interaction protocol for KeePassXC GUI

*(Not tested with Linux, but might work.)*



## Examples

### Get logins:
```python
from keepassxc_protocol import Connection

con = Connection()
con.associate() # Associate request for current ACTIVE database

response = con.get_logins("https://example.test") # Get ALL data for example.test. CAN be specified without http\https.
entry = response.entries[0] # First ecntry for example.test.

print(entry.group) # Output: "group2"
print(entry.login) # Output: "example_test_login"
print(entry.password) # Output: "example_test_password"
print(entry.name) # Output: "example_test"
print(entry.uuid) # Output: "4cbbe6a7efeb46458c5501e7203209e5"
print(entry.totp) # Output: "579423"

print(response.model_dump_json(indent=2))
# Output:
# {
#   "count": 1,
#   "nonce": "/r+xzDXU77NPZxA1CvHv/XWGFx2sgqXa",
#   "success": "true",
#   "hash": "8f1b004cbd837de560b9257b61443f9ae21ee24f4561c87b8f2bb3a6fa7627e0",
#   "version": "2.7.10",
#   "entries": [
#     {
#       "group": "group2",
#       "login": "example_test_login",
#       "name": "example_test",
#       "password": "example_test_password",
#       "uuid": "4cbbe6a7efeb46458c5501e7203209e5",
#       "stringFields": [],
#       "totp": "579423"
#     }
#   ]
# }
```

### Save associates
```python
from keepassxc_protocol import Connection

con = Connection()
con.associate() # Associate request for current ACTIVE database

associates = con.dump_associate_json() # Get ALL associates as json string

with open("associates.json", "w") as f:
    f.write(associates)
```

### Load associates
```python
from keepassxc_protocol import Connection

con = Connection()

with open("associates.json", "r") as f:
    associates = f.read()

con.load_associates_json(associates) # Load associates from json string.
                                     # This REPLACES the current associates if they exist.

response = con.get_logins("https://example.test") # Get ALL data for example.test.
```




## Features

### Actions ([link](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md)):
* ✅associate
* ✅change-public-keys
* ❌create-new-group
* ❌generate-password
* ✅get-database-gropus
* ✅get-databasehash
* ✅get-logins
* ❎get-totp *(deprecated? totp is available in get-logins)*
* ❌lock-database
* ❌request-autotype
* ❌set-login
* ✅test-associate
* ❌passkey-get
* ❌passkey-register