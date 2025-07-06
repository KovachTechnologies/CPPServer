# CPPServer
C++ Server is a basic implementation of a REST server which handles json written in C++.  We use sodium for password hashing, SQLite to store the user data, JSON Web Tokens (JWTs) with a 24 hour expiry to use as access tokens to get access to restricted data.

# Prerequisites

* Install boost
```
sudo apt install libboost-all-dev
```

* Install ASIO
```
sudo apt install libasio-dev
```

# Install Dependencies

* Download sodium - select "LATEST.tar.gz" [here](https://download.libsodium.org/libsodium/releases/), then unpack in the desired location

* In the project root directory, Configure, make, install
```
./configure
make && make check
sudo sudo make install
```

* Clone jwt-cpp
```
git clone https://github.com/Thalhammer/jwt-cpp.git
```

* Clone SQLiteCPP

```
git clone https://github.com/SRombauts/SQLiteCpp.git
```

* In the json project root directory, run

```
cmake .
make
sudo make install
```

* Clone CROW library

```
git clone http://github.com/CrowCpp/Crow.git
```

* In the json project root directory, run

```
cmake .
make
sudo make install
```

* Clone JSON library

```
git clone http://github.com/nlohmann/json.git
```

* In the json project root directory, run

```
cmake .
make
sudo make install
```

# Compile main application

* Clone repository
```
git clone https://github.com/KovachTechnologies/CPPServer.git
```

* Change back to CPPServer directory
```
cmake .
make
```

# Endpoints

- `/register`
    - POST
        - username
        - password
        - email
        - first_name
        - last_name
        - role
        - group

- `/login`
    - POST
        - username
        - password

- `/logout`
    - GET

- `/users/me`
    - GET

- `/user`
    - POST
        - username
        - password
        - email
        - role
        - group

- `/user/{user_id}`
    - GET
        - username
    - PUT
        - username
    - DELETE
        - username

- `/user/search`
    - POST
        - username
        - group
        - role

- `/user/role`
    - POST
        - username
        - role

- `/role/{name}`
    - GET
        - username

- `/user/roles`
    - GET

- `/user/group`
    - POST
        - groupname

- `/user/group/(name}`
    - GET
        - groupname
    - PUT
        - groupname
    - DELETE
        - groupname

- `/user/groups`
    - GET

# Test cases 

* Registration
```
python3 test.py -1
```

* Login 
```
python3 test.py -2
```

* Login, then request data at restricted endpoint 
```
python3 test.py -3
```

* Try to authenticate with a bad token (should fail) 
```
python3 test.py -4
```


