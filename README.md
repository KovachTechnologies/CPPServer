# CPPServer
C++ Server is a basic implementation of a REST server which handles json written in C++.  We use sodium for password hashing, SQLite to store the user data, JSON Web Tokens (JWTs) with a 24 hour expiry to use as access tokens to get access to restricted data.

# Install Dependencies

* Download sodium - select "LATEST.tar.gz" [here](https://download.libsodium.org/libsodium/releases/), then unpack in the desired location

* In the project root directory, Configure, make, install
```
./configure
make && make check
sudo make install
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
make install
```

* Clone CROW library

```
git clone http://github.com/CrowCpp/Crow.git
```

* In the json project root directory, run

```
cmake .
make
make install
```

* Clone JSON library

```
git clone http://github.com/nlohmann/json.git
```

* In the json project root directory, run

```
cmake .
make
make install
```

# Compile main application

* Change back to CPPServer directory
```
cmake .
make
```

# Run test cases

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

# Endpoints

- `/register`
    - POST

- `/login`
    - POST

- `/logout`
    - GET

- `/users/me`
    - GET

- `/user`
    - POST

- `/user/{user_id}`
    - GET

- `/user/search`
    - POST

- `/user/role`
    - POST

- `/role/{name}`
    - GET

- `/user/roles`
    - GET

- `/user/group`
    - POST

- `/user/group/(name}`
    - GET

- `/user/groups`
    - GET
