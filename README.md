# CPPServer
C++ Server

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
git clone git@github.com:Thalhammer/jwt-cpp.git
```

* Clone SQLiteCPP

```
git clone git@github.com:SRombauts/SQLiteCpp.git
```

* In the json project root directory, run

```
cmake .
make
make install
```

* Clone CROW library

```
git clone git@github.com:CrowCpp/Crow.git
```

* In the json project root directory, run

```
cmake .
make
make install
```

* Clone JSON library

```
git clone git@github.com:nlohmann/json.git
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
