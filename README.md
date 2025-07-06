# CPPServer
C++ Server

# Install Dependencies

* Download sodium
```
https://download.libsodium.org/libsodium/releases/
```

* 
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
