cmake_minimum_required(VERSION 3.15)

project(RestServer LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(Crow CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(SQLiteCpp CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)

#set(SODIUM_LIBRARY_PATH /Users/danielkovach/Documents/GitHub/libsodium-stable )
find_library(SODIUM_LIBRARY_PATH sodium HINTS /usr/local/lib )


# Add executable
add_executable(RestServer src/server.cpp)

# Link libraries
target_link_libraries(RestServer PRIVATE 
    Crow::Crow 
    nlohmann_json::nlohmann_json 
    SQLiteCpp 
    ${SODIUM_LIBRARY_PATH}
    jwt-cpp::jwt-cpp
)

# Enable threading support
find_package(Threads REQUIRED)
target_link_libraries(RestServer PRIVATE Threads::Threads)

# Set output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

enable_testing()

add_test(test_server python3 -m unittest unit_tests.py)
