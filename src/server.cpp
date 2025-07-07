#include <crow.h>
#include <nlohmann/json.hpp>
#include <SQLiteCpp/SQLiteCpp.h>
#include <sodium.h>
#include <jwt-cpp/jwt.h>
#include <iostream>
#include <string>

using json = nlohmann::json;

// JWT generation and verification functions
std::string generate_jwt(const std::string& username) {
    auto token = jwt::create()
        .set_issuer("rest_server")
        .set_subject(username)
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
        .sign(jwt::algorithm::hs256{"secret_key"});
    return token;
}

bool verify_jwt(const std::string& token, std::string& username, SQLite::Database& db) {
    try {
        // Check if token is blacklisted
        SQLite::Statement query(db, "SELECT expiry FROM token_blacklist WHERE token = ?");
        query.bind(1, token);
        if (query.executeStep()) {
            int64_t expiry = query.getColumn(0).getInt64();
            if (expiry > std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch()).count()) {
                return false; // Token is blacklisted and not yet expired
            }
        }

        // Verify JWT
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{"secret_key"})
            .with_issuer("rest_server");
        verifier.verify(decoded);
        username = decoded.get_subject();
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

// Middleware for JWT authentication
struct AuthMiddleware {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& /*ctx*/) {
        if (req.url == "/api/register" || req.url == "/api/login") {
            return;
        }

        auto auth_header = req.get_header_value("Authorization");
        if (auth_header.empty() || !auth_header.starts_with("Bearer ")) {
            res.code = 401;
            json error = {{"error", "Missing or invalid Authorization header"}, {"status", "error"}};
            res.write(error.dump());
            res.end();
            return;
        }

        std::string token = auth_header.substr(7);
        std::string username;
        SQLite::Database db("users.db", SQLite::OPEN_READWRITE);
        if (!verify_jwt(token, username, db)) {
            res.code = 401;
            json error = {{"error", "Invalid or expired token"}, {"status", "error"}};
            res.write(error.dump());
            res.end();
            return;
        }
        req.add_header("X-Username", username);
    }

    void after_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {}
};

int main() {
    // Initialize sodium for password hashing
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Initialize SQLite database
    SQLite::Database db("users.db", SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
    db.exec("CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY, "
            "password_hash TEXT NOT NULL, "
            "email TEXT NOT NULL, "
            "first_name TEXT NOT NULL, "
            "last_name TEXT NOT NULL, "
            "role TEXT NOT NULL CHECK(role IN ('ADMIN', 'READ', 'WRITE')), "
            "group_name TEXT NOT NULL DEFAULT 'DEFAULT')");
    db.exec("CREATE TABLE IF NOT EXISTS token_blacklist ("
            "token TEXT PRIMARY KEY, "
            "expiry INTEGER NOT NULL)");

    // Initialize Crow application with middleware
    crow::App<AuthMiddleware> app;

    // POST endpoint: /api/register
    CROW_ROUTE(app, "/api/register").methods(crow::HTTPMethod::POST)
    ([&db, &app](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            if (!body.contains("username") || !body.contains("password") ||
                !body.contains("email") || !body.contains("first_name") ||
                !body.contains("last_name") || !body.contains("role")) {
                json error = {{"error", "Missing required fields"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string username = body["username"].get<std::string>();
            std::string password = body["password"].get<std::string>();
            std::string email = body["email"].get<std::string>();
            std::string first_name = body["first_name"].get<std::string>();
            std::string last_name = body["last_name"].get<std::string>();
            std::string role = body["role"].get<std::string>();

            if (role != "ADMIN" && role != "READ" && role != "WRITE") {
                json error = {{"error", "Invalid role. Must be ADMIN, READ, or WRITE"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            SQLite::Statement query(db, "SELECT username FROM users WHERE username = ?");
            query.bind(1, username);
            if (query.executeStep()) {
                json error = {{"error", "Username already exists"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            char hashed_password[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(
                    hashed_password,
                    password.c_str(), password.length(),
                    crypto_pwhash_OPSLIMIT_MODERATE,
                    crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
                json error = {{"error", "Password hashing failed"}, {"status", "error"}};
                return crow::response(500, error.dump());
            }

            SQLite::Statement insert(db, "INSERT INTO users (username, password_hash, email, first_name, last_name, role, group_name) VALUES (?, ?, ?, ?, ?, ?, ?)");
            insert.bind(1, username);
            insert.bind(2, hashed_password);
            insert.bind(3, email);
            insert.bind(4, first_name);
            insert.bind(5, last_name);
            insert.bind(6, role);
            insert.bind(7, "DEFAULT");
            insert.exec();

            json response = {{"status", "success"}, {"message", "User registered successfully"}};
            return crow::response(201, response.dump());
        } catch (const json::exception& e) {
            json error = {{"error", "Invalid JSON format"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(400, error.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // POST endpoint: /api/login
    CROW_ROUTE(app, "/api/login").methods(crow::HTTPMethod::POST)
    ([&db, &app](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            if (!body.contains("username") || !body.contains("password")) {
                json error = {{"error", "Missing username or password"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string username = body["username"].get<std::string>();
            std::string password = body["password"].get<std::string>();

            SQLite::Statement query(db, "SELECT password_hash, email, first_name, last_name, role, group_name FROM users WHERE username = ?");
            query.bind(1, username);
            if (!query.executeStep()) {
                json error = {{"error", "Invalid username or password"}, {"status", "error"}};
                return crow::response(401, error.dump());
            }

            std::string stored_hash = query.getColumn(0).getString();
            if (crypto_pwhash_str_verify(stored_hash.c_str(), password.c_str(), password.length()) != 0) {
                json error = {{"error", "Invalid username or password"}, {"status", "error"}};
                return crow::response(401, error.dump());
            }

            std::string email = query.getColumn(1).getString();
            std::string first_name = query.getColumn(2).getString();
            std::string last_name = query.getColumn(3).getString();
            std::string role = query.getColumn(4).getString();
            std::string group_name = query.getColumn(5).getString();

            std::string token = generate_jwt(username);
            json response = {
                {"status", "success"},
                {"token", token},
                {"user", {
                    {"username", username},
                    {"email", email},
                    {"first_name", first_name},
                    {"last_name", last_name},
                    {"role", role},
                    {"group", group_name}
                }}
            };
            return crow::response(200, response.dump());
        } catch (const json::exception& e) {
            json error = {{"error", "Invalid JSON format"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(400, error.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // POST endpoint: /api/logout
    CROW_ROUTE(app, "/api/logout").methods(crow::HTTPMethod::POST)
    ([&db, &app](const crow::request& req) {
        try {
            auto auth_header = req.get_header_value("Authorization");
            if (auth_header.empty() || !auth_header.starts_with("Bearer ")) {
                json error = {{"error", "Missing or invalid Authorization header"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string token = auth_header.substr(7);
            std::string username;
            if (!verify_jwt(token, username, db)) {
                json error = {{"error", "Invalid or expired token"}, {"status", "error"}};
                return crow::response(401, error.dump());
            }

            auto decoded = jwt::decode(token);
            int64_t expiry = decoded.get_expires_at().time_since_epoch().count() /
                             std::chrono::seconds(1).count();

            SQLite::Statement insert(db, "INSERT INTO token_blacklist (token, expiry) VALUES (?, ?)");
            insert.bind(1, token);
            insert.bind(2, expiry);
            insert.exec();

            json response = {{"status", "success"}, {"message", "Logged out successfully"}};
            return crow::response(200, response.dump());
        } catch (const json::exception& e) {
            json error = {{"error", "Invalid JSON format"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(400, error.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // GET endpoint: /api/user/details
    CROW_ROUTE(app, "/api/user/details").methods(crow::HTTPMethod::GET)
    ([&db, &app](const crow::request& req) {
        try {
            std::string username = req.get_header_value("X-Username");
            if (username.empty()) {
                json error = {{"error", "Unable to retrieve username from token"}, {"status", "error"}};
                return crow::response(401, error.dump());
            }

            SQLite::Statement query(db, "SELECT username, email, first_name, last_name, role, group_name FROM users WHERE username = ?");
            query.bind(1, username);
            if (!query.executeStep()) {
                json error = {{"error", "User not found"}, {"status", "error"}};
                return crow::response(404, error.dump());
            }

            json response = {
                {"status", "success"},
                {"user", {
                    {"username", query.getColumn(0).getString()},
                    {"email", query.getColumn(1).getString()},
                    {"first_name", query.getColumn(2).getString()},
                    {"last_name", query.getColumn(3).getString()},
                    {"role", query.getColumn(4).getString()},
                    {"group", query.getColumn(5).getString()}
                }}
            };
            return crow::response(200, response.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // GET endpoint: /api/users/me
    CROW_ROUTE(app, "/api/users/me").methods(crow::HTTPMethod::GET)
    ([&db, &app](const crow::request& req) {
        try {
            std::string username = req.get_header_value("X-Username");
            if (username.empty()) {
                json error = {{"error", "Unable to retrieve username from token"}, {"status", "error"}};
                return crow::response(401, error.dump());
            }

            SQLite::Statement query(db, "SELECT username, email, first_name, last_name, role, group_name FROM users WHERE username = ?");
            query.bind(1, username);
            if (!query.executeStep()) {
                json error = {{"error", "User not found"}, {"status", "error"}};
                return crow::response(404, error.dump());
            }

            json response = {
                {"status", "success"},
                {"data", {
                    {"username", query.getColumn(0).getString()},
                    {"email", query.getColumn(1).getString()},
                    {"first_name", query.getColumn(2).getString()},
                    {"last_name", query.getColumn(3).getString()},
                    {"role", query.getColumn(4).getString()},
                    {"group", query.getColumn(5).getString()}
                }}
            };
            return crow::response(200, response.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // GET endpoint: /api/hello
    CROW_ROUTE(app, "/api/hello").methods(crow::HTTPMethod::GET)
    ([&app](const crow::request& req) {
        json response = {
            {"message", "Hello from the REST server!"},
            {"status", "success"}
        };
        return crow::response(200, response.dump());
    });

    // GET endpoint: /api/user/<string>
    CROW_ROUTE(app, "/api/user/<string>")
    ([&app](const crow::request& req, const std::string& user_id) {
        json response = {
            {"status", "success"},
            {"data", {
                {"user_id", user_id},
                {"message", "User details retrieved"}
            }}
        };
        return crow::response(200, response.dump());
    });

    // POST endpoint: /api/user (protected by JWT, ADMIN only)
    CROW_ROUTE(app, "/api/user").methods(crow::HTTPMethod::POST)
    ([&db, &app](const crow::request& req) {
        try {
            // Check if requester has ADMIN role
            std::string requester_username = req.get_header_value("X-Username");
            if (requester_username.empty()) {
                json error = {{"error", "Unable to retrieve username from token"}, {"status", "error"}};
                return crow::response(401, error.dump());
            }

            SQLite::Statement role_query(db, "SELECT role FROM users WHERE username = ?");
            role_query.bind(1, requester_username);
            if (!role_query.executeStep()) {
                json error = {{"error", "Requester not found"}, {"status", "error"}};
                return crow::response(404, error.dump());
            }
            std::string requester_role = role_query.getColumn(0).getString();
            if (requester_role != "ADMIN") {
                json error = {{"error", "Unauthorized: ADMIN role required"}, {"status", "error"}};
                return crow::response(403, error.dump());
            }

            // Parse and validate request body
            auto body = json::parse(req.body);
            if (!body.contains("username") || !body.contains("password") ||
                !body.contains("email") || !body.contains("role") ||
                !body.contains("group")) {
                json error = {{"error", "Missing required fields: username, password, email, role, group"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string username = body["username"].get<std::string>();
            std::string password = body["password"].get<std::string>();
            std::string email = body["email"].get<std::string>();
            std::string role = body["role"].get<std::string>();
            std::string group = body["group"].get<std::string>();

            // Validate role
            if (role != "ADMIN" && role != "READ" && role != "WRITE") {
                json error = {{"error", "Invalid role. Must be ADMIN, READ, or WRITE"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            // Check if username already exists
            SQLite::Statement query(db, "SELECT username FROM users WHERE username = ?");
            query.bind(1, username);
            if (query.executeStep()) {
                json error = {{"error", "Username already exists"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            // Generate salted hash using Argon2
            char hashed_password[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(
                    hashed_password,
                    password.c_str(), password.length(),
                    crypto_pwhash_OPSLIMIT_MODERATE,
                    crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
                json error = {{"error", "Password hashing failed"}, {"status", "error"}};
                return crow::response(500, error.dump());
            }

            // Insert new user into database
            SQLite::Statement insert(db, "INSERT INTO users (username, password_hash, email, first_name, last_name, role, group_name) VALUES (?, ?, ?, ?, ?, ?, ?)");
            insert.bind(1, username);
            insert.bind(2, hashed_password);
            insert.bind(3, email);
            insert.bind(4, ""); // first_name (not required for this endpoint)
            insert.bind(5, ""); // last_name (not required for this endpoint)
            insert.bind(6, role);
            insert.bind(7, group);
            insert.exec();

            json response = {{"status", "success"}, {"message", "User created successfully"}};
            return crow::response(201, response.dump());
        } catch (const json::exception& e) {
            json error = {{"error", "Invalid JSON format"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(400, error.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // Set the port and start the server
    app.port(8080)
       .multithreaded()
       .run();

    return 0;
}
