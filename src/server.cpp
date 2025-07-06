#include <crow.h>
#include <nlohmann/json.hpp>
#include <SQLiteCpp/SQLiteCpp.h>
#include <sodium.h>
#include <jwt-cpp/jwt.h>
#include <iostream>
#include <string>

// Use nlohmann::json for convenience
using json = nlohmann::json;

// JWT generation and verification functions
std::string generate_jwt(const std::string& username) {
    auto token = jwt::create()
        .set_issuer("rest_server")
        .set_subject(username)
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
        .sign(jwt::algorithm::hs256{"secret_key"}); // Replace "secret_key" with a secure key
    return token;
}

bool verify_jwt(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{"secret_key"})
            .with_issuer("rest_server");
        verifier.verify(decoded);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

// Middleware for JWT authentication
struct AuthMiddleware {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& /*ctx*/) {
        // Skip authentication for /api/register and /api/login
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

        std::string token = auth_header.substr(7); // Remove "Bearer " prefix
        if (!verify_jwt(token)) {
            res.code = 401;
            json error = {{"error", "Invalid or expired token"}, {"status", "error"}};
            res.write(error.dump());
            res.end();
            return;
        }
    }

    void after_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {
        // No action needed after handling
    }
};

int main() {
    // Initialize sodium for password hashing
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Initialize SQLite database
    SQLite::Database db("users.db", SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
    db.exec("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)");

    // Initialize Crow application with middleware
    crow::App<AuthMiddleware> app;

    // POST endpoint: /api/register
    CROW_ROUTE(app, "/api/register").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            if (!body.contains("username") || !body.contains("password")) {
                json error = {{"error", "Missing username or password"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string username = body["username"].get<std::string>();
            std::string password = body["password"].get<std::string>();

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

            // Store user in database
            SQLite::Statement insert(db, "INSERT INTO users (username, password_hash) VALUES (?, ?)");
            insert.bind(1, username);
            insert.bind(2, hashed_password);
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
    ([&db](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            if (!body.contains("username") || !body.contains("password")) {
                json error = {{"error", "Missing username or password"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string username = body["username"].get<std::string>();
            std::string password = body["password"].get<std::string>();

            // Retrieve user from database
            SQLite::Statement query(db, "SELECT password_hash FROM users WHERE username = ?");
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

            // Generate JWT
            std::string token = generate_jwt(username);
            json response = {{"status", "success"}, {"token", token}};
            return crow::response(200, response.dump());
        } catch (const json::exception& e) {
            json error = {{"error", "Invalid JSON format"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(400, error.dump());
        } catch (const SQLite::Exception& e) {
            json error = {{"error", "Database error"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(500, error.dump());
        }
    });

    // GET endpoint: /api/hello (protected by JWT)
    CROW_ROUTE(app, "/api/hello").methods(crow::HTTPMethod::GET)
    ([](const crow::request& req) {
        json response = {
            {"message", "Hello from the REST server!"},
            {"status", "success"}
        };
        return crow::response(200, response.dump());
    });

    // POST endpoint: /api/user (protected by JWT)
    CROW_ROUTE(app, "/api/user").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        try {
            auto body = json::parse(req.body);
            if (!body.contains("name") || !body.contains("email")) {
                json error = {{"error", "Missing required fields: name and email"}, {"status", "error"}};
                return crow::response(400, error.dump());
            }

            std::string name = body["name"].get<std::string>();
            std::string email = body["email"].get<std::string>();

            json response = {
                {"status", "success"},
                {"data", {
                    {"name", name},
                    {"email", email},
                    {"message", "User data received successfully"}
                }}
            };
            return crow::response(200, response.dump());
        } catch (const json::exception& e) {
            json error = {{"error", "Invalid JSON format"}, {"details", e.what()}, {"status", "error"}};
            return crow::response(400, error.dump());
        }
    });

    // GET endpoint with parameter: /api/user/<string> (protected by JWT)
    CROW_ROUTE(app, "/api/user/<string>")
    ([](const crow::request& req, const std::string& user_id) {
        json response = {
            {"status", "success"},
            {"data", {
                {"user_id", user_id},
                {"message", "User details retrieved"}
            }}
        };
        return crow::response(200, response.dump());
    });

    // Set the port and start the server
    app.port(8080)
       .multithreaded()
       .run();

    return 0;
}
