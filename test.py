import requests

# Base URL
BASE_URL = "http://localhost:8080/api"

# 1. Register
def register() :
    register_payload = {
        "username": "johndoe",
        "password": "mypassword"
    }
    register_response = requests.post(
        f"{BASE_URL}/register",
        json=register_payload,
        headers={"Content-Type": "application/json"}
    )
    print("Register Response:", register_response.status_code, register_response.text)

# 2. Login
def login() :
    login_payload = {
        "username": "johndoe",
        "password": "mypassword"
    }
    login_response = requests.post(
        f"{BASE_URL}/login",
        json=login_payload,
        headers={"Content-Type": "application/json"}
    )

    print("Login Response:", login_response.status_code, login_response.text)

    # Extract token from response
    try:
        token = login_response.json().get("token")  # Adjust key if API uses a different one
    except Exception as e:
        print("Error extracting token:", e)
        token = None
    return token

# 3. Access protected endpoint
def request( token ) :
    if token:
        protected_response = requests.get(
            f"{BASE_URL}/hello",
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

if __name__ == "__main__" :
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-1', '--register',  action='store_true')
    parser.add_argument('-2', '--login',  action='store_true')
    parser.add_argument('-3', '--request',  action='store_true')

    args = parser.parse_args()

    if args.register :
        register()

    if args.login :
        login()

    if args.request :
        token = login()
        request( token )
