import requests

# Base URL
BASE_URL = "http://localhost:8080/api"

# Register
def register() :
    register_payload = {
        "username": "johndoe",
        "password": "mypassword",
        "email":"john@example.com",
        "first_name":"John",
        "last_name":"Doe",
        "role":"ADMIN",
        "group":"DEFAULT"
    }
    register_response = requests.post(
        f"{BASE_URL}/register",
        json=register_payload,
        headers={"Content-Type": "application/json"}
    )
    print("Register Response:", register_response.status_code, register_response.text)

# Login
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

# Access protected endpoint
def request( token ) :
    if token:
        protected_response = requests.get(
            f"{BASE_URL}/hello",
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

# Logout 
def logout( token ) :
    if token:
        protected_response = requests.post(
            f"{BASE_URL}/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

# me 
def me( token ) :
    if token:
        protected_response = requests.get(
            f"{BASE_URL}/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

def add_user( token ) :
    if token:
        user_payload = {
            "username":"admin1",
            "password":"securepass123",
            "email":"admin@example.com",
            "first_name":"Admin",
            "last_name":"One",
            "role":"ADMIN",
            "group":"DEFAULT"
        }

        protected_response = requests.post(
            f"{BASE_URL}/user",
            json=user_payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

def get_user( token ) :
    if token :
        protected_response = requests.get(
            f"{BASE_URL}/user/admin1",
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

def delete_user( token ) :
    if token :
        protected_response = requests.delete(
            f"{BASE_URL}/user/admin1",
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)
    else:
        print("No token retrieved, cannot access protected endpoint.")

def search( token ) :
    if token:
        payload = {
            "username":"johndoe",
        }

        protected_response = requests.post(
            f"{BASE_URL}/user/search",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)

        payload = {
            "role":"ADMIN",
        }

        protected_response = requests.post(
            f"{BASE_URL}/user/search",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)

        payload = {
            "group":"DEFAULT",
        }

        protected_response = requests.post(
            f"{BASE_URL}/user/search",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        print("Protected Response:", protected_response.status_code, protected_response.text)

    else:
        print("No token retrieved, cannot access protected endpoint.")

def role( token ) :
    if token:
        payload = {
            "username":"admin1",
            "role" : "READ"
        }

        protected_response = requests.post(
            f"{BASE_URL}/user/role",
            json=payload,
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
    parser.add_argument('-4', '--request-fail',  action='store_true')
    parser.add_argument('-5', '--login-logout',  action='store_true')
    parser.add_argument('-6', '--me',  action='store_true')
    parser.add_argument('-7', '--add-user',  action='store_true')
    parser.add_argument('-8', '--get-user',  action='store_true')
    parser.add_argument('-9', '--delete-user',  action='store_true')
    parser.add_argument('-a', '--search',  action='store_true')
    parser.add_argument('-b', '--role',  action='store_true')

    args = parser.parse_args()

    if args.register :
        register()

    if args.login :
        login()

    if args.request :
        token = login()
        request( token )

    if args.request_fail :
        token = "bad-token" 
        request( token )

    if args.login_logout :
        token = login()
        logout( token )
        request( token )

    if args.me :
        token = login()
        me( token )

    if args.add_user :
        token = login()
        add_user( token )

    if args.get_user :
        token = login()
        get_user( token )

    if args.delete_user :
        token = login()
        delete_user( token )

    if args.search :
        token = login()
        search( token )

    if args.role :
        token = login()
        add_user( token )
        role( token )
