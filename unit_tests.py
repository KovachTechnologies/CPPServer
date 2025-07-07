import json
import os
import requests
import time
import unittest

class TestAPI(unittest.TestCase):
    BASE_URL = "http://localhost:8080/api"
    HEADERS = {"Content-Type": "application/json"}

    def setUp(self):
        """Set up common variables and headers for tests."""
        self.register_payload = {
            "username": "johndoe",
            "password": "mypassword",
            "email": "john@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "role": "ADMIN",
            "group": "DEFAULT"
        }
        self.login_payload = {
            "username": "johndoe",
            "password": "mypassword"
        }
        self.admin_payload = {
            "username": "admin1",
            "password": "securepass123",
            "email": "admin@example.com",
            "first_name": "Admin",
            "last_name": "One",
            "role": "ADMIN",
            "group": "DEFAULT"
        }

    def _login(self, username="johndoe", password="mypassword"):
        """Helper method to perform login and extract token."""
        payload = {"username": username, "password": password}
        response = requests.post(f"{self.BASE_URL}/login", json=payload, headers=self.HEADERS)
        self.assertEqual(response.status_code, 200, f"Login failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("token", response_data)
        return response_data["token"]

    def test_register(self):
        """Test /api/register endpoint."""
        response = requests.post(f"{self.BASE_URL}/register", json=self.register_payload, headers=self.HEADERS)
        if not os.path.exists( "test.db" ) :
            self.assertEqual(response.status_code, 400, f"User already registered: {response.text}")
        else :
            self.assertEqual(response.status_code, 201, f"Register: {response.text}")

    def test_login(self):
        """Test /api/login endpoint."""
        # Ensure user is registered
        response = requests.post(f"{self.BASE_URL}/login", json=self.login_payload, headers=self.HEADERS)
        self.assertEqual(response.status_code, 200, f"Login failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")

    def test_protected_endpoint(self):
        """Test /api/hello with valid token."""
        # Register and login
        token = self._login()
        response = requests.get(f"{self.BASE_URL}/hello", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Protected endpoint failed: {response.text}")

    def test_protected_endpoint_invalid_token(self):
        """Test /api/hello with invalid token."""
        response = requests.get(f"{self.BASE_URL}/hello", headers={"Authorization": "Bearer bad-token"})
        self.assertEqual(response.status_code, 401, f"Expected 401 for invalid token: {response.text}")

    def test_login_logout(self):
        """Test login followed by logout and verify token invalidation."""
        token = self._login()
        # Logout
        response = requests.post(f"{self.BASE_URL}/logout", headers={"Authorization": f"Bearer {token}"})
        time.sleep( 1 ) # let the logout come to fruition
        self.assertEqual(response.status_code, 200, f"Logout failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["message"], "Logged out successfully")
        # Try accessing protected endpoint with invalidated token
        response = requests.get(f"{self.BASE_URL}/hello", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 401, f"Expected 401 after logout: {response.text}")

    def test_users_me(self):
        """Test /api/users/me endpoint."""
        requests.post(f"{self.BASE_URL}/register", json=self.register_payload, headers=self.HEADERS)
        token = self._login()
        response = requests.get(f"{self.BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Users/me failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("data", response_data)
        self.assertEqual(response_data["data"]["username"], "johndoe")
        self.assertEqual(response_data["data"]["role"], "ADMIN")

    def test_add_user(self):
        """Test /api/user POST endpoint."""
        requests.post(f"{self.BASE_URL}/register", json=self.register_payload, headers=self.HEADERS)
        token = self._login()
        response = requests.post(f"{self.BASE_URL}/user", json=self.admin_payload, headers={"Authorization": f"Bearer {token}"})
        if response.status_code == 201 :
            self.assertEqual(response.status_code, 201, f"Add user failed: {response.text}")
            response_data = response.json()
            self.assertEqual(response_data["status"], "success")
        else :
            self.assertEqual(response.status_code, 400, f"Add user failed: {response.text}")
            response_data = response.json()
            self.assertEqual(response_data["status"], "error")

    def test_get_user(self):
        """Test /api/user/<username> GET endpoint."""
        requests.post(f"{self.BASE_URL}/register", json=self.register_payload, headers=self.HEADERS)
        token = self._login()
        # Add admin1 user
        requests.post(f"{self.BASE_URL}/user", json=self.admin_payload, headers={"Authorization": f"Bearer {token}"})
        # Get user
        response = requests.get(f"{self.BASE_URL}/user/admin1", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Get user failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("data", response_data)
        self.assertEqual(response_data["data"]["username"], "admin1")
        self.assertEqual(response_data["data"]["role"], "ADMIN")

    def test_delete_user(self):
        """Test /api/user/<username> DELETE endpoint."""
        requests.post(f"{self.BASE_URL}/register", json=self.register_payload, headers=self.HEADERS)
        token = self._login()
        # Add admin1 user
        requests.post(f"{self.BASE_URL}/user", json=self.admin_payload, headers={"Authorization": f"Bearer {token}"})
        # Delete user
        response = requests.delete(f"{self.BASE_URL}/user/admin1", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Delete user failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["message"], "User deleted successfully")
        # Verify user is deleted
        response = requests.get(f"{self.BASE_URL}/user/admin1", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 404, f"Expected 404 after deletion: {response.text}")

    def test_search(self):
        """Test /api/user/search endpoint with username, role, and group."""
        requests.post(f"{self.BASE_URL}/register", json=self.register_payload, headers=self.HEADERS)
        token = self._login()
        # Test search by username
        payload = {"username": "johndoe"}
        response = requests.post(f"{self.BASE_URL}/user/search", json=payload, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Search by username failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("data", response_data)
        self.assertEqual(len(response_data["data"]), 1)
        self.assertEqual(response_data["data"][0]["username"], "johndoe")
        # Test search by role
        payload = {"role": "ADMIN"}
        response = requests.post(f"{self.BASE_URL}/user/search", json=payload, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Search by role failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("data", response_data)
        self.assertEqual(len(response_data["data"]), 1)
        self.assertEqual(response_data["data"][0]["role"], "ADMIN")
        # Test search by group
        payload = {"group": "DEFAULT"}
        response = requests.post(f"{self.BASE_URL}/user/search", json=payload, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Search by group failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("data", response_data)
        self.assertEqual(len(response_data["data"]), 3)
        self.assertEqual(response_data["data"][0]["group"], "DEFAULT")

    def test_role(self):
        """Test /api/user/role endpoint."""
        token = self._login()
        # Add admin1 user
        requests.post(f"{self.BASE_URL}/user", json=self.admin_payload, headers={"Authorization": f"Bearer {token}"})
        # Update role
        payload = {"username": "admin1", "role": "READ"}
        response = requests.post(f"{self.BASE_URL}/user/role", json=payload, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Update role failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["message"], "User role updated successfully")
        # Verify role change
        response = requests.get(f"{self.BASE_URL}/user/admin1", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["role"], "READ")

    def test_roles(self):
        """Test /api/roles endpoint."""
        token = self._login()
        # Add another user with different role
        response = requests.get(f"{self.BASE_URL}/roles", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Get roles failed: {response.text}")
        response_data = response.json()
        self.assertEqual(response_data["status"], "success")
        self.assertIn("data", response_data)
        self.assertTrue(set(response_data["data"]).issuperset({"ADMIN", "READ"}))

    def test_groups(self):
        """Test /api/groups endpoint (expected to fail as not implemented)."""
        token = self._login()
        response = requests.get(f"{self.BASE_URL}/groups", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200, f"Expected failure for /api/groups: {response.text}")

if __name__ == "__main__":
    unittest.main()
