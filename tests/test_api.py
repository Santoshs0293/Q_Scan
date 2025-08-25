import unittest
from flask import Flask
from src.api.endpoints import api_bp
from src.api.auth import auth_bp

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(api_bp)
        self.app.register_blueprint(auth_bp)
        self.client = self.app.test_client()

    def test_login(self):
        response = self.client.post('/login', json={"username": "admin", "password": "password"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json)

if __name__ == "__main__":
    unittest.main()