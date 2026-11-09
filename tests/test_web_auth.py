import unittest

from ftm.web_auth import Auth, make_config, InvalidCredentials, RateLimited, SESSION_TTL


class WebAuthSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = make_config("admin", "synthetic long admin phrase")

    def test_session_csrf_and_logout(self):
        auth = Auth(self.config)
        token, csrf = auth.login("admin", "synthetic long admin phrase", "local")
        self.assertFalse(auth.authorize_mutation(token, "incorrect"))
        self.assertTrue(auth.authorize_mutation(token, csrf))
        auth.logout(token)
        self.assertIsNone(auth.session(token))

    def test_expired_session_cannot_authorize_mutation(self):
        clock = [100]
        auth = Auth(self.config, clock=lambda: clock[0])
        token, csrf = auth.login("admin", "synthetic long admin phrase", "local")
        clock[0] += SESSION_TTL + 1
        self.assertFalse(auth.authorize_mutation(token, csrf))

    def test_bad_credentials_are_rate_limited(self):
        auth = Auth(self.config)
        for _ in range(5):
            with self.assertRaises(InvalidCredentials):
                auth.login("admin", "incorrect phrase", "local")
        with self.assertRaises(RateLimited):
            auth.login("admin", "synthetic long admin phrase", "local")
