import unittest
from unittest.mock import MagicMock, patch
from pylutron import Lutron

class TestLutron(unittest.TestCase):
    def setUp(self):
        self.lutron = Lutron('127.0.0.1', 'admin', 'password')
        # Mock the connection send method to avoid actual network IO
        self.lutron._conn.send = MagicMock()

    def test_initialization(self):
        self.assertEqual(self.lutron._host, '127.0.0.1')
        self.assertEqual(self.lutron._user, 'admin')
        self.assertEqual(self.lutron._password, 'password')

    def test_send_command(self):
        # We need a dummy object to register an ID to send commands to it
        # However, Lutron.send uses the integration ID directly.
        
        self.lutron.send(Lutron.OP_EXECUTE, 'OUTPUT', 1, 1, 100.00)
        
        # Expected format: "#OUTPUT,1,1,100.0"
        self.lutron._conn.send.assert_called_with('#OUTPUT,1,1,100.0')

    def test_connection_injection(self):
        """Verify that we can inject a mock factory into LutronConnection via Lutron (if exposed) or directly."""
        mock_factory = MagicMock()
        # Note: Lutron class currently does not expose connection_factory in __init__, so we might need to test LutronConnection directly
        # or modify Lutron.__init__ as well. For now, let's test LutronConnection directly.
        from pylutron import LutronConnection
        
        conn = LutronConnection('host', 'user', 'pass', None, connection_factory=mock_factory)
        # We need to call a method that triggers connection creation, e.g., _do_login_locked
        # Accessing private method for test purpose
        conn._do_login_locked()
        
        mock_factory.assert_called_with('host', timeout=2)

if __name__ == '__main__':
    unittest.main()
