import unittest
from unittest.mock import MagicMock, AsyncMock
import asyncio
import threading
import time
from pylutron import LutronConnection

class AsyncTestBase(unittest.IsolatedAsyncioTestCase):
    pass

class TestLutronConnection(AsyncTestBase):
    async def test_connection_and_login(self):
        received_lines = []
        def recv_cb(line):
            received_lines.append(line)

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_socket = MagicMock()
        mock_writer.get_extra_info.return_value = mock_socket
        
        async def readuntil_mock(prompt):
            if prompt == LutronConnection.PROMPT:
                return b'GNET> '
            return prompt
        
        mock_reader.readuntil.side_effect = readuntil_mock
        mock_reader.readline.side_effect = [
            b"~OUTPUT,1,1,100.0\r\n",
            b"" # EOF
        ]

        async def mock_connection_factory(host, port, connect_timeout=None, encoding=None):
            return mock_reader, mock_writer

        conn = LutronConnection('127.0.0.1', 'user', 'pass', recv_cb, connection_factory=mock_connection_factory)
        
        # We need to test _do_login, but it's now async
        await conn._do_login()
        
        # Check if login commands were sent
        mock_writer.write.assert_any_call(b'user\r\n')
        mock_writer.write.assert_any_call(b'pass\r\n')
        # Monitoring commands
        mock_writer.write.assert_any_call(b'#MONITORING,12,2\r\n')
        
        # Check if socket options were set
        mock_writer.get_extra_info.assert_called_with('socket')
        mock_socket.setsockopt.assert_called()

    def test_thread_start_and_connect(self):
        """Test that the thread starts and connect() waits for connection."""
        received_lines = []
        def recv_cb(line):
            received_lines.append(line)

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_socket = MagicMock()
        mock_writer.get_extra_info.return_value = mock_socket
        
        async def readuntil_mock(prompt):
            if prompt == LutronConnection.PROMPT:
                return b'GNET> '
            return prompt
        
        mock_reader.readuntil.side_effect = readuntil_mock
        # Return a line then wait forever or return empty to close
        mock_reader.readline.side_effect = [b"~OUTPUT,1,1,100.0\r\n", b""]

        async def mock_connection_factory(host, port, connect_timeout=None, encoding=None):
            return mock_reader, mock_writer

        conn = LutronConnection('127.0.0.1', 'user', 'pass', recv_cb, connection_factory=mock_connection_factory)
        
        # Start the thread
        conn.connect()
        
        # If connect() returns, it means self._connected is True
        self.assertTrue(conn._connected)
        
        # Wait a bit for the main loop to process the line
        time.sleep(0.1)
        
        self.assertIn('~OUTPUT,1,1,100.0', received_lines)
        
        # Stop the thread
        conn._done = True
        
        conn.join(timeout=1)

if __name__ == '__main__':
    unittest.main()
