import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import threading
import time
from pylutron import LutronConnection, LutronLoginError
from typing import List, Optional, Tuple, Any

class AsyncTestBase(unittest.IsolatedAsyncioTestCase):
    pass

class TestLutronConnection(AsyncTestBase):
    def setUp(self) -> None:
        self.received_lines: List[str] = []
        self.mock_reader = AsyncMock()
        # Use MagicMock for the writer to avoid methods returning coroutines by default
        self.mock_writer = MagicMock()
        self.mock_writer.drain = AsyncMock()
        self.mock_socket = MagicMock()
        self.mock_writer.get_extra_info.return_value = self.mock_socket
        
        async def mock_connection_factory(host: str, port: int, connect_timeout: Optional[float] = None, encoding: Optional[str] = None) -> Tuple[AsyncMock, MagicMock]:
            return self.mock_reader, self.mock_writer
            
        self.conn = LutronConnection('127.0.0.1', 'user', 'pass', self._recv_cb, connection_factory=mock_connection_factory)

    def _recv_cb(self, line: str) -> None:
        self.received_lines.append(line)

    async def test_successful_login_gnet(self) -> None:
        """Test successful login with GNET> prompt."""
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT
        ]
        self.mock_reader.readuntil_pattern.return_value = b'GNET> '
        
        await self.conn._do_login()
        
        self.mock_writer.write.assert_any_call(b'user\r\n')
        self.mock_writer.write.assert_any_call(b'pass\r\n')
        self.assertEqual(self.mock_writer.drain.call_count, 9)

    async def test_successful_login_qnet(self) -> None:
        """Test successful login with QNET> prompt."""
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT
        ]
        self.mock_reader.readuntil_pattern.return_value = b'QNET> '
        
        await self.conn._do_login()
        self.mock_reader.readuntil_pattern.assert_called_with(LutronConnection.ANY_PROMPT)

    async def test_login_timeout_user_prompt(self) -> None:
        """Test timeout waiting for the initial login prompt."""
        self.mock_reader.readuntil.side_effect = asyncio.TimeoutError
        
        with self.assertRaisesRegex(LutronLoginError, "Timed out waiting for login prompt"):
            await self.conn._do_login()

    async def test_login_timeout_pw_prompt(self) -> None:
        """Test timeout waiting for the password prompt."""
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            asyncio.TimeoutError
        ]
        
        with self.assertRaisesRegex(LutronLoginError, "Timed out waiting for password prompt"):
            await self.conn._do_login()

    async def test_login_timeout_gnet_prompt(self) -> None:
        """Test timeout waiting for the final GNET/QNET prompt."""
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT
        ]
        self.mock_reader.readuntil_pattern.side_effect = asyncio.TimeoutError
        
        with self.assertRaisesRegex(LutronLoginError, "Timed out waiting for GNET/QNET prompt"):
            await self.conn._do_login()

    async def test_incorrect_credentials_retry_login(self) -> None:
        """Test behavior when credentials are incorrect."""
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT
        ]
        self.mock_reader.readuntil_pattern.side_effect = asyncio.TimeoutError
        
        with self.assertRaises(LutronLoginError) as cm:
            await self.conn._do_login()
        
        self.assertIn("check credentials", str(cm.exception).lower())

    def test_thread_start_and_connect(self) -> None:
        """Test that the thread starts and connect() waits for connection."""
        # Use a function for side_effect so it doesn't exhaust if the loop retries
        async def readuntil_side_effect(prompt: bytes) -> bytes:
            return prompt
        self.mock_reader.readuntil.side_effect = readuntil_side_effect
        self.mock_reader.readuntil_pattern.return_value = b'GNET> '
        self.mock_reader.readline.side_effect = [b"~OUTPUT,1,1,100.0\r\n", b""]

        self.conn.connect()
        self.assertTrue(self.conn._connected)
        time.sleep(0.1)
        self.assertIn('~OUTPUT,1,1,100.0', self.received_lines)
        
        self.conn._done = True
        self.conn.join(timeout=1)

if __name__ == '__main__':
    unittest.main()
