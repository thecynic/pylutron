import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import threading
import time
from pylutron import LutronConnection, LutronLoginError, LutronConnectionError, LutronAuthenticationError
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
        self.mock_reader.readuntil_pattern.assert_called_with(LutronConnection.PROMPT)

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

    async def test_incorrect_credentials_assertive(self) -> None:
        """Test assertive reporting of incorrect credentials."""
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT
        ]
        # Simulate repeater sending back the login prompt on failure
        self.mock_reader.readuntil_pattern.return_value = LutronConnection.USER_PROMPT
        
        with self.assertRaisesRegex(LutronLoginError, "Incorrect username or password"):
            await self.conn._do_login()

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

    def test_connect_deadlock_on_login_failure(self) -> None:
        """Test that connect() doesn't deadlock when login fails."""
        with patch.object(LutronConnection, '_do_login', side_effect=LutronLoginError("Fatal login error")):
            start_time = time.time()
            with self.assertRaises(LutronLoginError):
                self.conn.connect()
            end_time = time.time()
            self.assertLess(end_time - start_time, 5.0, "connect() took too long, possible deadlock")
            self.conn.join(timeout=1)
            self.assertFalse(self.conn.is_alive())

    def test_connect_fail_on_network_error(self) -> None:
        """Test that connect() fails if a network error occurs during initial connection."""
        with patch.object(LutronConnection, '_do_login', side_effect=OSError("Network unreachable")):
            start_time = time.time()
            with self.assertRaises(LutronConnectionError):
                self.conn.connect()
            end_time = time.time()
            self.assertLess(end_time - start_time, 5.0, "connect() took too long")
            self.conn.join(timeout=1)
            self.assertFalse(self.conn.is_alive())

    def test_connect_success_wait(self) -> None:
        """Test that connect() waits for a successful connection."""
        async def mock_do_login_success() -> None:
            # Set up reader to return empty line immediately after login
            self.mock_reader.readline.return_value = b""
            await asyncio.sleep(0.1)
            
        with patch.object(LutronConnection, '_do_login', side_effect=mock_do_login_success):
            self.conn.connect()
            self.assertTrue(self.conn._connected)
            self.conn._done = True
            self.conn.join(timeout=1)

    def test_disconnect_does_not_clear_ever_connected(self) -> None:
        """_disconnect_locked() clears _connected but must leave _ever_connected set.

        Narrow unit check on the flag only. It does NOT exercise the reconnect
        guard in _main_loop -- see test_main_loop_* below for that.
        """
        async def mock_do_login_success() -> None:
            self.mock_reader.readline.return_value = b""
            await asyncio.sleep(0.1)

        with patch.object(LutronConnection, '_do_login', side_effect=mock_do_login_success):
            self.conn.connect()
            self.assertTrue(self.conn._ever_connected)
            with self.conn._lock:
                self.conn._disconnect_locked()
            self.assertFalse(self.conn._connected)
            self.assertTrue(self.conn._ever_connected)
            self.conn._done = True
            self.conn.join(timeout=1)

    async def test_main_loop_retries_login_timeout_after_connect(self) -> None:
        """A login timeout on a reconnect (after a successful connect) must retry.

        Drives _main_loop directly: first _do_login() succeeds (so _ever_connected
        becomes True and the inner read loop breaks on an empty line), every later
        call raises a login timeout -- a LutronLoginError, the same type raised by
        _do_login()'s three asyncio.TimeoutError paths. With the reconnect guard in
        place the loop keeps retrying; reverting it (the except LutronException
        branch setting _done unconditionally) makes _do_login run exactly twice and
        _exception get set, which this test would catch.
        """
        calls = {'n': 0}

        async def do_login() -> None:
            calls['n'] += 1
            if calls['n'] == 1:
                self.conn._reader = self.mock_reader
                self.mock_reader.readline.return_value = b""
                return
            if calls['n'] >= 3:
                self.conn._done = True  # stop the loop after we've proven it retried
            raise LutronLoginError("Timed out waiting for GNET/QNET prompt (check credentials)")

        with patch.object(LutronConnection, '_do_login', side_effect=do_login), \
             patch('pylutron.asyncio.sleep', new=AsyncMock()):
            await self.conn._main_loop()

        self.assertGreaterEqual(calls['n'], 3,
                                "login timeout after a successful connect must retry, not give up")
        self.assertIsNone(self.conn._exception)

    async def test_main_loop_stops_on_authentication_error(self) -> None:
        """Bad credentials must stay fatal, even after a successful connect.

        Same harness as the retry test, but the reconnect raises
        LutronAuthenticationError ("Incorrect username or password"). The loop must
        set _done and stop rather than retry a credential that will never work.
        """
        calls = {'n': 0}

        async def do_login() -> None:
            calls['n'] += 1
            if calls['n'] == 1:
                self.conn._reader = self.mock_reader
                self.mock_reader.readline.return_value = b""
                return
            raise LutronAuthenticationError("Incorrect username or password")

        with patch.object(LutronConnection, '_do_login', side_effect=do_login), \
             patch('pylutron.asyncio.sleep', new=AsyncMock()):
            await self.conn._main_loop()

        self.assertEqual(calls['n'], 2,
                         "bad credentials must be fatal even after a successful connect")
        self.assertTrue(self.conn._done)
        self.assertIsInstance(self.conn._exception, LutronAuthenticationError)


if __name__ == '__main__':
    unittest.main()
