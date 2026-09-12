import unittest
from unittest.mock import MagicMock, AsyncMock, patch, call
import asyncio
import time

from pylutron import Lutron, LutronConnection, Output

from typing import List, Optional, Tuple, cast


class TestPromptTypeDetection(unittest.IsolatedAsyncioTestCase):
    """Verifies LutronConnection correctly identifies GNET vs QNET prompts."""

    def setUp(self) -> None:
        self.mock_reader = AsyncMock()
        self.mock_writer = MagicMock()
        self.mock_writer.drain = AsyncMock()
        self.mock_writer.get_extra_info.return_value = MagicMock()

        async def factory(host: str, port: int, connect_timeout: Optional[float] = None, encoding: Optional[str] = None) -> Tuple[AsyncMock, MagicMock]:
            return self.mock_reader, self.mock_writer

        self.factory = factory
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT,
        ]

    async def test_gnet_prompt_sets_prompt_type(self) -> None:
        conn = LutronConnection('1.1.1.1', 'u', 'p', lambda l: None,
                                connection_factory=self.factory)
        self.mock_reader.readuntil_pattern.return_value = b'GNET> '
        await conn._do_login()
        self.assertEqual(conn.prompt_type, LutronConnection.PROMPT_GNET)

    async def test_qnet_prompt_sets_prompt_type(self) -> None:
        conn = LutronConnection('1.1.1.1', 'u', 'p', lambda l: None,
                                connection_factory=self.factory)
        self.mock_reader.readuntil_pattern.return_value = b'QNET> '
        await conn._do_login()
        self.assertEqual(conn.prompt_type, LutronConnection.PROMPT_QNET)

    async def test_prompt_type_none_before_login(self) -> None:
        conn = LutronConnection('1.1.1.1', 'u', 'p', lambda l: None,
                                connection_factory=self.factory)
        self.assertIsNone(conn.prompt_type)


class TestMonitoringControl(unittest.IsolatedAsyncioTestCase):
    """Verifies that monitoring commands are sent or skipped based on
    the enable_monitoring flag."""

    def setUp(self) -> None:
        self.mock_reader = AsyncMock()
        self.mock_writer = MagicMock()
        self.mock_writer.drain = AsyncMock()
        self.mock_writer.get_extra_info.return_value = MagicMock()

        async def factory(host: str, port: int, connect_timeout: Optional[float] = None, encoding: Optional[str] = None) -> Tuple[AsyncMock, MagicMock]:
            return self.mock_reader, self.mock_writer

        self.factory = factory
        self.mock_reader.readuntil.side_effect = [
            LutronConnection.USER_PROMPT,
            LutronConnection.PW_PROMPT,
        ]
        self.mock_reader.readuntil_pattern.return_value = b'QNET> '

    async def test_monitoring_enabled_sends_commands(self) -> None:
        conn = LutronConnection('1.1.1.1', 'u', 'p', lambda l: None,
                                connection_factory=self.factory,
                                enable_monitoring=True)
        await conn._do_login()
        written = [c.args[0] for c in self.mock_writer.write.call_args_list]
        monitoring_cmds = [w for w in written if b'#MONITORING' in w]
        self.assertEqual(len(monitoring_cmds), 7)

    async def test_monitoring_disabled_skips_commands(self) -> None:
        conn = LutronConnection('1.1.1.1', 'u', 'p', lambda l: None,
                                connection_factory=self.factory,
                                enable_monitoring=False)
        await conn._do_login()
        written = [c.args[0] for c in self.mock_writer.write.call_args_list]
        monitoring_cmds = [w for w in written if b'#MONITORING' in w]
        self.assertEqual(len(monitoring_cmds), 0)


class TestLutronDualConnection(unittest.TestCase):
    """Tests the Lutron class dual-connection behavior for HomeWorks QS."""

    def _make_mock_conn(self, prompt: str) -> MagicMock:
        """Creates a mock LutronConnection with the given prompt type."""
        conn = MagicMock(spec=LutronConnection)
        conn.prompt_type = prompt
        conn.connect.return_value = None
        conn.send.return_value = None
        return conn

    def test_gnet_uses_single_connection(self) -> None:
        """On RadioRA 2 (GNET), no command connection is created."""
        lutron = Lutron('1.1.1.1', 'u', 'p')
        mock_conn = self._make_mock_conn(LutronConnection.PROMPT_GNET)
        lutron._conn = mock_conn

        lutron.connect()

        self.assertIsNone(lutron._cmd_conn)
        self.assertFalse(lutron.is_homeworks)

    def test_qnet_creates_command_connection(self) -> None:
        """On HomeWorks QS (QNET), a second connection is opened for commands."""
        lutron = Lutron('1.1.1.1', 'u', 'p')
        mock_monitor = self._make_mock_conn(LutronConnection.PROMPT_QNET)
        lutron._conn = mock_monitor

        cmd_conn = self._make_mock_conn(LutronConnection.PROMPT_QNET)
        created_conns: list[object] = []
        original_init = LutronConnection.__init__

        def capture_init(self_inner: LutronConnection, *args: object, **kwargs: object) -> None:
            created_conns.append(self_inner)

        with patch.object(LutronConnection, '__init__', capture_init):
            with patch.object(LutronConnection, 'connect'):
                lutron.connect()

        self.assertIsNotNone(lutron._cmd_conn)
        self.assertTrue(lutron.is_homeworks)

    def test_send_routes_to_cmd_conn_on_homeworks(self) -> None:
        """Commands are sent via the command connection on HomeWorks."""
        lutron = Lutron('1.1.1.1', 'u', 'p')
        mock_monitor = self._make_mock_conn(LutronConnection.PROMPT_QNET)
        mock_cmd = self._make_mock_conn(LutronConnection.PROMPT_QNET)
        lutron._conn = mock_monitor
        lutron._cmd_conn = mock_cmd

        lutron.send(Lutron.OP_EXECUTE, 'OUTPUT', 5, 1, '100.00')

        mock_cmd.send.assert_called_once_with('#OUTPUT,5,1,100.00')
        mock_monitor.send.assert_not_called()

    def test_send_routes_to_conn_on_radiora(self) -> None:
        """Commands are sent via the single connection on RadioRA 2."""
        lutron = Lutron('1.1.1.1', 'u', 'p')
        mock_conn = self._make_mock_conn(LutronConnection.PROMPT_GNET)
        lutron._conn = mock_conn

        lutron.send(Lutron.OP_EXECUTE, 'OUTPUT', 5, 1, '100.00')

        mock_conn.send.assert_called_once_with('#OUTPUT,5,1,100.00')

    def test_monitor_receives_status_updates(self) -> None:
        """Status updates on the monitor connection dispatch to handle_update."""
        lutron = Lutron('1.1.1.1', 'u', 'p')
        lutron._conn = MagicMock()
        output = Output(lutron, 'Light', 40, 'INC', 10, '714')
        handler = MagicMock()
        output.subscribe(handler, None)

        lutron._recv('~OUTPUT,10,1,75.00')

        self.assertEqual(output.last_level(), 75.0)
        handler.assert_called_once()


class TestLutronDualConnectionIntegration(unittest.TestCase):
    """End-to-end test using mock telnet sessions simulating HomeWorks QS."""

    def test_command_on_cmd_conn_generates_update_on_monitor(self) -> None:
        """Simulates: command sent on cmd_conn, status update arrives on
        monitor, handle_update fires."""
        received: List[str] = []

        def recv_cb(line: str) -> None:
            received.append(line)

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.get_extra_info.return_value = MagicMock()

        async def factory(host: str, port: int, connect_timeout: Optional[float] = None, encoding: Optional[str] = None) -> Tuple[AsyncMock, MagicMock]:
            return mock_reader, mock_writer

        mock_reader.readuntil.side_effect = lambda p: p
        mock_reader.readuntil_pattern.return_value = b'QNET> '
        mock_reader.readline.side_effect = [
            b'~OUTPUT,10,1,75.00\r\n',
            b'',
        ]

        conn = LutronConnection('1.1.1.1', 'u', 'p', recv_cb,
                                connection_factory=factory)
        conn.connect()
        time.sleep(0.2)

        self.assertEqual(conn.prompt_type, LutronConnection.PROMPT_QNET)
        self.assertIn('~OUTPUT,10,1,75.00', received)

        conn._done = True
        conn.join(timeout=1)


if __name__ == '__main__':
    unittest.main()
