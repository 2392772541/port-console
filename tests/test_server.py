from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import subprocess
import socket
import time
from unittest.mock import patch
import urllib.error
import urllib.request
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import server  # noqa: E402


class PortHelpersTests(unittest.TestCase):
    def test_scope_classification(self) -> None:
        self.assertEqual(server.scope_for_address("127.0.0.1"), "loopback")
        self.assertEqual(server.scope_for_address("::1"), "loopback")
        self.assertEqual(server.scope_for_address("0.0.0.0"), "all")
        self.assertEqual(server.scope_for_address("::"), "all")
        self.assertEqual(server.scope_for_address("192.168.1.10"), "interface")

    def test_function_prefers_service_evidence(self) -> None:
        function, evidence = server.infer_function(
            3306,
            "mysqld.exe",
            [{"name": "mysql", "display_name": "MySQL Service"}],
        )
        self.assertEqual(function, "MySQL Service")
        self.assertEqual(evidence, "service")

    def test_function_uses_process_then_port(self) -> None:
        self.assertEqual(server.infer_function(12345, "nginx.exe", [])[1], "process")
        self.assertEqual(server.infer_function(445, "", [])[0], "Windows SMB 文件共享")

    def test_allowed_hosts(self) -> None:
        self.assertTrue(server.allowed_host("127.0.0.1:8787"))
        self.assertTrue(server.allowed_host("localhost:8787"))
        self.assertTrue(server.allowed_host("[::1]:8787"))
        self.assertFalse(server.allowed_host("192.168.1.20:8787"))
        self.assertFalse(server.allowed_host("example.com"))


class ProjectManifestTests(unittest.TestCase):
    def test_normalize_command_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = {
                "id": "sample-api",
                "name": "Sample API",
                "type": "command",
                "working_directory": ".",
                "command": ["python", "app.py"],
                "expected_ports": [8000, 8000],
            }
            project = server.normalize_project(raw, root / "port-console.project.json")
            self.assertEqual(project["id"], "sample-api")
            self.assertEqual(project["expected_ports"], [8000])
            self.assertEqual(project["working_directory"], str(root.resolve()))

    def test_rejects_shell_string(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = {
                "id": "unsafe",
                "type": "command",
                "command": "python app.py && whoami",
            }
            with self.assertRaises(ValueError):
                server.normalize_project(raw, root / "port-console.project.json")

    def test_fixed_stop_command_is_valid_and_not_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = {
                "id": "desktop-app",
                "type": "command",
                "working_directory": ".",
                "command": ["python", "start.py"],
                "stop_command": ["python", "stop.py"],
                "expected_ports": [8383],
                "allow_stop": True,
            }
            project = server.normalize_project(raw, root / "port-console.project.json")
            public = server.project_state(project, {8383})
            self.assertTrue(public["can_stop"])
            self.assertNotIn("command", public)
            self.assertNotIn("stop_command", public)

    def test_rejects_invalid_service_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = {
                "id": "service",
                "type": "windows-service",
                "service_name": "mysql; whoami",
            }
            with self.assertRaises(ValueError):
                server.normalize_project(raw, Path(directory) / "port-console.project.json")

    def test_discovers_manifest_and_skips_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "alpha"
            ignored = root / "node_modules" / "bad"
            project.mkdir()
            ignored.mkdir(parents=True)
            (project / "port-console.project.json").write_text("{}", encoding="utf-8")
            (ignored / "port-console.project.json").write_text("{}", encoding="utf-8")
            found = server.discover_manifests([str(root)])
            self.assertEqual(found, [project / "port-console.project.json"])


class StopProjectTests(unittest.TestCase):
    def project(self, root, port=18765):
        return server.normalize_project({'id':'stop-test','type':'command',
            'working_directory':str(root),'command':[sys.executable,'app.py'],
            'expected_ports':[port],'allow_stop':True}, Path(root)/'manifest.json')

    def test_external_process_can_stop_after_console_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0))
                port=sock.getsockname()[1]
            process=subprocess.Popen([sys.executable,'-m','http.server',str(port),'--bind','127.0.0.1'],
                cwd=directory,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    with socket.socket() as sock:
                        if sock.connect_ex(('127.0.0.1',port))==0: break
                    time.sleep(.05)
                else: self.fail('fixture did not start')
                project=self.project(directory,port)
                server.PORT_CACHE['time']=0
                self.assertNotIn('stop-test',server.MANAGED_PROCESSES)
                self.assertTrue(server.project_state(project,{port})['can_stop'])
                self.assertTrue(server.stop_project(project)['ok'])
                process.wait(timeout=5)
                with socket.socket() as sock:
                    self.assertNotEqual(sock.connect_ex(('127.0.0.1',port)),0)
            finally:
                if process.poll() is None: process.kill()
                process.wait()

    def test_unrelated_port_owner_is_not_stoppable(self):
        with tempfile.TemporaryDirectory() as directory:
            project=self.project(directory)
            row={'protocol':'TCP','port':18765,'pid':987654,'services':[]}
            from unittest.mock import MagicMock
            other=MagicMock()
            current=MagicMock()
            current.parents.return_value=[]
            other.cwd.return_value=str(Path(directory).parent)
            with patch.object(server,'collect_ports',return_value={'items':[row]}), patch.object(server.psutil,'Process',side_effect=lambda pid=None: other if pid==987654 else current):
                state=server.project_state(project,{18765})
                self.assertFalse(state['can_stop'])
                self.assertIn('其他目录',state['stop_reason'])
                with self.assertRaisesRegex(RuntimeError,'其他目录'): server.stop_project(project)
                other.terminate.assert_not_called()

    def test_console_itself_is_protected(self):
        import os
        project=self.project(server.ROOT)
        with patch.object(server,'collect_ports',return_value={'items':[{'protocol':'TCP','port':18765,'pid':os.getpid(),'services':[]}]}):
            with self.assertRaisesRegex(RuntimeError,'自身'): server.owned_listeners(project)

    def test_stop_command_success_with_live_port_is_failure(self):
        project=self.project(server.ROOT)
        project['stop_command']=[sys.executable,'stop.py']
        with patch.object(server,'run_checked',return_value={'ok':True}), patch.object(server,'listening_ports',return_value={18765}), patch.object(server.time,'monotonic',side_effect=[0,16]):
            with self.assertRaisesRegex(RuntimeError,'仍在运行'): server.stop_project(project)


class HttpServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = server.create_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)

    def get_json(self, path: str) -> dict:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_health_and_session(self) -> None:
        health = self.get_json("/api/health")
        session = self.get_json("/api/session")
        self.assertTrue(health["ok"])
        self.assertEqual(health["port"], self.port)
        self.assertTrue(session["token"])

    def test_delete_action_routes(self) -> None:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/projects/missing/delete",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json", "X-Port-Console-Token": server.SESSION_TOKEN},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 404)
    def test_archive_action_routes(self) -> None:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/projects/missing/archive",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json", "X-Port-Console-Token": server.SESSION_TOKEN},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 404)

    def test_action_requires_token(self) -> None:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/projects/missing/start",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 403)

    def test_integrated_skills_html(self):
        with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/skills') as response:
            html=response.read().decode('utf-8')
        self.assertIn('data-integrated="true"',html)
        self.assertIn('/skills-assets/personal.js',html)
        self.assertIn('按用途分类',html)

    def test_skills_proxy_read_write_and_offline(self):
        from unittest.mock import patch, MagicMock
        connection=MagicMock()
        connection.getresponse.return_value.status=200
        connection.getresponse.return_value.read.return_value=b'{"ok":true}'
        with patch.object(server,'HTTPConnection',return_value=connection):
            self.assertTrue(self.get_json('/api/personal')['ok'])
            request=urllib.request.Request(f'http://127.0.0.1:{self.port}/api/personal/label',data=b'{"id":"fixture","categories":["video"]}',headers={'Content-Type':'application/json','X-Port-Console-Token':server.SESSION_TOKEN})
            with urllib.request.urlopen(request) as response:self.assertEqual(response.status,200)
            args=connection.request.call_args
            self.assertEqual(args.args[:2],('POST','/api/personal/label'))
            self.assertEqual(json.loads(args.kwargs['body'])['categories'],['video'])
        with patch.object(server,'HTTPConnection',return_value=connection):
            connection.request.side_effect=ConnectionRefusedError()
            with self.assertRaises(urllib.error.HTTPError) as raised:self.get_json('/api/personal')
            self.assertEqual(raised.exception.code,503)
        self.assertTrue(self.get_json('/api/health')['ok'])

    def test_skill_edit_requires_token(self):
        request=urllib.request.Request(f'http://127.0.0.1:{self.port}/api/personal/label',data=b'{}',method='POST')
        with self.assertRaises(urllib.error.HTTPError) as raised:urllib.request.urlopen(request)
        self.assertEqual(raised.exception.code,403)


@unittest.skipUnless(sys.platform == "win32", "Windows 端口盘点测试")
class WindowsInventoryTests(unittest.TestCase):
    def test_collect_ports_returns_live_inventory(self) -> None:
        data = server.collect_ports_uncached()
        self.assertTrue(data["ok"])
        self.assertGreater(data["summary"]["unique_ports"], 0)
        self.assertTrue(any(item["protocol"] == "TCP" for item in data["items"]))
        self.assertTrue(all(0 < item["port"] <= 65535 for item in data["items"]))




class DriftAndArchiveTests(unittest.TestCase):
    def test_normalize_project_path_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_existing = {
                "id": "existing-proj",
                "type": "command",
                "working_directory": ".",
                "command": ["python", "app.py"],
                "expected_ports": [8000],
            }
            p1 = server.normalize_project(raw_existing, root / "port-console.project.json")
            self.assertTrue(p1["path_exists"])

            raw_missing = {
                "id": "missing-proj",
                "type": "command",
                "working_directory": str(root / "nonexistent_subfolder"),
                "command": ["python", "app.py"],
                "expected_ports": [8000],
            }
            p2 = server.normalize_project(raw_missing, root / "port-console.project.json")
            self.assertFalse(p2["path_exists"])

    def test_project_state_missing_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_missing = {
                "id": "missing-proj",
                "type": "command",
                "working_directory": str(root / "nonexistent_subfolder"),
                "command": ["python", "app.py"],
                "expected_ports": [8000],
                "enabled": True,
            }
            project = server.normalize_project(raw_missing, root / "port-console.project.json")
            state = server.project_state(project, set())
            self.assertEqual(state["state"], "missing")
            self.assertEqual(state["lifecycle"], "archive_candidate")
            self.assertEqual(state["consistency"], "definition_missing")
            self.assertFalse(state["can_start"])

    def test_archive_and_restore_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgg_path = Path(directory) / "projects.json"
            cgg_data = {
                "projects": [
                    {
                        "id": "test-archive",
                        "name": "Test Archive",
                        "type": "command",
                        "working_directory": directory,
                        "command": ["python", "app.py"],
                        "expected_ports": [9999],
                        "enabled": True,
                        "tags": ["测试"],
                    }
                ]
            }
            import json
            cgg_path.write_text(json.dumps(cgg_data, ensure_ascii=False), encoding="utf-8")
            from unittest.mock import patch
            with patch.object(server, "CONFIG_PATH", cgg_path):
                res_archive = server.toggle_project_archive("test-archive", archive=True)
                self.assertFalse(res_archive["enabled"])
                self.assertIn("已归档", res_archive['tags'])

                res_restore = server.toggle_project_archive("test-archive", archive=False)
                self.assertTrue(res_restore["enabled"])
                self.assertNotIn("已归档s", res_restore['tags'])

    def test_sync_drift_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgg_path = Path(directory) / "projects.json"
            cgg_data = {
                "projects": [
                    {
                        "id": "test-sync",
                        "name": "Test Sync",
                        "type": "command",
                        "working_directory": directory,
                        "command": ["python", "app.py"],
                        "expected_ports": [8000],
                        "url": "http://127.0.0.1:8000",
                        "enabled": True,
                    }
                ]
            }
            import json
            cgg_path.write_text(json.dumps(cgg_data, ensure_ascii=False), encoding="utf-8")
            from unittest.mock import patch
            with patch.object(server, "CONFIG_PATH", cgg_path):
                res = server.sync_project_drift_port("test-sync", target_port=18000)
                self.assertEqual(res["expected_ports"], [18000])
                self.assertEqual(res["url"], "http://127.0.0.1:18000")



    def test_derive_effective_url(self) -> None:
        self.assertEqual(
            server.derive_effective_url("http://127.0.0.1:8383/", [8383], 18180),
            "http://127.0.0.1:18180/",
        )
        self.assertEqual(
            server.derive_effective_url("http://localhost:8383/app", [8383], 18180),
            "http://localhost:18180/app",
        )
        self.assertEqual(
            server.derive_effective_url("", [], 18180),
            "http://127.0.0.1:18180/",
        )

    def test_project_state_effective_url_on_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = {
                "id": "heygem-test",
                "name": "HeyGem Test",
                "type": "command",
                "working_directory": str(root),
                "command": ["python", "app.py"],
                "expected_ports": [8383],
                "url": "http://127.0.0.1:8383/",
                "enabled": True,
            }
            project = server.normalize_project(raw, root / "port-console.project.json")
            # Simulate drift_ports=[18180] via patch
            from unittest.mock import patch
            with patch.object(server, "discover_project_drift_ports", return_value=[18180]):
                state = server.project_state(project, active_ports=set(), tcp_items=[{"port": 18180}])
                self.assertEqual(state["state"], "running")
                self.assertTrue(state["port_drift"])
                self.assertEqual(state["effective_port"], 18180)
                self.assertEqual(state["effective_url"], "http://127.0.0.1:18180/")
                self.assertEqual(state["url"], "http://127.0.0.1:18180/")
                self.assertEqual(state["configured_url"], "http://127.0.0.1:8383/")

    def test_delete_project_and_atlas_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgg_path = Path(directory) / "projects.json"
            cgg_data = {
                "projects": [
                    {
                        "id": "port-atlas",
                        "name": "Port Atlas",
                        "expected_ports": [8787],
                    },
                    {
                        "id": "stale-proj",
                        "name": "Stale Project",
                        "expected_ports": [4173],
                    },
                ]
            }
            cgg_path.write_text(json.dumps(cgg_data, ensure_ascii=False), encoding="utf-8")
            from unittest.mock import patch
            with patch.object(server, "CONFIG_PATH", cgg_path):
                with self.assertRaises(ValueError):
                    server.delete_project("port-atlas")
                res = server.delete_project("stale-proj")
                self.assertTrue(res["deleted"])
                saved = json.loads(cgg_path.read_text(encoding="utf-8"))
                self.assertEqual(len(saved["projects"]), 1)
                self.assertEqual(saved["projects"][0]["id"], "port-atlas")

if __name__ == "__main__":

    unittest.main()
