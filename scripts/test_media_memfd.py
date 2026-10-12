"""Exercise the worker's exit classification without a live FFmpeg process."""
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('media_memfd', os.path.join(os.path.dirname(__file__), 'media-memfd.py'))
worker = importlib.util.module_from_spec(spec)
# The protocol test is portable; actual memfd/FFmpeg acceptance runs on Linux.
with patch.dict(sys.modules, {'resource': types.SimpleNamespace(RLIMIT_CORE=0, setrlimit=lambda *_: None)}):
    spec.loader.exec_module(worker)


class WorkerClassification(unittest.TestCase):
    def run_worker(self, exit_code):
        with tempfile.TemporaryDirectory() as directory:
            descriptors = []

            def memfd(name, _flags):
                fd = os.open(os.path.join(directory, name), os.O_CREAT | os.O_RDWR, 0o600)
                descriptors.append(fd)
                return fd

            def run(*_args, **_kwargs):
                if exit_code:
                    raise subprocess.CalledProcessError(exit_code, 'synthetic ffmpeg')
                os.write(descriptors[1], b'synthetic output')

            with patch.object(os, 'memfd_create', memfd, create=True), \
                    patch.object(os, 'MFD_CLOEXEC', 0, create=True), \
                    patch.object(sys, 'argv', ['worker', '1024', '1024']), \
                    patch.object(sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(b'synthetic input'))), \
                    patch.object(sys, 'stdout', types.SimpleNamespace(buffer=io.BytesIO())), \
                    patch.object(subprocess, 'run', side_effect=run):
                worker.main()

    def test_parser_rejection(self):
        for code in (1, 183, 187, 234):
            with self.subTest(code=code), self.assertRaises(worker.InvalidMedia):
                self.run_worker(code)

    def test_unavailable_commands_remain_service_failures(self):
        for code in (126, 127, -9, 244, 255):
            with self.subTest(code=code), self.assertRaises(subprocess.CalledProcessError):
                self.run_worker(code)

    def test_success(self):
        self.run_worker(0)


if __name__ == '__main__':
    unittest.main()
