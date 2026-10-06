"""Real local TLS evidence transport, frozen before network transport implementation."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

GATE = Path(__file__).resolve().parents[1] / "production_gate.py"


class EvidenceTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="factory-tls-evidence-")
        root = Path(cls.directory.name)
        key, cert = root / "key.pem", root / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        cls.payload = (b"actual-immutable-evidence-block\n" * 40000)
        payload = cls.payload
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/immutable/object")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        cls.server = HTTPServer(("localhost", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.prefix = "https://localhost:" + str(cls.server.server_port) + "/immutable/"
        cls.old_cert = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(cert)
        spec = importlib.util.spec_from_file_location("factory_transport_under_test", GATE)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        if cls.old_cert is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = cls.old_cert
        cls.directory.cleanup()

    def setUp(self):
        self.policy = {"production": {"evidence_transport": {"allowed_url_prefixes": [self.prefix], "maximum_object_bytes": 4 * 1024 * 1024, "timeout_seconds": 3}}}
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def fetch(self, suffix="object", digest=None, size=None, policy=None):
        return self.module.download_object(self.prefix + suffix, digest or self.digest, len(self.payload) if size is None else size, policy or self.policy)

    def test_full_size_real_tls_transfer_preserves_exact_bytes(self):
        self.assertGreater(len(self.payload), 48 * 1024)
        self.assertEqual(self.fetch(), self.payload)

    def test_bad_digest_rejected(self):
        with self.assertRaises(self.module.Rejection):
            self.fetch(digest="0" * 64)

    def test_untrusted_origin_rejected_before_network(self):
        with self.assertRaises(self.module.Rejection):
            self.module.download_object("https://example.invalid/immutable/object", self.digest, len(self.payload), self.policy)

    def test_insecure_http_rejected(self):
        with self.assertRaises(self.module.Rejection):
            self.module.download_object(self.prefix.replace("https:", "http:") + "object", self.digest, len(self.payload), self.policy)

    def test_redirect_rejected(self):
        with self.assertRaises(self.module.Rejection):
            self.fetch("redirect")

    def test_oversized_content_rejected(self):
        self.policy["production"]["evidence_transport"]["maximum_object_bytes"] = 100
        with self.assertRaises(self.module.Rejection):
            self.fetch()

    def test_wrong_declared_length_rejected(self):
        with self.assertRaises(self.module.Rejection):
            self.fetch(size=20)

    def test_credentials_or_query_are_not_transports(self):
        for url in (self.prefix.replace("https://", "https://user:secret@") + "object", self.prefix + "object?token=secret"):
            with self.assertRaises(self.module.Rejection):
                self.module.download_object(url, self.digest, len(self.payload), self.policy)


if __name__ == "__main__":
    unittest.main(verbosity=2)
