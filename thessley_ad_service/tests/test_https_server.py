import hashlib
import http.client
import ipaddress
import json
import os
import ssl
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from infra.thessley_ad_service.http_api import RawBodyRoute
from infra.thessley_ad_service.https_server import make_server


class HttpsServerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cert_path = os.path.join(self.temp.name, "cert.pem")
        self.key_path = os.path.join(self.temp.name, "key.pem")
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256())
        )
        with open(self.cert_path, "wb") as stream:
            stream.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(self.key_path, "wb") as stream:
            stream.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        self.route_calls = []

        def route(client_ip, body, raw_body, auth_headers):
            self.route_calls.append((client_ip, raw_body, auth_headers))
            return 201, {"result": "ok", "body_sha256": hashlib.sha256(raw_body).hexdigest(), "body": body}

        self.server = make_server(("127.0.0.1", 0), self.cert_path, self.key_path,
                                  {"/test": RawBodyRoute(route)})
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"https://127.0.0.1:{self.server.server_address[1]}"
        self.context = ssl._create_unverified_context()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def test_preserves_raw_json_and_machine_auth_headers(self):
        raw = b'{ "sample" : 1 }'
        request = Request(
            self.base + "/test",
            data=raw,
            headers={
                "Content-Type": "application/json",
                "X-Thessley-Machine-ID": "machine-id",
                "X-Ignored": "not-forwarded",
            },
            method="POST",
        )
        with urlopen(request, context=self.context, timeout=3) as response:
            result = json.load(response)
            self.assertEqual(response.status, 201)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(result["body_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.route_calls[0][1], raw)
        self.assertEqual(self.route_calls[0][2], {"x-thessley-machine-id": "machine-id"})

    def test_unknown_path_and_get_are_rejected(self):
        request = Request(self.base + "/test?extra=1", data=b"{}",
                          headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as error:
            urlopen(request, context=self.context, timeout=3)
        self.assertEqual(error.exception.code, 404)
        with self.assertRaises(HTTPError) as error:
            urlopen(self.base + "/test", context=self.context, timeout=3)
        self.assertEqual(error.exception.code, 405)
        self.assertEqual(self.route_calls, [])

    def test_oversized_body_is_rejected(self):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.server.server_address[1], context=self.context, timeout=3
        )
        connection.request("POST", "/test", body=b"x" * (64 * 1024 + 1),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        self.assertEqual(self.route_calls, [])
        connection.close()


if __name__ == "__main__":
    unittest.main()
