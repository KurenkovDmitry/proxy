import socket
import threading
import ssl
import http.server
import socketserver
import json
from urllib.parse import urlparse, parse_qs, urlencode
from http.client import HTTPResponse
from io import BytesIO
from OpenSSL import crypto
import tabulate
from pymongo import MongoClient
from http.cookies import SimpleCookie
import gzip
import zlib
import brotli

client = MongoClient('mongo', 27017)
db = client['proxy_db']
collection = db['requests']
counters = db['counters']
if counters.find_one({"_id": "request_id"}) is None:
    counters.insert_one({"_id": "request_id", "seq": 0})


def get_next_id():
    return counters.find_one_and_update(
        {"_id": "request_id"},
        {"$inc": {"seq": 1}},
        return_document=True
    )["seq"]


# Генерация корневого сертификата и ключа один раз
def generate_ca():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(1)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 лет
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.get_subject().CN = "Custom CA"
    ca_cert.set_pubkey(key)
    ca_cert.sign(key, 'sha256')
    with open("/app/ca.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    with open("/app/ca.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return ca_cert, key


# Генерация общего ключа для сертификатов хостов
def generate_cert_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    with open("cert.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return key


# Генерация сертификата для хоста с уникальным серийным номером
def generate_cert_for_host(host, ca_cert, ca_key, cert_key, serial):
    req = crypto.X509Req()
    req.get_subject().CN = host
    req.set_pubkey(cert_key)
    req.sign(cert_key, "sha256")

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # 1 год
    cert.set_subject(req.get_subject())
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(ca_key, "sha256")
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)


# Инициализация корневого сертификата и общего ключа при запуске
ca_cert, ca_key = generate_ca()
cert_key = generate_cert_key()
serial_counter = 2


def parse_request(request_data):
    lines = request_data.split('\r\n')
    first_line = lines[0].split()
    method, full_path = first_line[0], first_line[1]
    parsed_url = urlparse(full_path)

    if method == "CONNECT":
        scheme = "https"
        host, port = full_path.split(':')
        path = "/"
    else:
        scheme = parsed_url.scheme or "http"
        host = parsed_url.hostname or ""
        port = parsed_url.port or (443 if scheme == "https" else 80)
        path = parsed_url.path or "/"

    get_params = parse_qs(parsed_url.query)
    headers = {}
    cookies = {}
    post_params = {}
    header_end = lines.index('')
    header_lines = lines[1:header_end]
    for line in header_lines:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
            if key.lower() == 'cookie':
                cookie = SimpleCookie(value)
                for k in cookie:
                    cookies[k] = cookie[k].value

    if method == "POST" and headers.get('Content-Type') == 'application/x-www-form-urlencoded':
        body = '\r\n'.join(lines[header_end + 1:])
        post_params = parse_qs(body)

    return {
        "method": method,
        "url": full_path,
        "host": host,
        "path": path,
        "scheme": scheme,
        "port": port,
        "get_params": {k: v[0] if len(v) == 1 else v for k, v in get_params.items()},
        "headers": headers,
        "cookies": cookies,
        "post_params": {k: v[0] if len(v) == 1 else v for k, v in post_params.items()},
        "raw": request_data
    }


def parse_response(response_data):
    # Обработка сжатия на уровне байтов перед декодированием
    headers_part_bytes, sep, body_bytes = response_data.partition(b'\r\n\r\n')
    if not sep:
        headers_part_bytes = response_data
        body_bytes = b""

    headers_part = headers_part_bytes.decode('latin-1', errors='ignore')
    headers_lines = headers_part.split('\r\n')

    # Декодируем байты ответа в строку (предполагая, что это HTTP-ответ)
    try:
        response_str = response_data.decode('utf-8')
    except UnicodeDecodeError:
        response_str = response_data.decode('latin1', errors='ignore')

    # Разделяем ответ на заголовки и тело
    try:
        headers_part, body = response_str.split('\r\n\r\n', 1)
    except ValueError:
        # Если разделить не удалось, считаем, что тела нет
        headers_part = response_str
        body = ""

    # Парсим первую строку (статус)
    headers_lines = headers_part.split('\r\n')
    first_line = headers_lines[0]
    try:
        protocol, status_code, reason = first_line.split(' ', 2)
        status_code = int(status_code)
    except (ValueError, IndexError):
        status_code = 0
        reason = "Unknown"

    # Парсим заголовки
    headers = {}
    for line in headers_lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    # Обработка сжатия тела
    content_encoding = headers.get('Content-Encoding', '')
    if content_encoding == 'gzip':
        try:
            body_bytes = gzip.decompress(body_bytes)
        except Exception:
            pass
    elif content_encoding == 'deflate':
        try:
            body_bytes = zlib.decompress(body_bytes)
        except Exception:
            pass
    elif content_encoding == 'br':
        try:
            body_bytes = brotli.decompress(body_bytes)
        except Exception:
            pass

    # Декодируем тело
    try:
        body_str = body_bytes.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        body_str = body_bytes.decode('latin-1', errors='ignore')

    return {
        "code": status_code,
        "message": reason,
        "headers": headers,
        "body": body_str
    }


# Обработка клиента
def handle_client(client_socket):
    global serial_counter
    try:
        request_data = client_socket.recv(4096).decode(errors='ignore')
        if not request_data:
            client_socket.close()
            return

        parsed_request = parse_request(request_data)
        req_id = get_next_id()
        collection.insert_one({"id": req_id, **parsed_request})

        if request_data.startswith('CONNECT'):
            host_port = request_data.split(' ')[1]
            host, port = host_port.split(':')
            host, port = host.decode(), int(port)

            # Отправляем подтверждение
            client_socket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Генерируем сертификат на лету
            cert = generate_cert_for_host(host, ca_cert, ca_key, cert_key, serial_counter)
            serial_counter += 1

            # Настройка MITM-прокси
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=BytesIO(cert), keyfile="/app/ca.key")

            client_conn = context.wrap_socket(client_socket, server_side=True)

            # Соединение с целевым сервером
            server_socket = socket.create_connection((host, port))
            server_conn = ssl.create_default_context().wrap_socket(server_socket, server_hostname=host)

            # Буфер для сборки полных запросов
            client_buffer = b""
            server_buffer = b""

            def forward(src, dest, is_client, host=None, port=None):
                try:
                    reader = src.makefile('rb')
                    while True:
                        # Чтение первой строки запроса
                        request_line = reader.readline()
                        if not request_line:
                            break

                        headers = b""
                        while True:
                            line = reader.readline()
                            if line in (b"\r\n", b"\n", b""):
                                break
                            headers += line

                        full_headers = request_line + headers + b"\r\n"

                        # Парсинг заголовков
                        header_text = full_headers.decode('utf-8', errors='replace')
                        header_lines = header_text.split('\r\n')
                        method, path, _ = header_lines[0].split(' ', 2)
                        headers_dict = {}
                        content_length = 0

                        for line in header_lines[1:]:
                            if ':' in line:
                                k, v = line.split(':', 1)
                                headers_dict[k.strip()] = v.strip()
                                if k.lower() == "content-length":
                                    content_length = int(v.strip())

                        # Чтение тела, если есть
                        body = reader.read(content_length) if content_length > 0 else b""

                        parsed = {
                            "id": get_next_id(),
                            "scheme": "https",
                            "method": method,
                            "path": path,
                            "host": host,
                            "port": port,
                            "headers": headers_dict,
                            "body": body.decode('utf-8', errors='replace')
                        }

                        collection.insert_one(parsed)
                        print(f"HTTPS request logged: {method} {path}")

                        # Перенаправление
                        dest.sendall(full_headers + body)

                except Exception as e:
                    print(f"[!] Error in forward: {e}")

            # Запуск потоков для двусторонней передачи
            threading.Thread(target=forward, args=(client_conn, server_conn, True, host, port)).start()
            threading.Thread(target=forward, args=(server_conn, client_conn, False)).start()

        else:
            host = parsed_request["host"]
            port = parsed_request["headers"].get("Port", 80)
            headers = parsed_request["headers"]
            headers.pop("Proxy-Connection", None)

            # Соединение с сервером
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, int(port)))

            request_lines = request_data.split('\r\n')
            request_lines = [line for line in request_lines if not line.lower().startswith('proxy-connection')]
            new_request = '\r\n'.join(request_lines).encode()

            server_socket.sendall(new_request)
            response_data = b""

            # Пересылка ответа
            while True:
                data = server_socket.recv(4096)
                if not data:
                    break
                response_data += data
                client_socket.sendall(data)

            server_socket.close()
            client_socket.close()

            parsed_response = parse_response(response_data)
            content_encoding = parsed_response["headers"].get("Content-Encoding")
            response_body = parsed_response["body"].encode()  # Или обработка сжатия, если нужно

            if content_encoding == 'gzip':
                decompressed_body = gzip.decompress(response_body)
            elif content_encoding == 'deflate':
                decompressed_body = zlib.decompress(response_body)
            elif content_encoding == 'br':
                decompressed_body = brotli.decompress(response_body)
            else:
                decompressed_body = response_body

            try:
                body_str = decompressed_body.decode('utf-8')
            except UnicodeDecodeError:
                body_str = decompressed_body.decode('latin1', errors='ignore')

            parsed_response = parse_response(response_data)
            collection.update_one({"id": req_id}, {"$set": {"response": parsed_response}})
    except Exception as e:
        print(f"Error in handle_client: {e}")
        client_socket.close()


# Простой сканер уязвимостей
def scan_request(req_id):
    req = collection.find_one({"id": req_id}, {"_id": 0})
    if not req:
        return "Request not found"
    if req["method"] == "CONNECT":
        return "Scanning not applicable for CONNECT requests"

    # Проверяем наличие порта и задаем значение по умолчанию
    port = req.get("port")
    if port is None:
        scheme = req.get("scheme", "http")
        port = 443 if scheme == "https" else 80
    try:
        port = int(port)  # Убеждаемся, что порт - целое число
    except (TypeError, ValueError):
        return "Invalid port value"

    original_response = req.get("response")
    if not original_response:
        return "No response found for this request"
    original_code = original_response["code"]
    original_length = len(original_response["body"].encode())
    host = req["host"]
    scheme = req.get("scheme", "http")

    def send_modified_request(modified_req):
        try:
            if scheme == 'https':
                context = ssl.create_default_context()
                server_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            else:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, port))

            if modified_req["method"] == "GET":
                query_string = urlencode(modified_req["get_params"], doseq=True)
                path_with_query = modified_req["path"] + ('?' + query_string if query_string else '')
                request_line = f"GET {path_with_query} HTTP/1.1\r\n"
            elif modified_req["method"] == "POST":
                request_line = f"POST {modified_req['path']} HTTP/1.1\r\n"
                body = urlencode(modified_req["post_params"], doseq=True)
                modified_req["headers"]["Content-Length"] = str(len(body))
            else:
                request_line = f"{modified_req['method']} {modified_req['path']} HTTP/1.1\r\n"

            headers_str = ''.join(f"{k}: {v}\r\n" for k, v in modified_req["headers"].items())
            request = request_line + headers_str + '\r\n'
            if modified_req["method"] == "POST":
                request += body

            server_socket.sendall(request.encode())
            response_data = b""
            while True:
                data = server_socket.recv(4096)
                if not data:
                    break
                response_data += data
            server_socket.close()
            parsed_response = parse_response(response_data)
            return parsed_response["code"], len(parsed_response["body"].encode())
        except Exception as e:
            print(f"Error sending modified request: {e}")
            return None, None

    vulnerabilities = []
    for param in req.get("get_params", {}):
        for char in ["'", '"']:
            modified_get_params = {k: v + char if k == param else v for k, v in req["get_params"].items()}
            modified_req = req.copy()
            modified_req["get_params"] = modified_get_params
            code, length = send_modified_request(modified_req)
            if code is not None and (code != original_code or length != original_length):
                vulnerabilities.append(f"GET param '{param}' with '{char}'")

    if req["method"] == "POST":
        for param in req.get("post_params", {}):
            for char in ["'", '"']:
                modified_post_params = {k: v + char if k == param else v for k, v in req["post_params"].items()}
                modified_req = req.copy()
                modified_req["post_params"] = modified_post_params
                code, length = send_modified_request(modified_req)
                if code is not None and (code != original_code or length != original_length):
                    vulnerabilities.append(f"POST param '{param}' with '{char}'")

    for cookie in req.get("cookies", {}):
        for char in ["'", '"']:
            modified_cookies = {k: v + char if k == cookie else v for k, v in req["cookies"].items()}
            cookie_header = '; '.join(f"{k}={v}" for k, v in modified_cookies.items())
            modified_headers = req["headers"].copy()
            modified_headers["Cookie"] = cookie_header
            modified_req = req.copy()
            modified_req["headers"] = modified_headers
            code, length = send_modified_request(modified_req)
            if code is not None and (code != original_code or length != original_length):
                vulnerabilities.append(f"Cookie '{cookie}' with '{char}'")

    for header in req["headers"]:
        for char in ["'", '"']:
            modified_headers = {k: v + char if k == header else v for k, v in req["headers"].items()}
            modified_req = req.copy()
            modified_req["headers"] = modified_headers
            code, length = send_modified_request(modified_req)
            if code is not None and (code != original_code or length != original_length):
                vulnerabilities.append(f"Header '{header}' with '{char}'")

    return "Potential vulnerabilities found:\n" + "\n".join(vulnerabilities) if vulnerabilities else "No vulnerabilities found"


def repeat_request(req_id, follow_redirects=False, max_redirects=10):
    try:
        req = collection.find_one({"id": req_id}, {"_id": 0})
        if not req:
            return "Request not found"
        if req["method"] == "CONNECT":
            return "Cannot repeat CONNECT requests directly, use stored HTTPS request"

        host = req["host"]
        port = req.get("port", 80 if req.get("scheme") == "http" else 443)
        method = req["method"]
        path = req["path"]
        headers = {k: v for k, v in req["headers"].items() if k.lower() != "proxy-connection"}
        get_params = req["get_params"]
        post_params = req["post_params"]
        scheme = req.get("scheme", "http")

        # Создание соединения в зависимости от схемы
        if scheme == "https":
            context = ssl.create_default_context()
            # Игнорируем проверку сертификата, как в curl -k
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))

        # Формирование запроса
        if method == "GET":
            query_string = urlencode(get_params or {}, doseq=True)
            full_path = path + ('?' + query_string if query_string else '')
            request_line = f"{method} {full_path} HTTP/1.1\r\n"
            body = ""
        elif method == "POST":
            request_line = f"{method} {path} HTTP/1.1\r\n"
            body = urlencode(post_params or {}, doseq=True)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))
        else:
            request_line = f"{method} {path} HTTP/1.1\r\n"
            body = ""

        headers_str = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
        new_request = request_line + headers_str + '\r\n' + body

        # Отправка запроса и получение ответа
        server_socket.sendall(new_request.encode())
        response_data = b""
        while True:
            data = server_socket.recv(4096)
            if not data:
                break
            response_data += data
        server_socket.close()

        # Парсинг ответа
        parsed_response = parse_response(response_data)
        raw_response = response_data.decode('utf-8', errors='ignore')

        # Обработка редиректов (если включено)
        if follow_redirects and 300 <= parsed_response["code"] < 400:
            redirect_count = 0
            current_host = host
            current_port = port
            current_headers = headers.copy()
            current_scheme = scheme

            while 300 <= parsed_response["code"] < 400 and redirect_count < max_redirects:
                location = parsed_response["headers"].get("Location")
                if not location:
                    break

                parsed_url = urlparse(location)
                new_host = parsed_url.hostname or current_host
                new_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                new_path = parsed_url.path or "/"
                new_scheme = parsed_url.scheme or current_scheme
                new_get_params = parse_qs(parsed_url.query)

                if new_host != current_host:
                    current_headers["Host"] = new_host

                # Повторная отправка как GET-запрос
                request_line = f"GET {new_path} HTTP/1.1\r\n"
                headers_str = ''.join(f"{k}: {v}\r\n" for k, v in current_headers.items())
                new_request = request_line + headers_str + '\r\n'

                if new_scheme == "https":
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    server_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=new_host)
                else:
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((new_host, new_port))
                server_socket.sendall(new_request.encode())
                response_data = b""
                while True:
                    data = server_socket.recv(4096)
                    if not data:
                        break
                    response_data += data
                server_socket.close()

                parsed_response = parse_response(response_data)
                raw_response = response_data.decode('utf-8', errors='ignore')
                redirect_count += 1
                current_host = new_host
                current_port = new_port
                current_scheme = new_scheme

            if redirect_count >= max_redirects:
                return "Error: Maximum redirect limit reached"

        return raw_response
    except Exception as e:
        return f"Error: {str(e)}"


class APIHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/requests"):
            # Парсинг пути и параметров
            path_parts = self.path.split('?')
            base_path = path_parts[0]
            query_params = path_parts[1] if len(path_parts) > 1 else ""
            params = dict(param.split('=') for param in query_params.split('&') if '=' in param)

            query = {}
            if "method" in params:
                query["method"] = params["method"]
            filtered_requests = list(collection.find(query, {"_id": 0}).sort("id", 1))

            # Определение формата вывода
            output_format = params.get("format", "json")  # По умолчанию JSON
            if output_format == "json":
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(filtered_requests).encode())
            elif output_format == "table":
                # Создание таблицы
                table_data = [[r["id"], r["method"], r["url"]] for r in filtered_requests]
                table = tabulate.tabulate(table_data, headers=["ID", "Method", "URL"], tablefmt="grid")
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(table.encode())
            else:
                self.send_response(400)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid format. Use 'json' or 'table'.")

        elif self.path.startswith("/request/"):
            req_id = int(self.path.split("/")[-1])
            req = collection.find_one({"id": req_id}, {"_id": 0})
            self.send_response(200 if req else 404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(req if req else {"error": "Not found"}).encode())

        elif self.path.startswith("/stats"):
            path_parts = self.path.split('?', 1)
            base_path = path_parts[0]
            query_params = path_parts[1] if len(path_parts) > 1 else ""
            params = dict(param.split('=') for param in query_params.split('&') if '=' in param)

            total_requests = collection.count_documents({})
            method_counts = collection.aggregate([
                {"$group": {"_id": "$method", "count": {"$sum": 1}}}
            ])
            methods = {doc["_id"]: doc["count"] for doc in method_counts}
            stats = {
                "total_requests": total_requests,
                "methods": methods
            }

            output_format = params.get("format", "json")
            if output_format == "json":
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(stats).encode())
            elif output_format == "table":
                table_data = [["Total Requests", stats["total_requests"]]]
                for method, count in stats["methods"].items():
                    table_data.append([f"{method} Requests", count])
                table = tabulate.tabulate(table_data, headers=["Metric", "Value"], tablefmt="grid")
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(table.encode())
            else:
                self.send_response(400)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid format. Use 'json' or 'table'.")

        elif self.path.startswith("/repeat/"):
            path_parts = self.path.split('?')
            base_path = path_parts[0]
            query_params = parse_qs(path_parts[1]) if len(path_parts) > 1 else {}
            req_id = int(base_path.split("/")[-1])
            follow_redirects = query_params.get("follow_redirects", ["false"])[0].lower() == "true"

            response = repeat_request(req_id, follow_redirects=follow_redirects)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(response.encode())
        elif self.path.startswith("/scan/"):
            req_id = int(self.path.split("/")[-1])
            try:
                result = scan_request(req_id)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(result.encode())
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(f"Ошибка сканирования: {str(e)}".encode())
        elif self.path == "/clear_requests":
            collection.delete_many({})
            counters.update_one({"_id": "request_id"}, {"$set": {"seq": 0}})
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Requests cleared")
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")


def start_api():
    httpd = socketserver.TCPServer(("0.0.0.0", 8000), APIHandler)
    httpd.serve_forever()


# Запуск прокси
def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))
    server.listen(5)
    print("Proxy listening on port 8080...")
    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()


if __name__ == "__main__":
    threading.Thread(target=start_api).start()
    start_proxy()
