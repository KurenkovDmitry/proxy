import socket
import threading
import ssl
import http.server
import socketserver
import json
from urllib.parse import urlparse
from OpenSSL import crypto
import tabulate

# Список для хранения запросов
requests = []
request_id = 0
serial_counter = 2  # Начинаем с 2


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
    with open("ca.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    with open("ca.key", "wb") as f:
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


# Обработка клиента
def handle_client(client_socket):
    global request_id, serial_counter
    try:
        request_data = client_socket.recv(4096).decode(errors='ignore')
        if not request_data:
            client_socket.close()
            return

        first_line = request_data.split('\n')[0]
        method, url, _ = first_line.split()
        print(f"Received: method={method}, url={url}")

        # Сохранение запроса
        req = {"id": request_id, "method": method, "url": url, "raw": request_data}
        requests.append(req)
        request_id += 1

        if method == "CONNECT":
            try:
                host_port = url.split(':', 1)
                host = host_port[0]
                port = int(host_port[1])
                print(f"CONNECT: host={host}, port={port}")
            except (ValueError, IndexError) as e:
                print(f"Error parsing CONNECT URL {url}: {e}")
                client_socket.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
                client_socket.close()
                return

            client_socket.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                server_socket.connect((host, port))
            except socket.gaierror as e:
                print(f"Failed to connect to {host}:{port}: {e}")
                client_socket.close()
                return

            def proxy_data(src, dst):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception as e:
                    print(f"Proxy data error: {e}")
                finally:
                    src.close()
                    dst.close()

            threading.Thread(target=proxy_data, args=(client_socket, server_socket)).start()
            threading.Thread(target=proxy_data, args=(server_socket, client_socket)).start()

        else:
            # Обработка HTTP
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            # Разделяем заголовки и тело, учитывая Proxy-Connection
            if '\r\n\r\n' in request_data:
                headers_part, body = request_data.split('\r\n\r\n', 1)
                headers = headers_part.split('\n')
                # Удаляем Proxy-Connection из заголовков
                headers = [line for line in headers if not line.lower().startswith('proxy-connection')]
                new_request = f"{method} {path} HTTP/1.1\r\n" + '\n'.join(headers[1:]) + '\r\n\r\n' + body
            else:
                headers = request_data.split('\n')
                # Удаляем Proxy-Connection из заголовков
                headers = [line for line in headers if not line.lower().startswith('proxy-connection')]
                new_request = f"{method} {path} HTTP/1.1\r\n" + '\n'.join(headers[1:]) + '\r\n'

            # Соединение с сервером
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, port))
            server_socket.sendall(new_request.encode())

            # Пересылка ответа
            while True:
                data = server_socket.recv(4096)
                if not data:
                    break
                client_socket.sendall(data)

            server_socket.close()
            client_socket.close()
    except Exception as e:
        print(f"Error in handle_client: {e}")
        client_socket.close()


# Простой сканер уязвимостей
def scan_request(req_id):
    req = next((r for r in requests if r["id"] == req_id), None)
    if not req:
        return "Request not found"

    # Список подозрительных паттернов для поиска
    suspicious_patterns = [
        "<script>", "alert(", "onerror=", "javascript:",  # XSS
        "sql", "union select", "drop table"  # SQL-инъекции
    ]

    # Проверка URL
    if any(pattern in req["url"].lower() for pattern in suspicious_patterns):
        return "Potential vulnerability detected in URL!"

    # Проверка заголовков
    for line in req["raw"].split('\n'):
        # Пропускаем безопасные заголовки
        if line.lower().startswith('host:') or line.lower().startswith('user-agent:'):
            continue
        if any(pattern in line.lower() for pattern in suspicious_patterns):
            return "Potential vulnerability detected in headers!"

    # Проверка тела запроса для POST
    if req["method"] == "POST":
        body = req["raw"].split('\r\n\r\n', 1)[1] if '\r\n\r\n' in req["raw"] else ""
        if any(pattern in body.lower() for pattern in suspicious_patterns):
            return "Potential vulnerability detected in request body!"

    return "No vulnerabilities found"


# Повтор запроса
def repeat_request(req_id):
    req = next((r for r in requests if r["id"] == req_id), None)
    if not req:
        return "Request not found"
    parsed = urlparse(req["url"])
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    headers = [line for line in req["raw"].split('\n') if not line.lower().startswith('proxy-connection')]
    new_request = f"{req['method']} {path} HTTP/1.1\r\n" + '\n'.join(headers[1:]) + '\r\n'

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, port))
    server_socket.sendall(new_request.encode())
    response = server_socket.recv(4096).decode(errors='ignore')
    server_socket.close()
    return response


class APIHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global requests, request_id
        if self.path.startswith("/requests"):
            # Парсинг пути и параметров
            path_parts = self.path.split('?')
            base_path = path_parts[0]
            query_params = path_parts[1] if len(path_parts) > 1 else ""
            params = dict(param.split('=') for param in query_params.split('&') if '=' in param)

            # Фильтрация по методу, если указано
            if "method" in params:
                filtered_requests = [r for r in requests if r["method"] == params["method"]]
            else:
                filtered_requests = requests

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
            req = next((r for r in requests if r["id"] == req_id), None)
            self.send_response(200 if req else 404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(req if req else {"error": "Not found"}).encode())

        elif self.path.startswith("/stats"):
            path_parts = self.path.split('?', 1)
            base_path = path_parts[0]
            query_params = path_parts[1] if len(path_parts) > 1 else ""
            params = dict(param.split('=') for param in query_params.split('&') if '=' in param)

            # Подсчет статистики
            output_format = params.get("format", "json")
            stats = {
                "total_requests": len(requests),
                "methods": {method: sum(1 for r in requests if r["method"] == method)
                            for method in set(r["method"] for r in requests)}
            }
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
            req_id = int(self.path.split("/")[-1])
            response = repeat_request(req_id)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(response.encode())
        elif self.path.startswith("/scan/"):
            req_id = int(self.path.split("/")[-1])
            result = scan_request(req_id)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(result.encode())
        elif self.path == "/clear_requests":
            requests = []
            request_id = 0
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
