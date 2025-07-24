#!/usr/bin/env python3
"""
High-Performance Multi-Protocol Proxy Server
Supports SOCKS5, SOCKS4, and HTTP protocols with authentication and ngrok integration
"""

import sys
import os
import json
import socket
import threading
import struct
import select
import time
import logging
from datetime import datetime
from urllib.parse import urlparse
import base64
import subprocess
import yaml

# Auto-install required modules
def install_and_import(package, import_name=None):
    if import_name is None:
        import_name = package
    try:
        __import__(import_name)
    except ImportError:
        print("Installing {}...".format(package))
        os.system("{} -m pip install {}".format(sys.executable, package))
        __import__(import_name)

# Install required packages
required_packages = [('pyngrok', 'pyngrok'), ('pyyaml', 'yaml')]
for package, import_name in required_packages:
    install_and_import(package, import_name)

from pyngrok import ngrok, conf

class ProxyConfig:
    """Configuration manager for proxy settings"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file"""
        default_config = {
            "port": 8080,
            "bind_address": "0.0.0.0",
            "username": "",
            "password": "",
            "max_connections": 1000,
            "buffer_size": 8192,
            "timeout": 30,
            "log_level": "INFO",
            "ngrok": {
                "enabled": False,
                "token": "",
                "region": "us"
            },
            "upstream_proxy": {
                "enabled": False,
                "host": "",
                "port": 0,
                "username": "",
                "password": "",
                "type": "socks5"  # socks5, socks4, http
            },
            "protocols": {
                "socks5": True,
                "socks4": True,
                "http": True
            }
        }
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            # Merge with defaults
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            return config
        except IOError:
            return None  # Config file doesn't exist
        except ValueError as e:
            print("Error parsing config file: {}".format(e))
            return default_config
    
    def save_config(self, config):
        """Save configuration to JSON file"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)
    
    def initial_setup(self):
        """Initial setup process"""
        print("=== Proxy Server Setup ===")
        config = {
            "port": 8080,
            "bind_address": "0.0.0.0",
            "username": "",
            "password": "",
            "max_connections": 1000,
            "buffer_size": 8192,
            "timeout": 30,
            "log_level": "INFO",
            "ngrok": {
                "enabled": False,
                "token": "",
                "region": "us"
            },
            "upstream_proxy": {
                "enabled": False,
                "host": "",
                "port": 0,
                "username": "",
                "password": "",
                "type": "socks5"
            },
            "protocols": {
                "socks5": True,
                "socks4": True,
                "http": True
            }
        }
        
        # Step 1: Port configuration
        while True:
            try:
                port_input = input("Enter port (default 8080): ").strip()
                if not port_input:
                    port = 8080
                else:
                    port = int(port_input)
                    if port < 1 or port > 65535:
                        print("Port must be between 1 and 65535")
                        continue
                config["port"] = port
                break
            except ValueError:
                print("Invalid port number. Please enter a valid number.")
        
        # Step 2: Authentication
        while True:
            auth_choice = input("Add username and password? (1: Yes, 2: No): ").strip()
            if auth_choice == "1":
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                config["username"] = username
                config["password"] = password
                break
            elif auth_choice == "2":
                break
            else:
                print("Please enter 1 or 2")
        
        # Step 3: Ngrok configuration
        while True:
            ngrok_choice = input("Use ngrok? (1: Yes, 2: No): ").strip()
            if ngrok_choice == "1":
                token = input("Enter ngrok token: ").strip()
                if token:
                    config["ngrok"]["enabled"] = True
                    config["ngrok"]["token"] = token
                    
                    # Create ngrok.yml
                    self.create_ngrok_config(token, config["port"])
                    print("ngrok.yml created successfully")
                break
            elif ngrok_choice == "2":
                break
            else:
                print("Please enter 1 or 2")
        
        # Save configuration
        self.save_config(config)
        print("Configuration saved to config.json")
        return config
    
    def create_ngrok_config(self, token, port):
        """Create ngrok.yml configuration file"""
        ngrok_config = {
            "version": "2",
            "authtoken": token,
            "tunnels": {
                "proxy": {
                    "proto": "http",
                    "addr": port
                }
            }
        }
        
        with open("ngrok.yml", "w") as f:
            yaml.dump(ngrok_config, f, default_flow_style=False)

class ProxyLogger:
    """Enhanced logging system"""
    
    def __init__(self, config):
        self.setup_logging(config)
    
    def setup_logging(self, config):
        """Setup logging configuration"""
        log_level = getattr(logging, config.get('log_level', 'INFO').upper())
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/proxy_{}.log'.format(datetime.now().strftime("%Y%m%d"))),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def log_connection(self, client_addr, target_addr, protocol):
        """Log connection details"""
        self.logger.info("[{}] Connection: {} -> {}".format(protocol.upper(), client_addr, target_addr))
    
    def log_error(self, error, client_addr=None):
        """Log error details"""
        if client_addr:
            self.logger.error("Error from {}: {}".format(client_addr, error))
        else:
            self.logger.error("Error: {}".format(error))
    
    def log_data_transfer(self, client_addr, bytes_sent, bytes_received):
        """Log data transfer statistics"""
        self.logger.info("Transfer complete for {}: Sent {} bytes, Received {} bytes".format(
            client_addr, bytes_sent, bytes_received))

class NgrokManager:
    """Ngrok tunnel manager"""
    
    def __init__(self, config):
        self.config = config
        self.tunnel = None
    
    def start_tunnel(self):
        """Start ngrok tunnel"""
        if not self.config['ngrok']['enabled']:
            return None
        
        try:
            # Set ngrok auth token
            ngrok.set_auth_token(self.config['ngrok']['token'])
            
            # Start HTTP tunnel
            self.tunnel = ngrok.connect(self.config['port'], "http")
            print("Ngrok tunnel started: {}".format(self.tunnel.public_url))
            return self.tunnel.public_url
            
        except Exception as e:
            print("Failed to start ngrok tunnel: {}".format(e))
            return None
    
    def stop_tunnel(self):
        """Stop ngrok tunnel"""
        if self.tunnel:
            ngrok.disconnect(self.tunnel.public_url)
            self.tunnel = None
            print("Ngrok tunnel stopped")

class ProxyServer:
    """Main proxy server class supporting multiple protocols"""
    
    def __init__(self, config_file='config.json'):
        self.config_manager = ProxyConfig(config_file)
        
        # Check if config exists, if not run setup
        if self.config_manager.config is None:
            self.config = self.config_manager.initial_setup()
        else:
            self.config = self.config_manager.config
        
        self.logger = ProxyLogger(self.config)
        self.ngrok_manager = NgrokManager(self.config)
        self.running = False
        self.connections = []
        self.connection_count = 0
    
    def authenticate(self, username, password):
        """Authenticate user credentials"""
        if not self.config['username'] and not self.config['password']:
            return True  # No authentication required
        return (username == self.config['username'] and 
                password == self.config['password'])
    
    def connect_through_upstream(self, target_host, target_port):
        """Connect through upstream proxy if configured"""
        if not self.config['upstream_proxy']['enabled']:
            return None
        
        upstream = self.config['upstream_proxy']
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['timeout'])
            sock.connect((upstream['host'], upstream['port']))
            
            if upstream['type'] == 'socks5':
                return self.connect_socks5_upstream(sock, target_host, target_port, upstream)
            elif upstream['type'] == 'socks4':
                return self.connect_socks4_upstream(sock, target_host, target_port, upstream)
            elif upstream['type'] == 'http':
                return self.connect_http_upstream(sock, target_host, target_port, upstream)
            
        except Exception as e:
            self.logger.log_error("Upstream connection failed: {}".format(e))
            return None
    
    def connect_socks5_upstream(self, sock, target_host, target_port, upstream):
        """Connect through SOCKS5 upstream proxy"""
        try:
            # SOCKS5 handshake
            if upstream['username'] and upstream['password']:
                sock.send(b'\x05\x02\x00\x02')  # Auth methods: No auth, Username/Password
                response = sock.recv(2)
                if response[1] == 0x02:  # Username/Password auth required
                    # Send credentials
                    username = upstream['username'].encode('utf-8')
                    password = upstream['password'].encode('utf-8')
                    auth_req = struct.pack('!BB', 0x01, len(username)) + username + struct.pack('!B', len(password)) + password
                    sock.send(auth_req)
                    auth_resp = sock.recv(2)
                    if auth_resp[1] != 0x00:
                        raise Exception("Authentication failed")
            else:
                sock.send(b'\x05\x01\x00')  # No authentication
                sock.recv(2)
            
            # Connection request
            if target_host.replace('.', '').isdigit():  # IP address
                addr_type = 0x01
                addr = socket.inet_aton(target_host)
            else:  # Domain name
                addr_type = 0x03
                addr = struct.pack('!B', len(target_host)) + target_host.encode('utf-8')
            
            connect_req = struct.pack('!BBB', 0x05, 0x01, 0x00) + struct.pack('!B', addr_type) + addr + struct.pack('!H', target_port)
            sock.send(connect_req)
            
            response = sock.recv(10)
            if response[1] != 0x00:
                raise Exception("Connection failed")
            
            return sock
            
        except Exception as e:
            self.logger.log_error("SOCKS5 upstream error: {}".format(e))
            sock.close()
            return None
    
    def connect_socks4_upstream(self, sock, target_host, target_port, upstream):
        """Connect through SOCKS4 upstream proxy"""
        try:
            # SOCKS4 connection request
            if target_host.replace('.', '').isdigit():
                addr = socket.inet_aton(target_host)
            else:
                addr = socket.inet_aton(socket.gethostbyname(target_host))
            
            connect_req = struct.pack('!BBH', 0x04, 0x01, target_port) + addr + b'\x00'
            sock.send(connect_req)
            
            response = sock.recv(8)
            if response[1] != 0x5a:
                raise Exception("Connection failed")
            
            return sock
            
        except Exception as e:
            self.logger.log_error("SOCKS4 upstream error: {}".format(e))
            sock.close()
            return None
    
    def connect_http_upstream(self, sock, target_host, target_port, upstream):
        """Connect through HTTP upstream proxy"""
        try:
            # HTTP CONNECT request
            connect_req = "CONNECT {}:{} HTTP/1.1\r\n".format(target_host, target_port)
            connect_req += "Host: {}:{}\r\n".format(target_host, target_port)
            
            if upstream['username'] and upstream['password']:
                credentials = base64.b64encode("{}:{}".format(upstream['username'], upstream['password']).encode()).decode()
                connect_req += "Proxy-Authorization: Basic {}\r\n".format(credentials)
            
            connect_req += "\r\n"
            sock.send(connect_req.encode())
            
            response = sock.recv(1024).decode()
            if "200 Connection established" not in response:
                raise Exception("Connection failed")
            
            return sock
            
        except Exception as e:
            self.logger.log_error("HTTP upstream error: {}".format(e))
            sock.close()
            return None
    
    def handle_socks5(self, client_socket, client_addr):
        """Handle SOCKS5 protocol"""
        try:
            # Authentication negotiation
            data = client_socket.recv(256)
            if not data or data[0] != 0x05:
                return
            
            methods = data[2:2+data[1]]
            
            if self.config['username'] and self.config['password']:
                if 0x02 in methods:  # Username/Password authentication
                    client_socket.send(b'\x05\x02')  # Select username/password auth
                    
                    # Receive authentication request
                    auth_data = client_socket.recv(256)
                    username_len = auth_data[1]
                    username = auth_data[2:2+username_len].decode('utf-8')
                    password_len = auth_data[2+username_len]
                    password = auth_data[3+username_len:3+username_len+password_len].decode('utf-8')
                    
                    if self.authenticate(username, password):
                        client_socket.send(b'\x01\x00')  # Success
                    else:
                        client_socket.send(b'\x01\x01')  # Failure
                        return
                else:
                    client_socket.send(b'\x05\xFF')  # No acceptable methods
                    return
            else:
                client_socket.send(b'\x05\x00')  # No authentication required
            
            # Connection request
            data = client_socket.recv(256)
            if not data or data[0] != 0x05 or data[1] != 0x01:
                return
            
            addr_type = data[3]
            if addr_type == 0x01:  # IPv4
                target_host = socket.inet_ntoa(data[4:8])
                target_port = struct.unpack('!H', data[8:10])[0]
            elif addr_type == 0x03:  # Domain name
                domain_len = data[4]
                target_host = data[5:5+domain_len].decode('utf-8')
                target_port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
            else:
                client_socket.send(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Address type not supported
                return
            
            # Connect to target or upstream
            target_socket = self.connect_through_upstream(target_host, target_port)
            if not target_socket:
                try:
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_socket.settimeout(self.config['timeout'])
                    target_socket.connect((target_host, target_port))
                except Exception as e:
                    client_socket.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')  # Connection refused
                    self.logger.log_error("Target connection failed: {}".format(e), client_addr)
                    return
            
            # Send success response
            client_socket.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            
            self.logger.log_connection(client_addr, "{}:{}".format(target_host, target_port), "SOCKS5")
            self.relay_data(client_socket, target_socket, client_addr)
            
        except Exception as e:
            self.logger.log_error("SOCKS5 error: {}".format(e), client_addr)
        finally:
            client_socket.close()
    
    def handle_socks4(self, client_socket, client_addr):
        """Handle SOCKS4 protocol"""
        try:
            data = client_socket.recv(256)
            if not data or data[0] != 0x04 or data[1] != 0x01:
                return
            
            target_port = struct.unpack('!H', data[2:4])[0]
            target_ip = socket.inet_ntoa(data[4:8])
            
            # Find null terminator for user ID
            user_id = data[8:].split(b'\x00')[0]
            
            # Connect to target or upstream
            target_socket = self.connect_through_upstream(target_ip, target_port)
            if not target_socket:
                try:
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_socket.settimeout(self.config['timeout'])
                    target_socket.connect((target_ip, target_port))
                except Exception as e:
                    client_socket.send(b'\x00\x5b\x00\x00\x00\x00\x00\x00')  # Connection refused
                    self.logger.log_error("Target connection failed: {}".format(e), client_addr)
                    return
            
            # Send success response
            client_socket.send(b'\x00\x5a\x00\x00\x00\x00\x00\x00')
            
            self.logger.log_connection(client_addr, "{}:{}".format(target_ip, target_port), "SOCKS4")
            self.relay_data(client_socket, target_socket, client_addr)
            
        except Exception as e:
            self.logger.log_error("SOCKS4 error: {}".format(e), client_addr)
        finally:
            client_socket.close()
    
    def handle_http(self, client_socket, client_addr):
        """Handle HTTP CONNECT protocol"""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            lines = data.split('\r\n')
            
            if not lines[0].startswith('CONNECT'):
                client_socket.send(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                return
            
            # Parse CONNECT request
            target_info = lines[0].split(' ')[1]
            target_host, target_port = target_info.split(':')
            target_port = int(target_port)
            
            # Check authentication if required
            if self.config['username'] and self.config['password']:
                auth_found = False
                for line in lines:
                    if line.startswith('Proxy-Authorization:'):
                        auth_type, credentials = line.split(' ', 2)[1:]
                        if auth_type == 'Basic':
                            decoded = base64.b64decode(credentials).decode('utf-8')
                            username, password = decoded.split(':', 1)
                            if self.authenticate(username, password):
                                auth_found = True
                                break
                
                if not auth_found:
                    client_socket.send(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                                     b'Proxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                    return
            
            # Connect to target or upstream
            target_socket = self.connect_through_upstream(target_host, target_port)
            if not target_socket:
                try:
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_socket.settimeout(self.config['timeout'])
                    target_socket.connect((target_host, target_port))
                except Exception as e:
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    self.logger.log_error("Target connection failed: {}".format(e), client_addr)
                    return
            
            # Send success response
            client_socket.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
            
            self.logger.log_connection(client_addr, "{}:{}".format(target_host, target_port), "HTTP")
            self.relay_data(client_socket, target_socket, client_addr)
            
        except Exception as e:
            self.logger.log_error("HTTP error: {}".format(e), client_addr)
        finally:
            client_socket.close()
    
    def relay_data(self, client_socket, target_socket, client_addr):
        """Relay data between client and target with high performance"""
        try:
            bytes_sent = 0
            bytes_received = 0
            
            while True:
                ready, _, _ = select.select([client_socket, target_socket], [], [], 1)
                
                if not ready:
                    continue
                
                for sock in ready:
                    try:
                        data = sock.recv(self.config['buffer_size'])
                        if not data:
                            return
                        
                        if sock is client_socket:
                            target_socket.send(data)
                            bytes_sent += len(data)
                        else:
                            client_socket.send(data)
                            bytes_received += len(data)
                            
                    except Exception:
                        return
                        
        except Exception as e:
            self.logger.log_error("Relay error: {}".format(e), client_addr)
        finally:
            self.logger.log_data_transfer(client_addr, bytes_sent, bytes_received)
            try:
                target_socket.close()
            except:
                pass
    
    def handle_client(self, client_socket, client_addr):
        """Handle incoming client connection"""
        try:
            self.connection_count += 1
            client_socket.settimeout(self.config['timeout'])
            
            # Peek at first byte to determine protocol
            first_byte = client_socket.recv(1, socket.MSG_PEEK)
            if not first_byte:
                return
            
            if first_byte[0] == 0x05 and self.config['protocols']['socks5']:
                self.handle_socks5(client_socket, client_addr)
            elif first_byte[0] == 0x04 and self.config['protocols']['socks4']:
                self.handle_socks4(client_socket, client_addr)
            elif first_byte[0] in [ord('C'), ord('G'), ord('P')] and self.config['protocols']['http']:
                self.handle_http(client_socket, client_addr)
            else:
                self.logger.log_error("Unknown protocol from {}".format(client_addr))
                
        except Exception as e:
            self.logger.log_error("Client handling error: {}".format(e), client_addr)
        finally:
            try:
                client_socket.close()
            except:
                pass
            self.connection_count -= 1
    
    def start(self):
        """Start the proxy server"""
        self.running = True
        
        # Start ngrok tunnel if enabled
        tunnel_url = self.ngrok_manager.start_tunnel()
        
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.config['bind_address'], self.config['port']))
            server_socket.listen(self.config['max_connections'])
            
            print("=" * 50)
            print("Proxy server started on {}:{}".format(self.config['bind_address'], self.config['port']))
            print("Supported protocols: {}".format(', '.join([p.upper() for p, enabled in self.config['protocols'].items() if enabled])))
            print("Authentication: {}".format('Enabled' if self.config['username'] else 'Disabled'))
            print("Upstream proxy: {}".format('Enabled' if self.config['upstream_proxy']['enabled'] else 'Disabled'))
            if tunnel_url:
                print("Ngrok tunnel: {}".format(tunnel_url))
            print("=" * 50)
            
            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    
                    # Check connection limit
                    if self.connection_count >= self.config['max_connections']:
                        client_socket.close()
                        continue
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        self.logger.log_error("Accept error: {}".format(e))
                        
        except Exception as e:
            self.logger.log_error("Server error: {}".format(e))
        finally:
            server_socket.close()
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        self.ngrok_manager.stop_tunnel()
        print("Proxy server stopped.")

def main():
    """Main entry point"""
    proxy = ProxyServer()
    
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\nShutting down proxy server...")
        proxy.stop()

if __name__ == '__main__':
    main()