import socket
import threading
import paramiko
import sys
import logging
import time

# --- Configuration ---
# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# The local IP and port the proxy will listen on
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 2222

# The remote (upstream) SSH server details
UPSTREAM_HOST = '45.77.102.104' # CHANGE THIS
UPSTREAM_PORT = 9022

# The static credentials to connect to the upstream server
# The username for the upstream connection
UPSTREAM_USER = 'nickcao' # CHANGE THIS
# The path to the private key for authenticating to the upstream server
UPSTREAM_KEY_FILE = '/home/nickcao/.ssh/id_ed25519' # CHANGE THIS to the path of your static private key

# Generate a temporary host key for our proxy server.
# In a real scenario, you might want to use a static key.
HOST_KEY = paramiko.RSAKey.generate(2048)

# --- MITM Server Implementation ---

class MitmServer(paramiko.ServerInterface):
    """
    A custom Paramiko ServerInterface to handle client authentication.
    This implementation accepts ANY authentication attempt and handles
    both shell and exec requests.
    """
    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.event = threading.Event()
        self.exec_command = None # Will store the command for exec requests

    def check_channel_request(self, kind, chanid):
        # Allow any channel request (e.g., 'session')
        logging.info(f"Client {self.client_addr}: Allowed channel request of kind '{kind}'")
        return paramiko.OPEN_SUCCEEDED

    def check_auth_none(self, username):
        # Accept authentication via 'none' method
        logging.info(f"Client {self.client_addr}: Authenticating with username '{username}' (auth method: none)")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        # Accept any password authentication
        logging.info(f"Client {self.client_addr}: Authenticating with username '{username}', password '{password}' (auth method: password)")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        # Accept any public key authentication
        logging.info(f"Client {self.client_addr}: Authenticating with username '{username}' (auth method: publickey)")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        # Inform the client that all common auth methods are allowed
        return 'password,publickey,none'

    def check_channel_shell_request(self, channel):
        # A shell has been requested. We signal the main handler thread.
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # A PTY has been requested for the shell.
        return True

    def check_channel_exec_request(self, channel, command):
        # A command execution has been requested.
        self.exec_command = command.decode('utf-8')
        logging.info(f"Client {self.client_addr}: Received exec request for command: '{self.exec_command}'")
        self.event.set()
        return True


def forward_data(source, dest):
    """
    Forwards data from a source channel to a destination channel.
    """
    try:
        while True:
            data = source.recv(1024)
            if len(data) == 0:
                break
            dest.sendall(data)
    except (OSError, EOFError):
        pass # Channel is closed
    finally:
        # Gracefully close both ends if one side disconnects.
        source.close()
        dest.close()

def handle_connection(client_socket, client_addr):
    """
    Handles a single client connection from start to finish.
    """
    logging.info(f"New connection from: {client_addr}")
    transport = None
    try:
        # 1. Set up the transport for the incoming client connection
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)

        # 2. Start the SSH server and handle client-side authentication
        server = MitmServer(client_addr)
        transport.start_server(server=server)
        logging.info(f"Client {client_addr}: SSH handshake complete. Waiting for auth...")

        # 3. Wait for the client to request a channel (e.g., a shell or exec)
        client_channel = transport.accept(20)
        if client_channel is None:
            logging.error(f"Client {client_addr}: Timed out waiting for channel request.")
            return

        # Wait for the shell or exec request event from the MitmServer
        server.event.wait(10)
        if not server.event.is_set():
            logging.error(f"Client {client_addr}: Client never requested a shell or exec.")
            return

        logging.info(f"Client {client_addr}: Channel opened. Connecting to upstream server...")

        # 4. Connect to the upstream server
        upstream_client = paramiko.SSHClient()
        upstream_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            private_key = None
            key_types_to_try = [
                (paramiko.Ed25519Key, "Ed25519"),
                (paramiko.RSAKey, "RSA"),
                (paramiko.ECDSAKey, "ECDSA"),
                (paramiko.DSSKey, "DSS")
            ]
            for key_class, key_name in key_types_to_try:
                try:
                    private_key = key_class.from_private_key_file(UPSTREAM_KEY_FILE)
                    logging.info(f"Client {client_addr}: Loaded upstream private key as {key_name} type.")
                    break
                except (paramiko.ssh_exception.SSHException, FileNotFoundError):
                    continue
            
            if private_key is None:
                raise paramiko.ssh_exception.SSHException(f"Could not load private key from {UPSTREAM_KEY_FILE}.")

            upstream_client.connect(hostname=UPSTREAM_HOST, port=UPSTREAM_PORT, username=UPSTREAM_USER, pkey=private_key, timeout=10)
            logging.info(f"Client {client_addr}: Successfully connected to upstream {UPSTREAM_HOST}")
        except Exception as e:
            logging.error(f"Client {client_addr}: Failed to connect to upstream server {UPSTREAM_HOST}. Error: {e}")
            if client_channel.active:
                client_channel.send(f"Failed to connect to upstream server: {e}\r\n".encode())
            return

        # Handle shell vs exec
        if server.exec_command:
            # 5a. Handle command execution
            logging.info(f"Client {client_addr}: Executing command on upstream: '{server.exec_command}'")
            stdin, stdout, stderr = upstream_client.exec_command(server.exec_command)
            
            # Forward stdout and stderr in separate threads
            threading.Thread(target=forward_data, args=(stdout.channel, client_channel.makefile()), daemon=True).start()
            threading.Thread(target=forward_data, args=(stderr.channel, client_channel.makefile_stderr()), daemon=True).start()

            # Wait for the command to finish and send the exit status
            exit_status = stdout.channel.recv_exit_status()
            client_channel.send_exit_status(exit_status)
            logging.info(f"Client {client_addr}: Command finished with exit status {exit_status}.")
            client_channel.close()

        else:
            # 5b. Handle interactive shell
            logging.info(f"Client {client_addr}: Invoking interactive shell on upstream.")
            upstream_channel = upstream_client.invoke_shell()
            logging.info(f"Client {client_addr}: Bridging connections. Proxy is now transparent.")
            
            # Thread to forward data from client -> upstream
            threading.Thread(target=forward_data, args=(client_channel, upstream_channel), daemon=True).start()
            # Thread to forward data from upstream -> client
            threading.Thread(target=forward_data, args=(upstream_channel, client_channel), daemon=True).start()
            
            # --- MODIFIED SECTION ---
            # Keep the connection handler alive until the client's channel is closed.
            # This prevents the connection from being torn down prematurely.
            while client_channel.active and transport.is_active():
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    break
            logging.info(f"Client {client_addr}: Interactive session has ended.")
            # --- END MODIFIED SECTION ---

    except Exception as e:
        logging.error(f"Exception in connection handler for {client_addr}: {e}")
    finally:
        if transport and transport.is_active():
            transport.close()
        client_socket.close()
        logging.info(f"Connection closed for {client_addr}")


def main():
    """
    Main function to start the listening server.
    """
    logging.info(f"Starting SSH MITM proxy on {LISTEN_HOST}:{LISTEN_PORT}...")
    logging.info(f"Upstream server: {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    logging.info(f"Upstream auth: user='{UPSTREAM_USER}', key_file='{UPSTREAM_KEY_FILE}'")

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(100)
    except Exception as e:
        logging.error(f"Failed to bind to port {LISTEN_PORT}. Error: {e}")
        sys.exit(1)

    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            # Handle each connection in a new thread
            thread = threading.Thread(target=handle_connection, args=(client_socket, client_addr))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            logging.info("Shutting down proxy server.")
            break

    server_socket.close()

if __name__ == '__main__':
    main()

