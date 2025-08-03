# GuardedIM
This is an instant messaging program akin to Signal, with group messaging and file transfer functionality, all secured using AES256-GCM and RSA. Python is used for the client-side and GUI while the server-side is written in Go. We use CockroachDB for the database.

## Environment Setup:

### Python:
1. Clone the repository.
2. Create a venv using the following conda command: `conda create --name ENV_NAME python`.
3. Activate the venv: `conda activate ENV_NAME`.
4. Go to GuardedIM directory: `cd GuardedIM`.
5. Install requirements: `pip install -r requirements.txt`.

### Go:
Compile the Go components:

``` go
go build -o gdim ./cmd/gdim/*.go
go build -o gdimd ./cmd/gdimd/*.go
```
The `gdim` is just a CLI tool that controls the `gdimd` which is the daemon part of the code. The `gdimd` will be constantly running in the background using `systemd` and `gdim` is the actual controlling tool. The `gdim` must read a config file called `guarded_im_config.json` in the same directory, an example file is given:

```
{
	"operation_mode": "server",
	"self_server_wireguard_ip": "10.0.12.1",
	"self_server_wireguard_private_key": "REDACTED",
	"self_server_wireguard_listen_port": 51820,
	"self_server_wireguard_mtu": 1500,
	"self_server_public_ip": "67.21.123.25",
	"database_host": "127.0.0.1",
	"database_port": 26257,
	"database_cert_directory": "/root/guardedIM/db_certs",
	"database_dbname": "defaultdb",
	"database_username": "group6"
}
```

And subcommands of the `gdim` rely on those information to be executed correctly.

## Running the program:
1. Launch Go `Server` and `Client` components.
2. Start server (generate keys on first run or if you want fresh keys): `python3 -m server.server --gen-keys`.
3. On successful server creation, in another terminal run the client chat GUI with: `python3 -m client.chat_gui`.


### Application Flow:

```
User A                          User B
| 1. Send Message               ^
V                               | 6. Receive Message
+---------+           +---------+
| ChatGUI |           | ChatGUI |
+---------+           +---------+
| 2. Input                      ^ 
V                               | 5. Display
+-------------------------------+
| AES Encrypt + Socket Send     |
+-------------------------------+
| 3. Encrypted Msg              ^
V                               |
+-------------------------------+
|         Server.py             ^
|    - Public Key Exchange      |
|    - AES Key Decrypt          |
|    - User Routing (To: field) |
+-------------------------------+
| 4. Forward Encrypted          ^
V          Msg                  |
+-------------------------------+
|     AES Decrypt + Display     |
+-------------------------------+
|                               ^
V                               |
---------------------------------
      Encrypted Message Flow
```
