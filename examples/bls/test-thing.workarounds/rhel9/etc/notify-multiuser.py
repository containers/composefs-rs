#!/usr/bin/python3

"""Notify that the system has reached multi-user.target."""

import os
import socket
from pathlib import Path

credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
notify_socket = (credentials / "vmm.notify_socket").read_text()
af, cid, port = notify_socket.split(":")
assert af == "vsock"
sock = socket.socket(socket.AF_VSOCK, socket.SOCK_SEQPACKET)
sock.connect((int(cid), int(port)))
sock.sendmsg([b"X_SYSTEMD_UNIT_ACTIVE=multi-user.target\n"])
