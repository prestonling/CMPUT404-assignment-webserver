#  coding: utf-8 
import socketserver
import os

# Copyright 2013 Abram Hindle, Eddie Antonio Santos
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Furthermore it is derived from the Python documentation examples thus
# some of the code is Copyright © 2001-2013 Python Software
# Foundation; All Rights Reserved
#
# http://docs.python.org/2/library/socketserver.html
#
# run: python freetests.py

# try: curl -v -X GET http://127.0.0.1:8080/

REQUEST_TYPE_KEY = "Request-type"
PATH_KEY = "Path"
HTTP_VERSION_KEY = "Http-version"

class MyWebServer(socketserver.BaseRequestHandler):
    
    def handle(self):
        self.data = self.request.recv(1024).strip()
        print ("Got a request of: %s\n" % self.data)
        print(os.getcwd())
        http_request_info = get_http_info(self.data.decode())

        
        request_type = http_request_info[REQUEST_TYPE_KEY]
        print("request_type:")
        print(request_type) 
        if request_type == "GET":
            
            filepath = "www" + http_request_info[PATH_KEY]
            filepath, redirection_done = get_updated_filepath(filepath)
            is_malicious_request = check_malicious_path(filepath)
            file_exists = os.path.exists(filepath)
            filename, extension = os.path.splitext(http_request_info[PATH_KEY])
            # print("filename: ", filename)
            # print("extension: ", extension)

            if is_malicious_request:
                header = 'HTTP/1.1 404 Resource not found\r\n'
                self.request.sendall(header.encode())
            elif file_exists and not redirection_done:
                response = ""
                response += get_response_statusline(extension)
                file = open(filepath, "r")
                response += file.read()
                self.request.sendall(response.encode())
            
            elif file_exists and redirection_done:
                header = 'HTTP/1.1 301 Moved Permanently\r\n'
                header += "Location:" + http_request_info[PATH_KEY] + "/"
                self.request.sendall(header.encode())

            else:
                header = 'HTTP/1.1 404 Resource not found\r\n'
                self.request.sendall(header.encode())

        else:
            header = 'HTTP/1.1 405 Method Not Allowed\r\n'
            self.request.sendall(header.encode())
            # print("got not a GET request")

#returns True if file is part of response
#return False if file is not part of response
def get_response_statusline(extension):
    header = ""
    if extension == "":
        header = 'HTTP/1.1 200 OK\r\n'
        header += "Content-Type: text/html\r\n\r\n"

    elif extension == ".html":
        header = 'HTTP/1.1 200 OK\r\n'
        header += "Content-Type: text/html\r\n\r\n"

    elif extension == ".css":
        header = 'HTTP/1.1 200 OK\r\n'
        header += "Content-Type: text/css\r\n\r\n"

    return header

def get_updated_filepath(filepath):
    redirection_done = False
    if os.path.isdir(filepath):

        if filepath[-1] != "/":
            filepath += "/index.html"
            redirection_done = True

        else:
            filepath += "index.html"
    return filepath, redirection_done


def get_http_info(http_request):
    result = {}
    request_split_result = http_request.split("\r\n\r\n")
    has_body = False

    if len(request_split_result) > 1:
        has_body = True
        
    header = request_split_result[0]
    header_lines = header.split("\r")
    request_line = header_lines[0].split()
    
    result[REQUEST_TYPE_KEY] = request_line[0]
    result[PATH_KEY] = request_line[1]
    result[HTTP_VERSION_KEY] = request_line[2]

    for i in range(1, len(header_lines)):
        key, value = header_lines[i].split(": ")[0], header_lines[i].split(": ")[1]
        result[key] = value
        

    if has_body:
        result["message_body"] = request_line[1]
    
    return result

def check_malicious_path(filepath):
    count = 0 
    for resource in filepath.split("/"):
        if resource == "..":
            count -= 1
            if count < 0:
                return True
        elif resource == ".":
            continue
        else:
            count += 1
    return False 

if __name__ == "__main__":
    HOST, PORT = "localhost", 8080

    socketserver.TCPServer.allow_reuse_address = True
    # Create the server, binding to localhost on port 8080
    server = socketserver.TCPServer((HOST, PORT), MyWebServer)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
