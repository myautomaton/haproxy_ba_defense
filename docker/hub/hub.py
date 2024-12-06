import http.server
import socketserver
import os
import sys
import datetime
import json
import base64
import yaml
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict

# print('source code for "http.server":', http.server.__file__)


class MyServer(http.server.SimpleHTTPRequestHandler):

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"patronum\"')
        self.send_header("Content-type", "application/json")
        self.end_headers()
    
    def do_RESPONSE401(self, message):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"patronum\"')
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response = {
            'success': False,
            'error': message
        }
        self.wfile.write(bytes(json.dumps(response), 'utf-8'))

    def do_RESPONSE404(self, message):
        self.send_response(404)
        self.send_header('WWW-Authenticate', 'Basic realm=\"patronum\"')
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response = {
            'success': False,
            'message': "File not found: "+message
        }
        self.wfile.write(bytes(json.dumps(response), 'utf-8'))

    def do_RESPONSE200(self, message):
        self.send_response(200)
        self.send_header('WWW-Authenticate', 'Basic realm=\"patronum\"')
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response = {
            'success': True,
            'error': message
        }
        self.wfile.write(bytes(json.dumps(response), 'utf-8'))

    def do_GET(self):
        url = self.path.split("/")

        #BASIC AUTHORIZATION
        if self.headers.get('Authorization') == None:
            self.do_RESPONSE401('No auth header received')
            return ""
        elif self.headers.get('Authorization') != "Basic "+base64.b64encode(bytes('%s:%s' % (self.username , self.password), 'utf-8')).decode('ascii'):
            self.do_RESPONSE401('Wrong username or password')
            return ""
        else:
            pass

        #SAVE URL TO FILE
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        # Function to reconstruct nested dictionary
        def build_nested_dict(params):
            data = defaultdict(dict)

            for key, value in params.items():
                parts = key.split('.')
                sub_dict = data
                for part in parts[:-1]:
                    # Handle array indices like headers[0].host
                    if '[' in part and ']' in part:
                        index = int(part[part.index('[')+1 : part.index(']')])
                        part = part[:part.index('[')]
                        sub_dict = sub_dict.setdefault(part, [])
                        while len(sub_dict) <= index:
                            sub_dict.append({})
                        sub_dict = sub_dict[index]
                    else:
                        sub_dict = sub_dict.setdefault(part, {})
                
                # Assign the final value, unquoted and single-value list handled
                sub_dict[parts[-1]] = unquote(value[0])
            return data
        # Reconstruct the nested dictionary
        yaml_data = build_nested_dict(query_params)

        # Save the parsed data to a YAML file
        with open("/tmp/output.yaml", "w") as yaml_file:
            yaml.dump(yaml_data, yaml_file, default_flow_style=False)

        #print (self.headers)
        # CHECK IF BASH SCRIPT EXISTS AND EXECUTE
        if (url[1] == "run"):
            # run bash script if available
            if (os.path.isfile("./apis/"+url[2]+".sh")):
                print ("--------")
                print (datetime.datetime.now())
                print ("run script ./apis/"+url[2]+".sh")
                print ("-")
                print (os.system("./apis/"+url[2]+".sh"))
                self.do_RESPONSE200("running script: ./apis/"+url[2]+".sh")
                return ""
            if (os.path.isfile("./apis/"+url[2]+".py")):
                print ("--------")
                print (datetime.datetime.now())
                print ("run script ./apis/"+url[2]+".py")
                print ("-")
                print (os.system("python3 ./apis/"+url[2]+".py"))
                self.do_RESPONSE200("running script: ./apis/"+url[2]+".py")
                return ""

        elif self.path == '/':
            self.path = './index.html'

            try:
                f = open(self.path, 'rb')
            except OSError:
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return None

            ctype = self.guess_type(self.path)
            fs = os.fstat(f.fileno())

            self.send_response(200)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()

            try:
                self.copyfile(f, self.wfile)
            finally:
                f.close()
            return ""

        else:
            # run normal code
            self.do_RESPONSE404(self.path)
            return ""


# --- main ---
handler_object = MyServer

PORT = 8080

print(f'Starting: http://127.0.0.1:{PORT}')

try:
    # solution for `OSError: [Errno 98] Address already in use`
    socketserver.TCPServer.allow_reuse_address = True
    handler_object.username = "demo"
    handler_object.password = "demo"
    my_server = socketserver.TCPServer(("", PORT), handler_object)
    my_server.serve_forever()
except KeyboardInterrupt:
    # solution for `OSError: [Errno 98] Address already in use - when stoped by Ctr+C
    print('Stoped by "Ctrl+C"')
finally:
    # solution for `OSError: [Errno 98] Address already in use
    print('Closing')
    my_server.server_close()
