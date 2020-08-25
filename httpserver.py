"""
- CS2911 - 001
- Fall 2020
- Lab 6
- Names:
  - Sean Lang
  - Sean Lang's Clone

A simple HTTP server
"""

import socket
import re
import threading
import os
from os import path, stat
import mimetypes
import datetime
from urllib.parse import urlparse, unquote, parse_qs


def main():
    """ Start the server """
    http_server_setup(8080)


def http_server_setup(port):
    """
    Start the HTTP server
    - Open the listening socket
    - Accept connections and spawn processes to handle requests

    :param port: listening port number
    """

    num_connections = 10
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_address = ('', port)
    server_socket.bind(listen_address)
    server_socket.listen(num_connections)
    try:
        while True:
            request_socket, request_address = server_socket.accept()
            print('connection from {0}:{1}'.format(*request_address))
            # Create a new thread, and set up the handle_request method and its argument (in a tuple)
            request_handler = threading.Thread(
                target=handle_request, args=(request_socket,))
            # Start the request handler thread.
            request_handler.start()
            # Just for information, display the running threads (including this main one)
            print('threads: ', threading.enumerate())
    # Set up so a Ctrl-C should terminate the server; this may have some problems on Windows
    except KeyboardInterrupt:
        print("HTTP server exiting . . .")
        print('threads: ', threading.enumerate())
        server_socket.close()


def handle_request(tcp_socket):
    """
    Handle a single HTTP request, running on a newly started thread.

    Closes request socket after sending response.

    Should include a response header indicating NO persistent connection

    :param tcp_socket: socket representing TCP connection from the HTTP client_socket
    :return: None
    """

    request_line = parse_http_request_line(read_line(tcp_socket))
    print('request line:', request_line)
    headers = read_headers(tcp_socket)
    print('headers: ', headers)
    file_path = resolve_url(request_line['url'])

    if file_path is None:
        # invalid path
        send_response(tcp_socket, 404)
        return

    if request_line['verb'] == 'GET':
        handle_get_request(tcp_socket, file_path)
    elif request_line['verb'] == 'POST':
        handle_post_request(tcp_socket, headers)

    else:
        # invalid verb
        send_response(tcp_socket, 400)


def handle_get_request(tcp_socket, file_path):
    """
    This method handles a GET request. We ignore query parameters, redirects,
    and content-type negoation entirely and just respond with the file at that
    path.
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :param file_path: The path to the file being requested.
    """

    try:
        # don't use path.join because it handles absolute path segments
        # incorrectly. this does not break on windows during testing.
        requested_file = open('./fixtures' + file_path, 'rb')
        file_content = requested_file.read()
        mime_type = get_mime_type(file_path)
        requested_file.close()
        send_response(tcp_socket, 200, mime_type, file_content)
    except FileNotFoundError:
        send_response(tcp_socket, 404)


def handle_post_request(tcp_socket, headers):
    """
    Handle a POST request. We ignore the URL entirely and just look for data or
    files being uploaded. Uploaded files are extracted from the request and
    written to the upload directory. Other data in the form is ignored entirely.
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    """

    if 'Content-Length' in headers:
        content = read_body(tcp_socket, headers['Content-Length'])
    elif headers.get('Transfer-Encoding', None) == 'chunked':
        content = read_chunks(tcp_socket)
    else:
        send_response(tcp_socket, 500, b'text/plain',
                      b'Didn\'t get a Content-Length or Transfer-Encoding: chunked.\n')
        return

    content_type = parse_header_value(headers.get('Content-Type', ''))
    if content_type['base_value'] == 'application/x-www-form-urlencoded':
        print('POST data: ', parse_qs(content))
        # just send a minimal response to say we got it
        send_response(tcp_socket, 200, b'text/plain', b'OK\n')
    elif content_type['base_value'] == 'multipart/form-data':
        handle_post_multipart_request(tcp_socket, content, content_type)
    else:
        send_response(tcp_socket, 500)


def handle_post_multipart_request(tcp_socket, content, content_type):
    """
    Handle a multipart form-data request and write any uploaded files to the
    upload directory. We do no validation on these files whatsoever, so anyone
    making requests to this server is free to fill up the disk with whatever
    they want.
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    """

    boundary = content_type['boundary']
    content = b'\r\n' + content  # add a leading CRLF to make splitting easy
    first_part = True
    for raw_part in content.split(b'\r\n--' + str.encode(boundary, 'ascii')):
        if first_part:
            # skip the first part because it's a preamble, usually blank
            first_part = False
            continue

        if raw_part == b'--\r\n':
            # according to rfc2046, the final boundary delimiter is followed
            # by 2 hyphens
            break

        if not raw_part.startswith(b'\r\n'):
            send_response(tcp_socket, 500, b'text/plain',
                          b'Boundry must be followed by CRLF')
            return
        else:
            raw_part = raw_part.replace(b'\r\n', b'', 1)

        part = parse_form_part(raw_part)
        if part != None:
            part_headers, body = part
            disposition = part_headers.get('Content-Disposition', {})
            filename = disposition.get('filename', None)
            if filename != None:
                print('writing file: ', 'upload/' + filename)
                write_message_to_file(body, 'upload/' + filename)

    send_response(tcp_socket, 200, b'text/plain', b'OK\n')


def parse_form_part(part):
    """
    Parse a part of a multipart form already split by boundries. Pull out the
    headers, especially the Content-Disposition, and give back the headers and
    parsed body.
    :author: Sean Lang
    :return: A tuple of the headers (dictionary) and parsed body (bytes object).
    :rtype: tuple
    """

    headers = {}
    raw_headers, part = part.split(b'\r\n\r\n', 1)
    for raw_header in raw_headers.split(b'\r\n'):
        key, value = parse_header(raw_header)
        if key == 'Content-Disposition':
            value = parse_header_value(value)
        headers[key] = value

    return (headers, part)


def resolve_url(url_path):
    """
    Given a url path, turn it into a file path to check. Right now we just
    handle percent encoding, strip out any GET parameters (ignore them) and add
    a default directory index of index.html
    :author: Sean Lang
    :param url_path: The raw URL parsed from the request line
    :returns: A processed file path, with segments like '..' or '.' removed.
    :rtype: string

    >>> resolve_url('/abc?var=45')
    '/abc'
    >>> resolve_url('/abc/../')
    '/index.html'
    >>> resolve_url('//')
    '//index.html'
    >>> resolve_url('/')
    '/index.html'
    >>> resolve_url('/abc/../../def.html') is None
    True
    >>> resolve_url('/my%20index.html')
    '/my index.html'
    """

    file_path = unquote(urlparse('http://localhost' + url_path).path)

    # posixpath.normpath allows for // at the beginning of the url, strips
    # trailing slashes, and replaces an empty path with '.', so we can't use
    # that. urljoin also has problems with not handling '..' correctly.
    segments = file_path.split('/')
    if segments[-1] == '':
        # add default directory index name
        segments[-1] = 'index.html'
    segments = [segment + '/' for segment in segments[:-1]] + [segments[-1]]
    resolved = []

    # resolve '..' and '.' segments in the path. curl & most browsers will
    # actually refuse to send us URLs this bad, so use GET from the lwp-request
    # package to test it out on the running server
    for segment in segments:
        if segment in ('../', '..'):
            if resolved[1:]:
                resolved.pop()
            else:
                # trying to break out of http root
                return None
        elif segment != './' and segment != '.':
            resolved.append(segment)
    file_path = ''.join(resolved)

    return file_path


def send_response(tcp_socket, *args):
    """
    A simple wrapper around make_response & sendall to send a response. This is
    hard to test with doctests (it would require a mock tcp_socket), so we keep
    it out of the real make_response().
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :param *args: All the args to pass to make_response.
    """
    tcp_socket.sendall(make_response(*args))


def make_response(status_code, mime_type=b'text/html', body=b'', headers={}):
    """
    Make a full HTTP GET response.
    :author: Sean Lang
    :param status_code: The status code to be sent in the response as an integer
    :param mime_type: The mime type to be used in the Content-Type header.
    Defaults to b'text/html'
    :param body: The body of the response. Defaults to an empty bytes object but
    will be filled in with an error page if a status code other than 200 is
    passed.
    :return: The formatted response body.
    :rtype: bytes

    >>> make_response(100)
    b'HTTP/1.1 100 Continue\\r\\n\\r\\n'
    """

    status_line = make_http_status_line(status_code)

    if status_code < 200:
        # 1xx status codes don't need headers or bodies
        return status_line + b'\r\n\r\n'

    if (status_code < 200 or status_code >= 400) and body == b'':
        body = make_error_page(status_code)

    if headers.get(b'Date', None) is None:
        timestamp = datetime.datetime.utcnow().strftime(
            '%a, %d %b %Y %H:%M:%S GMT')
        headers[b'Date'] = timestamp
    headers[b'Server'] = b'Lab 7 Test Server'
    headers[b'Connection'] = b'close'
    headers[b'Content-Length'] = len(body)
    headers[b'Content-Type'] = mime_type

    response_lines = [status_line]
    for key, value in headers.items():
        response_lines.append(make_http_header(key, value))

    return b'\r\n'.join(response_lines) + b'\r\n\r\n' + body


"""
Taken from https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html and
https://tools.ietf.org/id/draft-nottingham-thanks-larry-00.html
"""
status_code_map = {
    100: b'Continue',
    101: b'Switching Protocols',
    200: b'OK',
    201: b'Created',
    202: b'Accepted',
    203: b'Non-Authoritative Information',
    204: b'No Content',
    205: b'Reset Content',
    206: b'Partial Content',
    300: b'Multiple Choices',
    301: b'Moved Permanently',
    302: b'Found',
    303: b'See Other',
    304: b'Not Modified',
    305: b'Use Proxy',
    307: b'Temporary Redirect',
    400: b'Bad Request',
    401: b'Unauthorized',
    402: b'Payment Required',
    403: b'Forbidden',
    404: b'Not Found',
    405: b'Method Not Allowed',
    406: b'Not Acceptable',
    407: b'Proxy Authentication Required',
    408: b'Request Time-out',
    409: b'Conflict',
    410: b'Gone',
    411: b'Length Required',
    412: b'Precondition Failed',
    413: b'Request Entity Too Large',
    414: b'Request-URI Too Large',
    415: b'Unsupported Media Type',
    416: b'Requested range not satisfiable',
    417: b'Expectation Failed',
    418: b'I\'m a teapot',
    500: b'Internal Server Error',
    501: b'Not Implemented',
    502: b'Bad Gateway',
    503: b'Service Unavailable',
    504: b'Gateway Time-out',
    505: b'HTTP Version not supported',
}


def make_http_status_line(status_code, version=b'HTTP/1.1'):
    """
    Create a status line. The status phrase is omitted from the parameters
    because it is derived from the status_code. See https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html for a list of
    status_code to status phrase pairs.
    :author: Donal Moloney
    :param status_code: The code indicating the result of the request.
    :param version: The version of HTTP being used, defaults to 'HTTP/1.1'
    :return: The response status line, without a trailing CRLF.
    :rtype: bytes

    >>> make_http_status_line(200)
    b'HTTP/1.1 200 OK'
    """

    return b' '.join((
        version,
        str(status_code).encode('ascii'),
        status_code_map[status_code]
    ))


ERROR_PAGE_FORMAT = b"""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta charset="ascii">
        <meta http-equiv="X-UA-Compatible" content="IE=edge, chrome=1">
        <meta name="viewport" content="width=device-width">
        <title>%i Error</title>
    </head>
    <body>
        <h1>Error</h1>
        <p>%b</p>
    </body>
</html>
"""


def make_error_page(status_code):
    """
    Makes an error page based on the status code.
    :author: Donal Moloney
    :param status_code: The status code of the response to be returned, used for
    formatting the error page.
    :return: A formatted error page.
    :rtype: bytes
    """

    return ERROR_PAGE_FORMAT % (status_code, status_code_map[status_code])


def read_chunks(tcp_socket):
    """
    Read the body of the response as chunks and concatenate them together
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :return: The body of the response.
    :rtype: bytes
    """

    content = b''
    chunk = read_chunk(tcp_socket)
    while len(chunk) != 0:
        content += chunk
        chunk = read_chunk(tcp_socket)
    return content


def read_chunk(tcp_socket):
    """
    Read a single chunk, parsing the length of the chunk, reading the specified
    number of bytes from the socket, and consuming the trailing CRLF.
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :return: The content of the chunk, without the trailing CRLF or leading size
    line.
    :rtype: bytes
    """

    size = int(bytes.decode(read_line(tcp_socket), 'ascii'), 16)
    content = read_body(tcp_socket, size)

    # read the line ending and make sure it's correct
    if read_body(tcp_socket, 2) != b'\r\n':
        raise Exception('Didn\'t get a correct line ending for chunk')
    return content


def read_body(tcp_socket, length):
    """
    This method reads the body of the HTTP request, trying to read in as large
    of segments as possible to reduce the number of function calls.
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :param length: The number of bytes to read.
    :return: The bytes read off of the socket, concat'd together.
    :rtype bytes
    """

    content = tcp_socket.recv(length)
    while len(content) < length:
        content += tcp_socket.recv(length - len(content))
    return content


def read_line(tcp_socket):
    """
    Read a single line and return it without the CRLF. Return a zero length line
    if it's blank (indicating the end of the headers).
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :return: A single line from the response, without the trailing CRLF.
    :rtype: bytes
    """

    line = b''
    char = tcp_socket.recv(1)
    while not (char == b'\n' and line[-1:] == b'\r'):
        line += char
        char = tcp_socket.recv(1)
    return line[:-1]


def read_headers(tcp_socket):
    """
    Use read_line to read all the headers from the tcp_socket. Stop when we hit
    the end of the headers.
    :author: Sean Lang
    :param tcp_socket: The socket to read from.
    :return: All the headers we parsed, as key, value pairs.
    :rtype: dict
    """

    headers = {}
    line = read_line(tcp_socket)
    while len(line) != 0:
        key, value = parse_header(line)
        headers[key] = value
        line = read_line(tcp_socket)
    return headers


HEADER_RE = r'([^:]+): (.+)'


def parse_header(line):
    """
    Parse a header and return a tuple with the (key,value) pair. Also, handle
    basic type conversion.
    :author: Sean Lang
    :param line: A line single of the header, without a trailing CRLF
    :return: The parsed header key and value.
    :rtype: tuple

    >>> parse_header(b'Content-Length: 10')
    ('Content-Length', 10)
    >>> parse_header(b'Content-Type: text/html')
    ('Content-Type', 'text/html')
    """

    result = re.match(HEADER_RE, line.decode('ascii')).group(1, 2)
    if result[0] == 'Content-Length':
        # this always represents an integer
        result = (result[0], int(result[1]))
    return result


def parse_header_value(value):
    """
    Parses a set of key, value pairs out of a semicolon delimited header value.
    Useful for handling POST requests.
    :author: Sean Lang
    :param value: The value to parse.
    :return: The parsed value as a dictionary of key, value pairs, with the part
    that has no key being called base_value.
    :rtype: dict

    >>> parse_header_value('multipart/form-data; boundary=-------8b61c4369832')
    {'base_value': 'multipart/form-data', 'boundary': '-------8b61c4369832'}
    >>> parse_header_value('form-data; name="fileToUpload"; filename="test.md"')
    {'base_value': 'form-data', 'name': 'fileToUpload', 'filename': 'test.md'}
    >>> parse_header_value('max-age=0')
    {'max-age': '0'}
    >>> parse_header_value('form-data; name="data"; filename="style.css"')
    {'base_value': 'form-data', 'name': 'data', 'filename': 'style.css'}
    """

    result = {}
    for part in value.split('; '):
        kv_pair = part.split('=', 1)
        if len(kv_pair) == 1:
            result['base_value'] = kv_pair[0]
        else:
            result[kv_pair[0]] = kv_pair[1]

    for key, value in result.items():
        start = value[0]
        end = value[-1]
        if (start == '"' and end == '"') or (start == '\'' and end == '\''):
            result[key] = value[1:-1]

    return result


REQUEST_LINE_RE = r'(.+) (.+) (HTTP/[0-9\.]+)'


def parse_http_request_line(line):
    """
    Parse the HTTP request line and return a dict with the info it contains.
    :author: Sean Lang
    :param line: The request line to parse, without a trailing CRLF.
    :return: The parts of the HTTP request line.
    :rtype dict

    >>> parse_http_request_line(b'GET /test.txt HTTP/1.1')
    {'verb': 'GET', 'url': '/test.txt', 'version': 'HTTP/1.1'}
    """

    match = re.match(REQUEST_LINE_RE, line.decode('ascii'))
    return {
        'verb': match.group(1),
        'url': match.group(2),
        'version': match.group(3),
    }


def make_http_header(key, value):
    """
    Make an HTTP header.
    :author: Sean Lang
    :param key: Name of the header as a bytes object
    :param value: Value of the header as a string, bytes object, or int.
    :return: HTTP header for given key/value, without trailing CRLF.
    :rtype: bytes

    >>> make_http_header(b'Content-Length', b'10')
    b'Content-Length: 10'
    >>> make_http_header(b'Content-Length', '10')
    b'Content-Length: 10'
    >>> make_http_header(b'Content-Length', 10)
    b'Content-Length: 10'
    """

    if type(value) == int:
        value = str(value)
    if type(value) == str:
        value = value.encode('ascii')
    return key + b': ' + value


def write_message_to_file(message, file_path):
    """
    Write the message out to a file, specified by the given file_path.
    :author: Sean Lang
    :param message: The contents to write to the file as a bytes object.
    :param file_path: The file path to write to.
    """

    output_file = open(file_path, 'wb')
    output_file.write(message)
    output_file.close()


# ** Do not modify code below this line.  You should add additional helper methods above this line.

# Utility functions
# You may use these functions to simplify your code.


def get_mime_type(file_path):
    """
    Try to guess the MIME type of a file (resource), given its path (primarily its file extension)
    :param file_path: string containing path to (resource) file, such as './abc.html'
    :return: If successful in guessing the MIME type, a string representing the content type, such as 'text/html'
             Otherwise, None
    :rtype: int or None

    >>> get_mime_type('index.html')
    'text/html'
    >>> get_mime_type('index.js')
    'application/javascript'
    """

    return mimetypes.guess_type(file_path)[0]


def get_file_size(file_path):
    """
    Try to get the size of a file (resource) as number of bytes, given its path

    :param file_path: string containing path to (resource) file, such as './abc.html'
    :return: If file_path designates a normal file, an integer value representing the the file size in bytes
             Otherwise (no such file, or path is not a file), None
    :rtype: int or None
    """

    # Initially, assume file does not exist
    file_size = None
    if os.path.isfile(file_path):
        file_size = os.stat(file_path).st_size
    return file_size


if __name__ == "__main__":
    # execute only if run as a script
    main()

# Replace this line with your comments on the lab
