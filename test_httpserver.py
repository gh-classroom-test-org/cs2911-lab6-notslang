from httpserver import __doc__ as docstring, handle_request, get_mime_type, get_file_size
from unittest.mock import Mock
import socket
import re

def test_get_mime_type():
    """
    Test provided utility function get_mime_type()
    """
    assert get_mime_type('index.html') == 'text/html'
    assert get_mime_type('index.js') == 'application/javascript'

def test_get_file_size():
    """
    Test provided utility function get_file_size(). Also makes sure that fixtures are still there.
    """
    assert get_file_size('fixtures/e-sebern2.gif') == 1774
    assert get_file_size('fixtures/sebern1.jpg') == 37207


def test_names_in_docstring():
    """
    Put your names and section number in the docstring at the top of the lab.
    """
    assert '<your section number>' not in docstring
    assert '<your name>' not in docstring
    assert '<your partner\'s name>' not in docstring

# global vars for storing I/O of mock socket
mock_recv_content = b''
mock_send_content = b''

def mock_recv(bufsize, flags=None):
    global mock_recv_content
    if len(mock_recv_content) <= bufsize:
        content = mock_recv_content
        mock_recv_content = b''
        return content
    else:
        content = mock_recv_content[:bufsize]
        mock_recv_content = mock_recv_content[bufsize:]
        return content

def mock_send(data, flags=None):
    global mock_send_content
    mock_send_content += data
    return len(data)

def mock_sendall(data, flags=None):
    global mock_send_content
    mock_send_content += data
    return None

def get_fixture_content(path):
    file = open(path, mode='rb')
    page_content = file.read()
    file.close()
    return page_content

def get_mock_socket():
    mock_socket = Mock(spec=socket.socket)
    mock_socket.recv.side_effect = mock_recv
    mock_socket.send.side_effect = mock_send
    mock_socket.sendall.side_effect = mock_sendall
    return mock_socket

DATE_HEADER_RE = re.compile('[A-Z][a-z]+, [0-9]+ [A-Z][a-z]+ [0-9]+ [0-9]+:[0-9]+:[0-9]+ GMT')
HEADER_RE = r'([^:]+): (.+)'


def extract_headers(content):
    headers = {}
    line, content = content.split(b'\r\n', 1)
    while len(line) != 0:
        key, value = re.match(HEADER_RE, line.decode('ascii')).group(1, 2)
        headers[key] = value
        line, content = content.split(b'\r\n', 1)
    return (headers, content)


def check_response(sent_content, page_content, content_type='text/html'):
    # check statusline
    status_line, sent_content = sent_content.split(b'\r\n', 1)
    assert status_line == b'HTTP/1.1 200 OK'

    headers, sent_content = extract_headers(sent_content)

    assert 'Connection' in headers
    assert headers['Connection'] == 'close'
    assert 'Content-Length' in headers
    assert headers['Content-Length'] == str(len(page_content))
    assert 'Content-Type' in headers
    assert headers['Content-Type'] == content_type
    assert 'Date' in headers
    assert re.match(DATE_HEADER_RE, headers['Date']) is not None
    assert sent_content == page_content

def test_get_index_file_status_line_ok():
    """
    Checks the status line when making a successful request to the index file.
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    assert mock_send_content.startswith(b'HTTP/1.1 200 OK\r\n')

def test_get_index_file_status_line_missing():
    """
    Checks the status line when making an unsuccessful request.
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /bad-path-that-should-not-exist HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    assert mock_send_content.startswith(b'HTTP/1.1 404 Not Found\r\n')

def test_get_index_file_connection_header():
    """
    Checks the Connection header
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    assert b'Connection: close\r\n' in mock_send_content

def test_get_index_file_content_length_header():
    """
    Checks the existance of the Content-Length header
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    assert b'Content-Length: ' in mock_send_content

def test_get_index_file_content_type_header():
    """
    Checks the Content-Type header
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    assert b'Content-Type: text/html\r\n' in mock_send_content

def test_get_index_file_date_header():
    """
    Checks the existance of the Date header
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    assert b'Date: ' in mock_send_content

def test_get_index_file_response_content():
    """
    Checks that the content of the page is returned
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)
    page_content = get_fixture_content('fixtures/index.html')
    assert mock_send_content.endswith(page_content)

def test_get_root_file():
    """
    Check that the root URL gets resolved to /index.html and parse the full response
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET / HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)

    page_content = get_fixture_content('fixtures/index.html')
    check_response(mock_send_content, page_content)

def test_get_index_file():
    """
    Check that /index.html works and parse the full response
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /index.html HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)

    page_content = get_fixture_content('fixtures/index.html')
    check_response(mock_send_content, page_content)

def test_get_css_file():
    """
    Check that /style.css works and parse the full response
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /style.css HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)

    page_content = get_fixture_content('fixtures/style.css')
    check_response(mock_send_content, page_content, 'text/css')

def test_get_gif_file():
    """
    Check that /e-sebern2.gif works and parse the full response
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /e-sebern2.gif HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)

    page_content = get_fixture_content('fixtures/e-sebern2.gif')
    check_response(mock_send_content, page_content, 'image/gif')

def test_get_jpg_file():
    """
    Check that /sebern1.jpg works and parse the full response
    """
    global mock_recv_content
    global mock_send_content
    mock_socket = get_mock_socket()
    mock_recv_content = b'GET /sebern1.jpg HTTP/1.1\r\n\r\n'
    mock_send_content = b''
    handle_request(mock_socket)

    page_content = get_fixture_content('fixtures/sebern1.jpg')
    check_response(mock_send_content, page_content, 'image/jpeg')
