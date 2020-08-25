# CS2911 Lab 6: HTTP Server

This lab is due at the beginning of the following lab's lab period. Please work in teams of two unless approved by the instructor. Please submit only one report per team.

When you have questions you can't resolve, consult the instructor as soon as possible, in person or by email.

## Introduction

The goal of this lab is to write a short Python program, to respond to HTTP requests and return web resources, acting as an HTTP server.

## Procedure

- Accept the assignment through GitHub Classrooms and clone the repository to your computer.
- Edit the header of `httpserver.py` to include your team members' names and usernames.
- Plan as a team and divide up the primary responsibility for parts of the program in an equitable way.
- Complete the `handle_request` method to parse a request and respond by returning the designated resource. You will want to add other helper methods, but do not change any other code provided in the template. Note that this method will be invoked on a separate thread for each request received. This means that there may be multiple copies of this method running simultaneously, if the web client opens more than one connection at a time (e.g., to download resources that are referenced in a main HTML file). For this reason, you should not rely on any global variables, but instead pass data as arguments to related functions. Each thread will have its own execution stack.
- If this base functionality turns out to be too easy, you may experiment with adding additional functions, but be sure the basic requirements are still met.

You may not use a prebuilt library like `Lib/BaseHTTPServer`; the point of this lab is for you to understand the low-level implementation of the HTTP protocol.

You should use the utility functions that are included near the end of the skeleton template file. Read the description for each function and ask the instructor if you have questions about them.

## Assignment details

- Your server is only expected to handle "file" resources, so that you can service a client request by returning the contents of a file associated with the resource identifier.

  - You must be able to serve at least the following resources. These are provided in the `./fixtures` directory of the repository.

    Relative URL   | File path
    -------------- | -----------
    / (default)    | ./fixtures/index.html
    /index.html    | ./fixtures/index.html
    /sebern1.jpg   | ./fixtures/sebern1.jpg
    /style.css     | ./fixtures/style.css
    /e-sebern2.gif | ./fixtures/e-sebern2.gif

  - Your server should look like https://seprof.sebern.com/ when you browse to http://localhost:8080

- You must parse the request Request-Line and all request header lines, storing the key/value pairs in a Python dictionary.

  - Unless you implement additional functionality, it is unlikely that you will need to make use of any of the request headers, but you should store and print them after the entire request is received, so you can verify that you are handling the request correctly.
  - You do not need to print the headers in the same order they were received. The order the dictionary iterates them is just fine.

- You must return an appropriate response Status-Line and header lines to the requesting client, regardless of what the user types in the URL. You should send a body with the message if the RFC specifies that there should be one for the status code(s) you use.
- Use a Python dictionary to store the response header lines, and then send them all at once at an appropriate time.
- The response header lines must include: (again, in the order that a dictionary iterates is fine)

  - A Date header (in proper RFC format) indicating the time that the request was satisfied.
  - A Connection header indicating that a non-persistent connection will be used.
  - A Content-Type header with an appropriate MIME type (you should use the provided function to get the MIME type).
  - A Content-Length header to specify the size of the resource being returned (if there is one to return).

    - You are not required to use chunked encoding for any file type.
    - Optionally, you may use chunked encoding for text/html resources. If you do so, you must include the appropriate Transfer-Encoding header instead of Content-Length, and format the resource data appropriately in the response.

## Hints and Notes

- To test your code, direct your browser to localhost:8080
- As in the HTTP client lab, you will have to both send and receive on the TCP connection to the HTTP client. On the receiving side, since we will only be handling GET requests with no entity bodies, there will likely be only one kind of data that needs to be processed: "Textual" data, organized as a sequence of ASCII characters followed by the CR/LF pair. Data in this category includes:

  - The HTTP Request-Line.
  - Request header lines.
  - "Blank" lines (e.g., to terminate a header). You should probably have a "read line" function from the HTTP client lab, which you can likely use here.

- Remember that when you read from the network stream with a function like recv, or from a file with a function like read, you can only control the maximum number of bytes that will be returned. You will always get at least one byte, unless there is no more data (in the case of a file or a socket that has been closed), but there is no way to predict absolutely in advance how many bytes will be available when you make the recv or read call.

  - At times, you may get fewer than the number of bytes needed (e.g., in a block of "binary byte" data). If this happens, you will have to make another recv call to get additional data. If you choose to send a chunked file, you may choose to send whatever recv gives you immediately, instead of calling it again. This might reduce the latency of your response.

- When serving resource data from a file, open the file in binary ('rb') mode to avoid problems with line-ending modification on Windows.
- Getting the proper HTTP "Date" value can be a little tricky. You can try something like this:

```python
timestamp = datetime.datetime.utcnow()
timestring = timestamp.strftime('%a, %d %b %Y %H:%M:%S GMT')
# Sun, 06 Nov 1994 08:49:37 GMT
```

## Excellent Credit

There is one point allocated for "excellent credit" activities beyond the requirements. A couple of things that would work well might be implementing persistent connections or implementing caching. You could also implement file uploads by allowing the POST action in addition to the GET action. Be sure to incorporate these cleanly into the request and response header dictionaries used in your design.

If you choose to implement the POST action, please ask, and I can help you set up a page that will allow your browser to generate a POST upload. HTML is beyond the scope of this class.

If you decide to implement a persistent connection, you can demonstrate that it is working by capturing the request in [Wireshark](https://www.wireshark.org/).

Getting the excellent credit point is a challenge. If I see that you've made an effort, I'll want to give you the point, but I am reserving it for those teams which truly go above and beyond the requirements, demonstrating excellence in their extra work.

## Acknowledgements

The original version of this lab was written by Dr. Sebern. The lab was modified by Dr. Yoder and updated for automated testing by Rokkincat.
