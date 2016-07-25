__author__ = 'ehood'


end_chars = [',', ';', '.', r"'", "}", ':', '>', r'"', '\n', '\r']
start_chars = [',', ';', '.', r"'", '\n', '\r', ':', '<', '{', r'"']


# the function should get the responses without the headers.
def find_diff_str(response1, response2):
    i = 0  # len(response1)
    j = 0  # flag and temp for i.
    while i < len(response1) and i < len(response2):
        if response1[i] == response2[i]:
            i += 1
        else:
            j += 1
            break
    if j != 0:
        j = i
        while response1[i] not in end_chars or i >= len(response1):
            i += 1
        while response1[j] not in start_chars or j <= 0:
            j -= 1
        return [response1[j+1:i], response2[j+1:i]]
    return None

r1 = """HTTP/1.1 200 OK
server: Apache/2.4.7 (Ubuntu)
x-powered-by: PHP/5.5.9-1ubuntu4.17
x-robots-tag: noindex
x-content-type-options: nosniff
expires: Wed, 11 Jan 1984 05:00:00 GMT
cache-control: no-cache, must-revalidate, max-age=0
pragma: no-cache
content-length: 47
keep-alive: timeout=5, max=100
content-type: application/json; charset=UTF-8
X-BACKEND: apps-proxy
Connection: close
{"wp-auth-check":true,"server_time":1469437078}"""
r2 = """HTTP/1.1 200 OK
server: Apache/2.4.7 (Ubuntu)
x-powered-by: PHP/5.5.9-1ubuntu4.17
x-robots-tag: noindex
x-content-type-options: nosniff
expires: Wed, 11 Jan 1984 05:00:00 GMT
cache-control: no-cache, must-revalidate, max-age=0
pragma: no-cache
content-length: 47
keep-alive: timeout=5, max=100
content-type: application/json; charset=UTF-8
X-BACKEND: apps-proxy
Connection: close
{"wp-auth-check":true,"server_time":1469437142}"""

print(find_diff_str(response1=r1, response2=r2))