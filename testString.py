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


def find_hidden_input(response1, response2):
    index_of = response1.find(r'input type="hidden"')
    while index_of != -1:
        y = 0
        x = response1.find(r'value="', index_of)
        j = x
        if x != -1:
            y += response1.find(r'"', x+7)
            if y != -1:
                while x < y:
                    if response1[x] != response2[x]:
                        return [response1[j+7:y], response2[j+7:y]]
                    x += 1
        index_of = response1.find(r'input type="hidden"', index_of+1)
    return None


r21 = """<form action="/transfer.do" method="post">
  <input type="hidden" name="CSRFToken"
  value="OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWE
  wYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZ
  MGYwMGEwOA==">
  </form>"""
r22 = """<form action="/transfer.do" method="post">
  <input type="hidden" name="CSRFToken"
  value="OWY4NmQwODE3ODRjN2Q2NTlhMmZlYWE
  wYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZ
  MGYwMGEwOA==">
  </form>"""


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

#print(find_diff_str(response1=r1, response2=r2))

print(find_hidden_input(r21, r22))