
<This project is under development>
Enforcment Detection

review:
In the daily life of web app pt , is to check vulu and enforcment  in the cookies/session , headers enc,
in every page,and API on the web server.
this mission is a difficual to handle in a big API web server. every time to change the session or the other headers in the page.
this tools help to that simple PT daily life.
by enering first the header modify , the tools is checking for a BYPASS, in every page/API in the
server, all you have to do is to browse to those pages/API's.
the tool will simply tell you if bypass or not in every web req.

strategy:
the tool work like that:

the user in input the modify header/session/cookies.

the tool run a intercept http/s proxy , for every request, the tool will take the request and
make 3 diffrent request:

1. the same request as the original
2. the modify request
3. request without cookie

next the algoritem make a check by a diffrent in those request , 1 and 2 , 1 and 3.
the check is to how many diffrent is between those request by checking diffrent in the lenght ,status, and satistic of the text/tags in the response msg.

the reason of sending the first requset again, and not making check by the original response, is for
complex one time request like deleting somthing from the server, becuase after the firts request , this
request in not valid, so you got more chance to get the right messure by sending the original request again.
the reson of sending the request without cookies is for checking maybe the BYPASS is more danger .

usage:

for install :
./setup_cert.sh
python enforDetect.py
go to http://get.cert/ the certificate will be install in the browser.

for running:
first enter the header/cookies/sesion modify for example:

Cookie: phpseed:asdf3w42r2f2f2f233crebge

Created by : Tiko and Ehood.


