FROM python:3

ADD xss.py /
ADD xfuzz.py /
ADD payloads.txt /


RUN pip install pystrich
RUN pip install requests

CMD [ "python", "./xss.py", "./xfuzz.py" , "./payloads.txt"]