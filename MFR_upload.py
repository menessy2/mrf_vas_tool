import requests
import os
from config import *

LOGIN_PATH = 'src/lib/usercake/login.php'
UPLOAD_PATH = 'api.php?action=uploadfiles'
VIRUSTOTAL_PATH = 'api.php?action=virustotalscan'





def login(username=USERNAME, password=PASSWORD):
    payload = {
        'username': username,
        'password': password
    }
    session = requests.session()
    r = session.post(BASE_URL+LOGIN_PATH, data=payload)
    return session


def upload_single_file(session, filename):
    files = {
        'files[]' : open(filename, 'rb'),
        'files_data' : '[{"index":0,"preview":{},"vtsubmit":true,"cksubmit":false,"tags":"","urls":""}]'
    }
    r = session.post(BASE_URL + UPLOAD_PATH, data='', files=files)
    print(r.text)


def request_virustotal_scan(session, hash):
    data = "hash=" + hash
    r = session.post(BASE_URL + VIRUSTOTAL_PATH, data=data)
    print(r.text)


def return_files_list(folder):
    matches = []
    for root, dirnames, filenames in os.walk(folder):
        for filename in filenames:
            temp_file = os.path.join(root, filename)
            if os.path.isfile(temp_file):
                matches.append(temp_file)
    return matches



def main():
    session = login()
    filepath = str(input("Enter filepath: "))
    files = return_files_list(filepath)
    for file in files:
        upload_single_file(session, file)


if __name__ == '__main__':
    main()