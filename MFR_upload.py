import requests
import os
import json
from config import *

LOGIN_PATH = 'login.php'
UPLOAD_PATH = 'api.php?action=uploadfiles'
VIRUSTOTAL_PATH = 'api.php?action=virustotalscan'
INDEXING_PATH = 'api.php?action=getfiles&page='
STATS_PATH = 'api.php?action=getstorageinfo'



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


def get_page_counts(session):
    r = session.get(BASE_URL + STATS_PATH )
    return int(json.loads(r.text)['max_page'])

"""
@returns list of hashes
"""
def indexing_files(session, page_id):
    final_result = []
    r = session.get(BASE_URL + INDEXING_PATH + str(page_id))
    result = json.loads(r.text)
    for element in result:
        virustotal_id = element["virustotal_scan_id"]
        hash = element["md5"]
        if virustotal_id != '':
            final_result.append(hash)
    return final_result




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