from MFR_upload import login, request_virustotal_scan





def main():
    files = []
    session = login()
    for file in files:
        request_virustotal_scan(session, file)


if __name__ == '__main__':
    main()