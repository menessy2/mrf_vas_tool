from MFR_upload import login, request_virustotal_scan, indexing_files, get_page_counts





def main():
    session = login()
    total_page_counts = get_page_counts()
    for page_count in range(1, total_page_counts+1):
        hashes = indexing_files(session, page_count)
        for hash in hashes:
            request_virustotal_scan(session, hash)


if __name__ == '__main__':
    main()