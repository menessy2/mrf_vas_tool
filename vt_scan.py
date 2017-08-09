from MFR_upload import login, request_virustotal_scan, indexing_files, get_page_counts
import time




def main():
    session = login()
    total_page_counts = get_page_counts(session)
    for page_count in range(1, total_page_counts+1):
        hashes = indexing_files(session, page_count)
        for hash in hashes:
            while request_virustotal_scan(session, hash) == 400:
                time.sleep(60)

if __name__ == '__main__':
    main()