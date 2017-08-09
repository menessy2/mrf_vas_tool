from MFR_upload import login, request_virustotal_scan, indexing_files, get_page_counts
import time




def main():
    session = login()
    total_page_counts = get_page_counts(session)
    for page_count in range(1, total_page_counts+1):
        hashes = indexing_files(session, page_count)
        for hash in hashes:
            res = request_virustotal_scan(session, hash)
            print("Result", res)
            while res == 400:
                print("Sleeping for 60s...")
                time.sleep(60)
                res = request_virustotal_scan(session, hash)
                print("Result After sleeping", res)

if __name__ == '__main__':
    main()