import gzip
try:
    with gzip.open(r'data\raw\epss_scores_2026-10-08.csv.gz', 'rt') as f:
        print('--- VERBATIM EPSS HEADER ---')
        print([next(f).strip() for _ in range(3)])
except Exception as e:
    print(f'File read error: {e}')
