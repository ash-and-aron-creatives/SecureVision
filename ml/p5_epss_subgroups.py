import pandas as pd, numpy as np
from sklearn.metrics import average_precision_score

print('--- SUPPLEMENTARY: EPSS SUBGROUPS ---')
test_df = pd.read_csv(r'data\processed\test_2026-10-08.csv', low_memory=False)
test_pub_d = pd.to_datetime(test_df['published_date'], utc=True).dt.date
test_kev_d = pd.to_datetime(test_df['kev_date_added'], utc=True).dt.date
gaps = (test_kev_d - test_pub_d).apply(lambda x: x.days if pd.notnull(x) else np.nan)

y_test = test_df['in_kev'].values.astype(int)
s_epss = test_df['epss'].fillna(0).astype(float).values

mask_g1 = (y_test == 1) & (gaps > 0) & (gaps <= 30)
drop_other_g1 = (y_test == 0) | mask_g1
y_g1 = y_test[drop_other_g1]
s_epss_g1 = s_epss[drop_other_g1]
print(f'1-30 Days Post-Pub | Positives={y_g1.sum()} | EPSS PR-AUC={average_precision_score(y_g1, s_epss_g1):.4f}')

mask_g2 = (y_test == 1) & (gaps <= 0)
drop_other_g2 = (y_test == 0) | mask_g2
y_g2 = y_test[drop_other_g2]
s_epss_g2 = s_epss[drop_other_g2]
print(f'Same-day/Earlier   | Positives={y_g2.sum()} | EPSS PR-AUC={average_precision_score(y_g2, s_epss_g2):.4f}')
