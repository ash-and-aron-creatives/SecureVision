import pandas as pd
import numpy as np
import scipy.sparse as sp
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import average_precision_score
from sklearn.calibration import CalibratedClassifierCV
import json, hashlib, glob, os, re, joblib, sys
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

LOG_P5 = 'docs/results/p5/p5_console.log'
os.makedirs('docs/results/p5', exist_ok=True)

def log_p5(msg):
    print(msg)
    with open(LOG_P5, 'a', encoding='utf-8') as f: f.write(msg + '\n')

def eval_k(y_true, y_scores, k):
    rng = np.random.RandomState(42)
    noise = rng.uniform(0, 1e-9, size=len(y_true))
    idx = np.argsort(-(y_scores + noise))
    top_k = y_true[idx[:k]]
    return top_k.sum() / k, top_k.sum() / max(1, y_true.sum())

def parse_full_vector(df):
    keys = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    parsed = {k: [] for k in keys}
    patterns = {
        'AV': re.compile(r'AV:([NALP])'),
        'AC': re.compile(r'AC:([LH])'),
        'PR': re.compile(r'PR:([NLH])'),
        'UI': re.compile(r'UI:([NR])'),
        'S':  re.compile(r'S:([UC])'),
        'C':  re.compile(r'C:([NLH])'),
        'I':  re.compile(r'I:([NLH])'),
        'A':  re.compile(r'A:([NLH])')
    }
    vec_series = df['cvss_vector'] if 'cvss_vector' in df.columns else pd.Series([''] * len(df))
    for vec in vec_series.fillna(''):
        s = str(vec)
        for k, p in patterns.items():
            m = p.search(s)
            parsed[k].append(m.group(1) if m else 'MISSING')
    return pd.DataFrame(parsed, index=df.index)

def run_p5_final(config_path):
    open(LOG_P5, 'w').close()
    log_p5('=== P5: FINAL SINGLE TEST SET EVALUATION ===')
    log_p5('Execution Time (UTC): {}'.format(datetime.utcnow().isoformat() + 'Z'))

    # Load and verify config
    with open(config_path, 'r') as f: config = json.load(f)
    log_p5('Loaded Frozen Config: {}'.format(config_path))
    log_p5('Target Model File   : {}'.format(config['saved_model']))
    log_p5('Config Model SHA-256: {}'.format(config['model_sha256']))

    # Load frozen calibrated model
    model_path = os.path.join('data', 'processed', config['saved_model'])
    with open(model_path, 'rb') as f: actual_model_h = hashlib.sha256(f.read()).hexdigest()
    log_p5('Disk Model SHA-256  : {}'.format(actual_model_h))
    assert actual_model_h == config['model_sha256'], 'FATAL: Model hash mismatch on disk!'
    cal_model = joblib.load(model_path)
    base_model = cal_model.calibrated_classifiers_[0].estimator

    # C1. Validation Reference Line BEFORE test labels are evaluated
    log_p5('\n--- C1: REFERENCE LINE (VALIDATION 2025 SET) ---')
    train_df = pd.read_csv(r'data\processed\train_2026-10-08.csv', low_memory=False)
    val_df = pd.read_csv(r'data\processed\val_2026-10-08.csv', low_memory=False)

    train_df['cvss_missing'] = train_df['cvss_score'].isna().astype(float)
    val_df['cvss_missing'] = val_df['cvss_score'].isna().astype(float)
    cvss_tr_sp = sp.csr_matrix(train_df[['cvss_score', 'cvss_missing']].fillna(6.7).astype(float).values)
    cvss_val_sp = sp.csr_matrix(val_df[['cvss_score', 'cvss_missing']].fillna(6.7).astype(float).values)

    ohe_vec = OneHotEncoder(handle_unknown='ignore', sparse_output=True)
    ohe_vec.fit(parse_full_vector(train_df))
    X_vec_val = ohe_vec.transform(parse_full_vector(val_df))

    top_cwes = train_df['cwe'].value_counts().head(20).index.tolist() if 'cwe' in train_df.columns else []
    train_cwe = train_df['cwe'].apply(lambda x: str(x) if x in top_cwes else 'OTHER').to_frame()
    val_cwe = val_df['cwe'].apply(lambda x: str(x) if x in top_cwes else 'OTHER').to_frame()
    ohe_cwe = OneHotEncoder(handle_unknown='ignore', sparse_output=True)
    ohe_cwe.fit(train_cwe)
    X_cwe_val = ohe_cwe.transform(val_cwe)

    desc_col = 'description' if 'description' in train_df.columns else train_df.columns[1]
    pat_b = re.compile(config['regex_blacklist'], re.IGNORECASE)
    tfidf_b = TfidfVectorizer(max_features=100, preprocessor=lambda x: pat_b.sub('', str(x).lower()), stop_words='english', ngram_range=(1,2), min_df=2)
    tfidf_b.fit(train_df[desc_col].fillna(''))
    text_val_b = tfidf_b.transform(val_df[desc_col].fillna(''))

    X_val = sp.hstack([cvss_val_sp, X_vec_val, X_cwe_val, text_val_b]).tocsr()
    assert X_val.shape[1] == config['n_features_in'], 'Val feature count mismatch!'

    y_val = val_df['in_kev'].values.astype(int)
    val_preds = cal_model.predict_proba(X_val)[:, 1]
    val_pr = average_precision_score(y_val, val_preds)
    val_p100, val_r100 = eval_k(y_val, val_preds, 100)
    val_p500, val_r500 = eval_k(y_val, val_preds, 500)
    log_p5('[REFERENCE LINE - VAL 2025] PR-AUC: {:.4f} | P@100: {:.4f} (R@100: {:.4f}) | P@500: {:.4f} (R@500: {:.4f})'.format(val_pr, val_p100, val_r100, val_p500, val_r500))

    # C4. Boundary Check
    log_p5('\n--- C4: BOUNDARY & KEV TIMELINE AUDIT ---')
    kev_path = r'data\raw\kev_catalog_2026-10-08.json'
    kev_mtime = datetime.fromtimestamp(os.path.getmtime(kev_path)).isoformat() if os.path.exists(kev_path) else 'N/A'
    log_p5('KEV Snapshot Modified Time (Local): {}'.format(kev_mtime))

    # 2. OPEN TEST SET
    log_p5('\n--- OPENING TEST SET (2026 SINGLE PASS) ---')
    test_df = pd.read_csv(r'data\processed\test_2026-10-08.csv', low_memory=False)
    y_test = test_df['in_kev'].values.astype(int)
    test_cvss_raw = test_df['cvss_score'].fillna(6.7).values / 10.0

    test_pub_dt = pd.to_datetime(test_df['published_date'], utc=True)
    is_sep8 = test_pub_dt.dt.date == pd.to_datetime('2026-09-08').date()
    sep8_pos = int(test_df.loc[is_sep8, 'in_kev'].sum())
    log_p5('Test Partition: Rows={} | Positives={}'.format(len(test_df), int(y_test.sum())))
    log_p5('Sep 8 Boundary CVEs: Total={} | Positives={}'.format(int(is_sep8.sum()), sep8_pos))

    # Construct test features strictly using frozen encoders
    test_df['cvss_missing'] = test_df['cvss_score'].isna().astype(float)
    cvss_test_sp = sp.csr_matrix(test_df[['cvss_score', 'cvss_missing']].fillna(6.7).astype(float).values)
    X_vec_test = ohe_vec.transform(parse_full_vector(test_df))
    test_cwe = test_df['cwe'].apply(lambda x: str(x) if x in top_cwes else 'OTHER').to_frame() if 'cwe' in test_df.columns else pd.DataFrame({'cwe': ['OTHER']*len(test_df)})
    X_cwe_test = ohe_cwe.transform(test_cwe)
    text_test_b = tfidf_b.transform(test_df[desc_col].fillna(''))

    X_test = sp.hstack([cvss_test_sp, X_vec_test, X_cwe_test, text_test_b]).tocsr()
    assert X_test.shape[1] == config['n_features_in'], 'FATAL: Test feature columns mismatch!'

    # Score test set
    test_preds = cal_model.predict_proba(X_test)[:, 1]

    # Metrics
    log_p5('\n--- 1. PRIMARY METRICS ON TEST SET ---')
    test_pr = average_precision_score(y_test, test_preds)
    p50, r50 = eval_k(y_test, test_preds, 50)
    p100, r100 = eval_k(y_test, test_preds, 100)
    p500, r500 = eval_k(y_test, test_preds, 500)
    log_p5('XGBoost Calibrated Model | Test PR-AUC: {:.4f}'.format(test_pr))
    log_p5('  P@50 : {:.4f} | R@50 : {:.4f}'.format(p50, r50))
    log_p5('  P@100: {:.4f} | R@100: {:.4f}'.format(p100, r100))
    log_p5('  P@500: {:.4f} | R@500: {:.4f}'.format(p500, r500))

    # Baseline 1: CVSS Ranking Baseline (100 random tie-breaks)
    log_p5('\n--- 2. BASELINE COMPARISONS ---')
    rng_tie = np.random.RandomState(42)
    cvss_prs, cvss_p50s, cvss_r50s, cvss_p100s, cvss_r100s, cvss_p500s, cvss_r500s = [], [], [], [], [], [], []
    for _ in range(100):
        noise = rng_tie.uniform(0, 1e-9, size=len(y_test))
        s = test_cvss_raw + noise
        cvss_prs.append(average_precision_score(y_test, s))
        p50_c, r50_c = eval_k(y_test, s, 50); cvss_p50s.append(p50_c); cvss_r50s.append(r50_c)
        p100_c, r100_c = eval_k(y_test, s, 100); cvss_p100s.append(p100_c); cvss_r100s.append(r100_c)
        p500_c, r500_c = eval_k(y_test, s, 500); cvss_p500s.append(p500_c); cvss_r500s.append(r500_c)
    log_p5('CVSS Baseline (100 tie-breaks) | Test PR-AUC: {:.4f} +/- {:.4f}'.format(np.mean(cvss_prs), np.std(cvss_prs)))
    log_p5('  P@50 : {:.4f} | R@50 : {:.4f}'.format(np.mean(cvss_p50s), np.mean(cvss_r50s)))
    log_p5('  P@100: {:.4f} | R@100: {:.4f}'.format(np.mean(cvss_p100s), np.mean(cvss_r100s)))
    log_p5('  P@500: {:.4f} | R@500: {:.4f}'.format(np.mean(cvss_p500s), np.mean(cvss_r500s)))

    # Baseline 2: EPSS Hindsight Baseline
    if 'epss' in test_df.columns:
        s_epss = test_df['epss'].fillna(0).astype(float).values + rng_tie.uniform(0, 1e-9, size=len(y_test))
        e_pr = average_precision_score(y_test, s_epss)
        ep50, er50 = eval_k(y_test, s_epss, 50)
        ep100, er100 = eval_k(y_test, s_epss, 100)
        ep500, er500 = eval_k(y_test, s_epss, 500)
        log_p5('EPSS Hindsight Snapshot       | Test PR-AUC: {:.4f}'.format(e_pr))
        log_p5('  P@50 : {:.4f} | R@50 : {:.4f}'.format(ep50, er50))
        log_p5('  P@100: {:.4f} | R@100: {:.4f}'.format(ep100, er100))
        log_p5('  P@500: {:.4f} | R@500: {:.4f}'.format(ep500, er500))

    # Paired Bootstrap (1,000 resamples against CVSS ranking)
    log_p5('\n--- 3. PAIRED BOOTSTRAP (1,000 RESAMPLES, TEST SET) ---')
    diff_pr, diff_p100, diff_p500 = [], [], []
    for _ in range(1000):
        idx = rng_tie.randint(0, len(y_test), len(y_test))
        if y_test[idx].sum() > 0:
            m_pr = average_precision_score(y_test[idx], test_preds[idx])
            c_noise = rng_tie.uniform(0, 1e-9, size=len(idx))
            c_pr = average_precision_score(y_test[idx], test_cvss_raw[idx] + c_noise)
            diff_pr.append(m_pr - c_pr)

            m_noise = rng_tie.uniform(0, 1e-9, size=len(idx))
            mp100, _ = eval_k(y_test[idx], test_preds[idx] + m_noise, 100)
            cp100, _ = eval_k(y_test[idx], test_cvss_raw[idx] + c_noise, 100)
            diff_p100.append(mp100 - cp100)

            mp500, _ = eval_k(y_test[idx], test_preds[idx] + m_noise, 500)
            cp500, _ = eval_k(y_test[idx], test_cvss_raw[idx] + c_noise, 500)
            diff_p500.append(mp500 - cp500)

    ci_pr = np.percentile(diff_pr, [2.5, 97.5])
    ci_p100 = np.percentile(diff_p100, [2.5, 97.5])
    ci_p500 = np.percentile(diff_p500, [2.5, 97.5])
    log_p5('PR-AUC Difference  | Mean: {:.4f} | 95% CI: [{:.4f}, {:.4f}]'.format(np.mean(diff_pr), ci_pr[0], ci_pr[1]))
    log_p5('P@100 Difference   | Mean: {:.4f} | 95% CI: [{:.4f}, {:.4f}]'.format(np.mean(diff_p100), ci_p100[0], ci_p100[1]))
    log_p5('P@500 Difference   | Mean: {:.4f} | 95% CI: [{:.4f}, {:.4f}]'.format(np.mean(diff_p500), ci_p500[0], ci_p500[1]))

    # Sub-groups Analysis (Isolated positive masking)
    log_p5('\n--- 4. SUB-GROUP ANALYSIS (ISOLATED POSITIVES) ---')
    test_pub_d = test_pub_dt.dt.date
    test_kev_d = pd.to_datetime(test_df['kev_date_added'], utc=True).dt.date
    gaps = (test_kev_d - test_pub_d).apply(lambda x: x.days if pd.notnull(x) else np.nan)

    # Subgroup 1: 1-30 days exploitation
    mask_g1 = (test_df['in_kev'] == 1) & (gaps > 0) & (gaps <= 30)
    drop_other_g1 = (test_df['in_kev'] == 0) | mask_g1
    y_g1 = test_df.loc[drop_other_g1, 'in_kev'].values.astype(int)
    ns_g1 = y_g1.sum() / len(y_g1)
    pr_m_g1 = average_precision_score(y_g1, test_preds[drop_other_g1])
    pr_c_g1 = average_precision_score(y_g1, test_cvss_raw[drop_other_g1])
    log_p5('1-30 Days Post-Pub Exploitation | Positives={} | No-Skill={:.4f}'.format(int(y_g1.sum()), ns_g1))
    log_p5('  Model PR-AUC: {:.4f} | CVSS PR-AUC: {:.4f}'.format(pr_m_g1, pr_c_g1))

    # Subgroup 2: Same-day or earlier
    mask_g2 = (test_df['in_kev'] == 1) & (gaps <= 0)
    drop_other_g2 = (test_df['in_kev'] == 0) | mask_g2
    y_g2 = test_df.loc[drop_other_g2, 'in_kev'].values.astype(int)
    ns_g2 = y_g2.sum() / len(y_g2)
    pr_m_g2 = average_precision_score(y_g2, test_preds[drop_other_g2])
    pr_c_g2 = average_precision_score(y_g2, test_cvss_raw[drop_other_g2])
    log_p5('Same-day / Earlier (Known)      | Positives={} | No-Skill={:.4f}'.format(int(y_g2.sum()), ns_g2))
    log_p5('  Model PR-AUC: {:.4f} | CVSS PR-AUC: {:.4f}'.format(pr_m_g2, pr_c_g2))

    # Sensitivity: Excluding Sep 8
    log_p5('\n--- 5. SENSITIVITY ANALYSIS (EXCLUDING SEP 8) ---')
    test_pre8 = test_df[~is_sep8]
    y_pre8 = test_pre8['in_kev'].values.astype(int)
    preds_pre8 = test_preds[~is_sep8]
    cvss_pre8 = test_cvss_raw[~is_sep8]
    log_p5('Excluding Sep 8 Boundary | Rows={} | Positives={}'.format(len(test_pre8), int(y_pre8.sum())))
    log_p5('  Model PR-AUC: {:.4f} | CVSS PR-AUC: {:.4f}'.format(average_precision_score(y_pre8, preds_pre8), average_precision_score(y_pre8, cvss_pre8)))
    p100_pre8, _ = eval_k(y_pre8, preds_pre8, 100)
    p500_pre8, _ = eval_k(y_pre8, preds_pre8, 500)
    log_p5('  P@100: {:.4f} | P@500: {:.4f}'.format(p100_pre8, p500_pre8))

    # Out-of-sample Calibration Reliability Table on 2026 Test Set
    log_p5('\n--- 6. OUT-OF-SAMPLE CALIBRATION TABLE (TEST SET) ---')
    brier_score = np.mean((test_preds - y_test) ** 2)
    log_p5('Brier Score on Test Set: {:.6f}'.format(brier_score))
    
    p80 = np.percentile(test_preds, 80)
    bins_lower = list(np.percentile(test_preds[test_preds < p80], np.linspace(0, 100, 5))[:-1])
    bins_upper = list(np.percentile(test_preds[test_preds >= p80], np.linspace(0, 100, 11)))
    bins = sorted(list(set(bins_lower + bins_upper)))
    bins[0], bins[-1] = -0.001, 1.001

    df_cal_t = pd.DataFrame({'pred': test_preds, 'true': y_test})
    df_cal_t['bin'] = pd.cut(df_cal_t['pred'], bins=bins)
    agg_t = df_cal_t.groupby('bin', observed=False).agg(Mean_Pred=('pred', 'mean'), True_Frac=('true', 'mean'), N=('true', 'count'), Positives=('true', 'sum'))
    log_p5(agg_t.dropna(subset=['Mean_Pred']).to_string())
    log_p5('Total Test N Sum: {} (Matches Test Rows: {})'.format(int(agg_t['N'].sum()), len(test_df)))

    # Save summary manifest
    manifest = {
        'test_rows': len(test_df),
        'test_positives': int(y_test.sum()),
        'test_pr_auc': round(test_pr, 4),
        'cvss_pr_auc_mean': round(float(np.mean(cvss_prs)), 4),
        'paired_diff_mean': round(float(np.mean(diff_pr)), 4),
        'paired_diff_ci': [round(float(ci_pr[0]), 4), round(float(ci_pr[1]), 4)],
        'brier_score': round(float(brier_score), 6)
    }
    with open('docs/results/p5/manifest.json', 'w') as f: json.dump(manifest, f, indent=2)
    log_p5('\nP5 Evaluation Complete. Manifest saved to docs/results/p5/manifest.json')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--final':
        cfg = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == '--config' else 'frozen_config.json'
        run_p5_final(cfg)
    else:
        print('To run final P5 evaluation: python ml/run_pipeline.py --final --config frozen_config.json')
