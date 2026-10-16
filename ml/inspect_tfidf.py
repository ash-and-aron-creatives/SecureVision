import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import os
from datetime import datetime

PROCESSED_DIR = os.path.join('data', 'processed')
TODAY = datetime.now().strftime('%Y-%m-%d')
MASTER_FILE = os.path.join(PROCESSED_DIR, f'master_cves_{TODAY}.csv')

def inspect_text_features():
    if not os.path.exists(MASTER_FILE):
        print("Master file not found.")
        return
    df = pd.read_csv(MASTER_FILE).fillna('')
    # Assuming description column exists
    desc_col = 'description' if 'description' in df.columns else df.columns[1]
    
    vectorizer = TfidfVectorizer(max_features=30, stop_words='english')
    X = vectorizer.fit_transform(df[desc_col])
    
    print("=== P3 AUDIT: Top 30 TF-IDF Terms ===")
    print(vectorizer.get_feature_names_out())

if __name__ == '__main__':
    inspect_text_features()
