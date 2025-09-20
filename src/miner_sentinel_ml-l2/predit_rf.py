#!/usr/bin/env python3
import argparse, joblib, pandas as pd, numpy as np, os, glob, json

def load_any(path):
    if os.path.isdir(path):
        files = glob.glob(os.path.join(path, "*.csv")) + glob.glob(os.path.join(path, "*.parquet"))
        df = pd.concat([pd.read_parquet(p) if p.endswith(".parquet") else pd.read_csv(p) for p in files], ignore_index=True)
    elif path.endswith(".parquet"):
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path)
    return df

def main(model_path, data_path, out_json=None, topn=50):
    bundle = joblib.load(model_path)
    model, features, thr = bundle["model"], bundle["features"], bundle["threshold"]
    df = load_any(data_path)
    for c in df.columns:
        if df[c].dtype == "bool": df[c] = df[c].astype(np.uint8)
    X = df[features].to_numpy()
    prob = model.predict_proba(X)[:,1]
    pred = (prob >= thr).astype(int)
    df_out = df.copy()
    df_out["proba"] = prob
    df_out["pred"] = pred
    df_out = df_out.sort_values("proba", ascending=False)
    if out_json:
        df_out.head(topn).to_json(out_json, orient="records", force_ascii=False)
        print(f"[OK] wrote {out_json}")
    else:
        print(df_out.head(topn).to_string(index=False))

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--topn", type=int, default=50)
    args = ap.parse_args()
    main(args.model, args.data, args.out_json, args.topn)
