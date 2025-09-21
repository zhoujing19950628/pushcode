#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
import json
import os
from pathlib import Path
from typing import List, Tuple, Optional, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    auc,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    accuracy_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit

# -----------------------------
# 数据加载
# -----------------------------
def load_dataset(path: str, label_col="miner", group_col=None, drop_cols=None, impute="none"):
    if os.path.isdir(path):
        files = glob.glob(os.path.join(path, "*.csv")) + glob.glob(os.path.join(path, "*.parquet"))
        if not files:
            raise FileNotFoundError(f"No CSV/Parquet files under {path}")
        dfs = [pd.read_parquet(p) if p.endswith(".parquet") else pd.read_csv(p) for p in files]
        df = pd.concat(dfs, ignore_index=True)
    elif str(path).endswith(".parquet"):
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path)

    if label_col not in df.columns:
        raise KeyError(f"Label column '{label_col}' not found. Available: {df.columns.tolist()}")

    # 布尔->0/1
    for c in df.columns:
        if df[c].dtype == "bool":
            df[c] = df[c].astype(np.uint8)

    drop = set(drop_cols or [])
    drop.add(label_col)
    if group_col and group_col in df.columns:
        drop.add(group_col)

    numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
    features = [c for c in numeric_cols if c not in drop]
    if not features:
        raise ValueError("No numerical features found after dropping label/group/extra columns.")

    if impute == "median":
        df[features] = df[features].fillna(df[features].median())
    elif impute == "zero":
        df[features] = df[features].fillna(0)

    X = df[features].to_numpy()
    y = df[label_col].astype(int).to_numpy()
    groups = df[group_col].to_numpy() if group_col and group_col in df.columns else None
    return df, X, y, groups, features

# -----------------------------
# 阈值选择 & 指标
# -----------------------------
def pr_auc_value(y_true, prob):
    p, r, _ = precision_recall_curve(y_true, prob)
    return float(auc(r, p))

def choose_threshold_by_min_precision(y_true, prob, min_precision=0.90, policy="max_recall"):
    """
    在 precision >= min_precision 的候选里挑阈值：
      - policy="max_recall": 召回最大的阈值（推荐，避免过保守）
      - policy="min_thr":    最小阈值（尽量多报正）
      - policy="max_f1":     F1 最大
    """
    p, r, thr = precision_recall_curve(y_true, prob)
    ok = np.where(p[:-1] >= min_precision)[0]
    if ok.size == 0:
        # 没有任何阈值满足 min_precision，退而求其次用90分位作为阈值
        return float(np.quantile(prob, 0.9))
    if policy == "min_thr":
        j = ok[np.argmin(thr[ok])]
    elif policy == "max_f1":
        f1 = 2 * p[:-1] * r[:-1] / (p[:-1] + r[:-1] + 1e-12)
        j = ok[np.argmax(f1[ok])]
    else:  # max_recall
        j = ok[np.argmax(r[:-1][ok])]
    return float(thr[j])

def choose_threshold_by_recall(y_true, prob, recall_target=0.95):
    p, r, thr = precision_recall_curve(y_true, prob)
    idx = np.where(r[:-1] >= recall_target)[0]
    if len(idx):
        j = idx[np.argmax(p[:-1][idx])]  # 先满足召回，再取精度最高
        return float(thr[j])
    # 退路：尽量取召回最高的点
    j = int(np.argmax(r[:-1]))
    return float(thr[j]) if len(thr) else 0.5

def choose_threshold_by_accuracy(y_true, prob, min_recall=None, min_precision=None):
    p, r, thr = precision_recall_curve(y_true, prob)
    best_acc, best_thr = -1.0, 0.5
    for i, t in enumerate(thr):
        yhat = (prob >= t).astype(int)
        prec = p[i] if i < len(p) else 1.0
        rec = r[i] if i < len(r) else 0.0
        if (min_recall is not None and rec < min_recall):
            continue
        if (min_precision is not None and prec < min_precision):
            continue
        acc = accuracy_score(y_true, yhat)
        if acc > best_acc:
            best_acc, best_thr = acc, float(t)
    return best_thr

def quantiles(arr: np.ndarray) -> List[float]:
    return list(map(float, np.quantile(arr, [0, .25, .5, .75, .9, .95, .99, 1])))

def parse_max_features(s: Optional[str]):
    if s is None:
        return None
    s = str(s).lower()
    if s in ("none", "null"):
        return None
    if s in ("sqrt", "log2"):
        return s
    try:
        if "." in s:
            return float(s)
        return int(s)
    except Exception:
        return s  # 兜底

# -----------------------------
# 训练主流程
# -----------------------------
def main(args):
    Path(args.out).mkdir(parents=True, exist_ok=True)

    df, X, y, groups, features = load_dataset(
        args.data,
        label_col=args.label,
        group_col=args.group,
        drop_cols=(args.drop_cols.split(",") if args.drop_cols else None),
        impute=args.impute,
    )
    pos_rate = float(y.mean()) if len(y) else 0.0
    print(f"[INFO] dataset shape={df.shape}, pos_rate={pos_rate:.3f}, features={len(features)}")

    # 一次性 Test 切分（优先 GroupSplit）
    if groups is not None:
        gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.random_state)
        tr_idx, te_idx = next(gss.split(X, y, groups))
    else:
        sss = StratifiedShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.random_state)
        tr_idx, te_idx = next(sss.split(X, y))

    Xtr_full, Xte = X[tr_idx], X[te_idx]
    ytr_full, yte = y[tr_idx], y[te_idx]

    # 从训练集中再切出验证集（用于挑阈值，避免在训练集本身上选阈值导致过保守）
    if args.val_size > 0:
        sss2 = StratifiedShuffleSplit(n_splits=1, test_size=args.val_size, random_state=args.random_state + 1)
        tr2_idx, val_idx = next(sss2.split(Xtr_full, ytr_full))
        Xtr, ytr = Xtr_full[tr2_idx], ytr_full[tr2_idx]
        Xval, yval = Xtr_full[val_idx], ytr_full[val_idx]
    else:
        Xtr, ytr = Xtr_full, ytr_full
        Xval = yval = None

    # 构造 RF
    max_features = parse_max_features(args.max_features)
    class_weight = None if (args.class_weight is None or str(args.class_weight).lower() == "none") else args.class_weight

    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        min_samples_split=args.min_samples_split,
        max_features=max_features,
        criterion=args.criterion,
        class_weight=class_weight,
        oob_score=args.oob_score,
        n_jobs=-1,
        random_state=args.random_state,
    )
    rf.fit(Xtr, ytr)

    # 训练/验证/测试 概率
    prob_tr = rf.predict_proba(Xtr)[:, 1]
    prob_val = rf.predict_proba(Xval)[:, 1] if Xval is not None else None
    prob_te = rf.predict_proba(Xte)[:, 1]

    # 平滑（可选）
    if args.smooth > 1:
        k = args.smooth
        def _mv(a): return np.convolve(a, np.ones(k)/k, mode="same")
        prob_tr = _mv(prob_tr)
        if prob_val is not None: prob_val = _mv(prob_val)
        prob_te = _mv(prob_te)

    # 阈值选择：默认在 验证集 上确定（--threshold-on 可选 train/val）
    choose_on = (args.threshold_on or "val").lower()
    y_for_thr, prob_for_thr = (yval, prob_val) if (choose_on == "val" and prob_val is not None) else (ytr, prob_tr)

    if args.acc:
        thr = choose_threshold_by_accuracy(
            y_for_thr, prob_for_thr, min_recall=args.min_recall, min_precision=args.min_precision
        )
    elif args.recall_target is not None:
        thr = choose_threshold_by_recall(y_for_thr, prob_for_thr, args.recall_target)
    else:
        # 修复：在满足最小精度的前提下取“最大召回”的阈值（避免阈值过高导致全负）
        thr = choose_threshold_by_min_precision(y_for_thr, prob_for_thr, args.min_precision, policy="max_recall")

    # 测试集评估
    yhat_te = (prob_te >= thr).astype(int)
    report = classification_report(yte, yhat_te, digits=3, output_dict=True, zero_division=0)
    cm = confusion_matrix(yte, yhat_te).tolist()
    pr_auc_tr = pr_auc_value(ytr, prob_tr)
    pr_auc_te = pr_auc_value(yte, prob_te)

    # 诊断信息
    q_tr = quantiles(prob_tr)
    q_val = quantiles(prob_val) if prob_val is not None else None
    q_te = quantiles(prob_te)
    pos_preds_test = int((prob_te >= thr).sum())

    # 特征重要性
    importances = pd.DataFrame({"feature": features, "importance": rf.feature_importances_}) \
                    .sort_values("importance", ascending=False)
    importances.to_csv(os.path.join(args.out, "importances.csv"), index=False)

    # 保存模型（bundle）
    bundle = {
        "model": rf,
        "features": features,
        "label": args.label,
        "threshold": float(thr),
        "params": {
            "n_estimators": args.n_estimators,
            "max_depth": args.max_depth,
            "min_samples_leaf": args.min_samples_leaf,
            "min_samples_split": args.min_samples_split,
            "max_features": max_features,
            "criterion": args.criterion,
            "class_weight": class_weight,
            "oob_score": args.oob_score,
            "random_state": args.random_state,
            "smooth": args.smooth,
            "threshold_on": choose_on,
            "threshold_strategy": (
                "accuracy" if args.acc else ("recall_target" if args.recall_target is not None else "min_precision_max_recall")
            ),
        },
        "diagnostics": {
            "prob_quantiles_train": q_tr,
            "prob_quantiles_val": q_val,
            "prob_quantiles_test": q_te,
        }
    }
    joblib.dump(bundle, os.path.join(args.out, "rf_model.joblib"))

    metrics = {
        "n_train": int(len(ytr)),
        "n_val": int(len(yval)) if yval is not None else 0,
        "n_test": int(len(yte)),
        "pos_rate_train": float(ytr.mean()),
        "pos_rate_val": float(yval.mean()) if yval is not None else None,
        "pos_rate_test": float(yte.mean()),
        "threshold": float(thr),
        "oob_score": getattr(rf, "oob_score_", None),
        "pr_auc_train": pr_auc_tr,
        "pr_auc_test": pr_auc_te,
        "report_test": report,
        "confusion_matrix_test": cm,
        "pos_preds_test": pos_preds_test,
    }
    with open(os.path.join(args.out, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[OK] saved: {args.out}/rf_model.joblib, {args.out}/metrics.json, {args.out}/importances.csv")
    print("[DIAG] prob_quantiles_train:", q_tr)
    if q_val is not None:
        print("[DIAG] prob_quantiles_val:  ", q_val)
    print("[DIAG] prob_quantiles_test: ", q_te)
    print(f"[DIAG] pos_preds_test: {pos_preds_test}")
    print("[TEST] precision={:.3f} recall={:.3f} f1={:.3f} thr={:.3f}".format(
        report.get("1", {}).get("precision", 0.0),
        report.get("1", {}).get("recall", 0.0),
        report.get("1", {}).get("f1-score", 0.0),
        float(thr)
    ))

# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Train RandomForest on mining features (with validation-based threshold)")
    # data & io
    ap.add_argument("--data", required=True, help="CSV/Parquet file or a directory containing them")
    ap.add_argument("--out", default="out_rf", help="output directory")
    ap.add_argument("--label", default="miner", help="label column name (0/1)")
    ap.add_argument("--group", default=None, help="optional group column for GroupSplit (e.g., host_id/date)")
    ap.add_argument("--drop-cols", default=None, help="extra columns to drop, comma-separated")
    ap.add_argument("--impute", default="none", choices=["none", "median", "zero"], help="missing value handling")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--val-size", type=float, default=0.2, help="validation size from training set for threshold picking (0 to disable)")
    ap.add_argument("--threshold-on", choices=["train","val"], default="val", help="choose threshold on which split")
    ap.add_argument("--random-state", type=int, default=42)

    # RF hyperparameters
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--min-samples-leaf", type=int, default=3)
    ap.add_argument("--min-samples-split", type=int, default=2)
    ap.add_argument("--max-features", default="sqrt", help='"sqrt","log2","none"/"null" or an int/float for sklearn')
    ap.add_argument("--criterion", default="gini", choices=["gini", "entropy", "log_loss"])
    ap.add_argument("--class-weight", default="balanced", choices=["none", "balanced"])
    ap.add_argument("--oob-score", action="store_true", help="enable OOB score (needs enough trees)")

    # threshold strategies
    ap.add_argument("--acc", action="store_true", help="choose threshold by max accuracy (optionally with floors)")
    ap.add_argument("--min-recall", type=float, default=None, help="accuracy mode: recall floor")
    ap.add_argument("--min-precision", type=float, default=0.80, help="min precision floor for min-precision strategy")
    ap.add_argument("--recall-target", type=float, default=None, help="target recall for recall-based threshold")
    ap.add_argument("--smooth", type=int, default=0, help="moving average window for probabilities before threshold")

    args = ap.parse_args()
    main(args)
