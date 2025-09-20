#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
import json
import os
from pathlib import Path

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
def load_dataset(path, label_col="miner", group_col=None, drop_cols=None, impute="none"):
    if os.path.isdir(path):
        files = glob.glob(os.path.join(path, "*.csv")) + glob.glob(os.path.join(path, "*.parquet"))
        if not files:
            raise FileNotFoundError(f"No CSV/Parquet files under {path}")
        dfs = [pd.read_parquet(p) if p.endswith(".parquet") else pd.read_csv(p) for p in files]
        df = pd.concat(dfs, ignore_index=True)
    elif path.endswith(".parquet"):
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path)

    if label_col not in df.columns:
        raise KeyError(f"Label column '{label_col}' not found. Available: {df.columns.tolist()}")

    # 布尔转 0/1
    for c in df.columns:
        if df[c].dtype == "bool":
            df[c] = df[c].astype(np.uint8)

    # 选择特征列：数值型，排除 label 与显式 drop 列
    drop = set(drop_cols or [])
    drop.add(label_col)
    if group_col and group_col in df.columns:
        drop.add(group_col)

    numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
    features = [c for c in numeric_cols if c not in drop]
    if not features:
        raise ValueError("No numerical features found after dropping label/group/extra columns.")

    # 简单缺失值处理
    if impute == "median":
        df[features] = df[features].fillna(df[features].median())
    elif impute == "zero":
        df[features] = df[features].fillna(0)

    X = df[features].to_numpy()
    y = df[label_col].astype(int).to_numpy()
    groups = df[group_col].to_numpy() if group_col and group_col in df.columns else None
    return df, X, y, groups, features


# -----------------------------
# 阈值选择策略
# -----------------------------
def choose_threshold_by_min_precision(y_true, prob, min_precision=0.90):
    p, r, thr = precision_recall_curve(y_true, prob)
    mask = p[:-1] >= min_precision
    if mask.any():
        return float(thr[mask].max())
    return 0.5


def choose_threshold_by_recall(y_true, prob, recall_target=0.95):
    p, r, thr = precision_recall_curve(y_true, prob)
    idx = np.where(r[:-1] >= recall_target)[0]
    if len(idx):
        # 满足召回前提下 precision 最高的阈值
        j = idx[np.argmax(p[:-1][idx])]
        return float(thr[j])
    return 0.5


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


def pr_auc_value(y_true, prob):
    p, r, _ = precision_recall_curve(y_true, prob)
    return float(auc(r, p))


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

    # 划分
    if groups is not None:
        splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.random_state)
        tr_idx, te_idx = next(splitter.split(X, y, groups))
    else:
        splitter = StratifiedShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.random_state)
        tr_idx, te_idx = next(splitter.split(X, y))

    Xtr, Xte = X[tr_idx], X[te_idx]
    ytr, yte = y[tr_idx], y[te_idx]

    # 构造 RF
    max_features = None if (args.max_features is None or args.max_features.lower() == "none") else args.max_features
    class_weight = None if (args.class_weight is None or args.class_weight.lower() == "none") else args.class_weight

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

    # 训练集概率（用于挑阈值）
    prob_tr = rf.predict_proba(Xtr)[:, 1]

    # 可选平滑（对时间序列样本才有意义；这里按样本顺序平滑）
    if args.smooth > 1:
        k = args.smooth
        prob_tr = np.convolve(prob_tr, np.ones(k) / k, mode="same")

    # 阈值策略
    if args.acc:
        thr = choose_threshold_by_accuracy(
            ytr, prob_tr, min_recall=args.min_recall, min_precision=args.min_precision
        )
    elif args.recall_target is not None:
        thr = choose_threshold_by_recall(ytr, prob_tr, args.recall_target)
    else:
        thr = choose_threshold_by_min_precision(ytr, prob_tr, args.min_precision)

    # 测试集评估
    prob_te = rf.predict_proba(Xte)[:, 1]
    if args.smooth > 1:
        k = args.smooth
        prob_te = np.convolve(prob_te, np.ones(k) / k, mode="same")
    yhat_te = (prob_te >= thr).astype(int)

    report = classification_report(yte, yhat_te, digits=3, output_dict=True)
    cm = confusion_matrix(yte, yhat_te).tolist()
    pr_auc_tr = pr_auc_value(ytr, prob_tr)
    pr_auc_te = pr_auc_value(yte, prob_te)

    # 特征重要性
    importances = pd.DataFrame(
        {"feature": features, "importance": rf.feature_importances_}
    ).sort_values("importance", ascending=False)
    importances.to_csv(os.path.join(args.out, "importances.csv"), index=False)

    # 保存模型与元数据
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
            "threshold_strategy": (
                "accuracy"
                if args.acc
                else ("recall_target" if args.recall_target is not None else "min_precision")
            ),
        },
    }
    joblib.dump(bundle, os.path.join(args.out, "rf_model.joblib"))

    metrics = {
        "n_train": int(len(ytr)),
        "n_test": int(len(yte)),
        "pos_rate_train": float(ytr.mean()),
        "pos_rate_test": float(yte.mean()),
        "threshold": float(thr),
        "oob_score": getattr(rf, "oob_score_", None),
        "pr_auc_train": pr_auc_tr,
        "pr_auc_test": pr_auc_te,
        "report_test": report,
        "confusion_matrix_test": cm,
    }
    with open(os.path.join(args.out, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[OK] saved: {args.out}/rf_model.joblib, {args.out}/metrics.json, {args.out}/importances.csv")
    print(
        "[TEST] precision={:.3f} recall={:.3f} f1={:.3f} thr={:.3f}".format(
            report["1"]["precision"], report["1"]["recall"], report["1"]["f1-score"], float(thr)
        )
    )


# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Train RandomForest on host-level mining features")
    # data & io
    ap.add_argument("--data", required=True, help="CSV/Parquet file or a directory containing them")
    ap.add_argument("--out", default="out_rf", help="output directory")
    ap.add_argument("--label", default="miner", help="label column name (0/1)")
    ap.add_argument("--group", default=None, help="optional group column for GroupSplit (e.g., host_id/date)")
    ap.add_argument("--drop-cols", default=None, help="extra columns to drop, comma-separated")
    ap.add_argument("--impute", default="none", choices=["none", "median", "zero"], help="missing value handling")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--random-state", type=int, default=42)

    # RF hyperparameters
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--max-depth", type=int, default=5)
    ap.add_argument("--min-samples-leaf", type=int, default=5)
    ap.add_argument("--min-samples-split", type=int, default=2)
    ap.add_argument("--max-features", default="sqrt", help='"sqrt","log2","none" or an int/float for sklearn')
    ap.add_argument("--criterion", default="gini", choices=["gini", "entropy", "log_loss"])
    ap.add_argument("--class-weight", default="none", choices=["none", "balanced"])
    ap.add_argument("--oob-score", action="store_true", help="enable OOB score (needs enough trees)")

    # threshold strategies
    ap.add_argument("--acc", action="store_true", help="choose threshold by max accuracy (optionally with floors)")
    ap.add_argument("--min-recall", type=float, default=None, help="accuracy mode: recall floor")
    ap.add_argument("--min-precision", type=float, default=0.90, help="min precision for min-precision strategy")
    ap.add_argument("--recall-target", type=float, default=None, help="target recall for recall-based threshold")
    ap.add_argument("--smooth", type=int, default=0, help="moving average window for probabilities before threshold")

    args = ap.parse_args()
    main(args)
