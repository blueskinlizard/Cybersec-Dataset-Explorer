#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from scipy.stats import spearmanr
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

CICIDS_2017 = pd.read_csv("CICIDS2017_Modified.csv")

print("CICIDS2017 - FEATURE USEFULNESS & INTERPRETABILITY METRICS (PCA-based)")

FEATURE_GROUPS = {
    'Flow Duration': ['Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min'],
    'Forward Packets': ['Total Fwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 
                       'Fwd Packet Length Mean', 'Fwd Packet Length Std'],
    'Backward Packets': ['Total Backward Packets', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
                        'Bwd Packet Length Mean', 'Bwd Packet Length Std'],
    'Flow Rates': ['Flow Bytes/s', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s'],
    'Packet Timing': ['Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
                     'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min'],
    'TCP Flags': ['FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 
                 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
                 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags'],
    'Header Info': ['Fwd Header Length', 'Bwd Header Length'],
    'Packet Size': ['Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 
                   'Packet Length Std', 'Packet Length Variance', 'Average Packet Size'],
    'Bulk Transfer': ['Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
                     'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate'],
    'Subflow': ['Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes'],
    'Window Size': ['Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 
                   'min_seg_size_forward'],
    'Active/Idle': ['Active Mean', 'Active Std', 'Active Max', 'Active Min',
                   'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'],
    'Ratios': ['Down/Up Ratio'],
    'Engineered - Traffic Volume': ['packets_total', 'bytes_total', 'avg_packet_size'],
    'Engineered - Asymmetry': ['packet_ratio', 'byte_ratio', 'is_asymmetric'],
    'Engineered - Connection State': ['connection_completed', 'connection_failed'],
    'Engineered - Network Quality': ['avg_jitter', 'high_jitter'],
    'Engineered - TCP': ['has_tcp_info', 'window_size_avg'],
    'Engineered - Scanning': ['diverse_ports', 'diverse_src_ports', 'repeated_connection'],
    'Engineered - Response': ['response_body_len', 'has_response']
}

all_numeric_features = []
for group_features in FEATURE_GROUPS.values():
    all_numeric_features.extend(group_features)

available_features = [f for f in all_numeric_features if f in CICIDS_2017.columns]

print(f"\nAnalyzing {len(available_features)} features across {len(FEATURE_GROUPS)} categories")

X = CICIDS_2017[available_features].fillna(0).replace([np.inf, -np.inf], 0)
y = CICIDS_2017['is_attack'].values

sample_size = min(50000, len(X))
sample_idx = np.random.choice(len(X), sample_size, replace=False)
X_sample = X.iloc[sample_idx]
y_sample = y[sample_idx]

print(f"Using sample size: {sample_size:,} rows")

print("\n[1/6] Computing Feature Importance...")
rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
rf.fit(X_sample, y_sample)
feature_importance = pd.DataFrame({
    'feature': available_features,
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=False)

print("[2/6] Computing Mutual Information...")
mi_scores = mutual_info_classif(X_sample, y_sample, random_state=42)
mutual_info = pd.DataFrame({
    'feature': available_features,
    'mutual_info': mi_scores
}).sort_values('mutual_info', ascending=False)

print("[3/6] Computing Correlations with Target...")
correlations = []
for feat in available_features:
    try:
        corr, _ = spearmanr(X_sample[feat], y_sample)
        correlations.append({'feature': feat, 'correlation': abs(corr)})
    except:
        correlations.append({'feature': feat, 'correlation': 0})
correlation_df = pd.DataFrame(correlations).sort_values('correlation', ascending=False)

print("[4/6] Computing Statistical Separability...")
separability = []
for feat in available_features:
    benign_vals = X_sample[y_sample == 0][feat]
    attack_vals = X_sample[y_sample == 1][feat]
    
    pooled_std = np.sqrt(((len(benign_vals)-1)*benign_vals.std()**2 + 
                          (len(attack_vals)-1)*attack_vals.std()**2) / 
                         (len(benign_vals) + len(attack_vals) - 2))
    
    if pooled_std > 0:
        cohens_d = abs(benign_vals.mean() - attack_vals.mean()) / pooled_std
    else:
        cohens_d = 0
    
    separability.append({'feature': feat, 'cohens_d': cohens_d})

separability_df = pd.DataFrame(separability).sort_values('cohens_d', ascending=False)

print("[5/6] Computing PCA-based Interpretability Scores...")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_sample)

n_components = min(20, len(available_features))
pca = PCA(n_components=n_components, random_state=42)
X_pca = pca.fit_transform(X_scaled)
X_reconstructed = pca.inverse_transform(X_pca)

reconstruction_errors = []
for i, feat in enumerate(available_features):
    mse = np.mean((X_scaled[:, i] - X_reconstructed[:, i]) ** 2)
    reconstruction_errors.append({'feature': feat, 'pca_reconstruction_error': mse})

reconstruction_df = pd.DataFrame(reconstruction_errors)

print("[6/6] Computing Composite Usefulness Scores...")

metrics_combined = (feature_importance
                   .merge(mutual_info, on='feature')
                   .merge(correlation_df, on='feature')
                   .merge(separability_df, on='feature')
                   .merge(reconstruction_df, on='feature'))

for col in ['importance', 'mutual_info', 'correlation', 'cohens_d', 'pca_reconstruction_error']:
    max_val = metrics_combined[col].max()
    if max_val > 0:
        metrics_combined[f'{col}_norm'] = metrics_combined[col] / max_val
    else:
        metrics_combined[f'{col}_norm'] = 0

metrics_combined['usefulness_score'] = (
    0.30 * metrics_combined['importance_norm'] +
    0.25 * metrics_combined['mutual_info_norm'] +
    0.20 * metrics_combined['correlation_norm'] +
    0.25 * metrics_combined['cohens_d_norm']
)

metrics_combined['combined_score'] = (
    0.70 * metrics_combined['usefulness_score'] +
    0.30 * metrics_combined['pca_reconstruction_error_norm']
)

def get_feature_group(feature):
    for group_name, features in FEATURE_GROUPS.items():
        if feature in features:
            return group_name
    return 'Unknown'

metrics_combined['feature_group'] = metrics_combined['feature'].apply(get_feature_group)

metrics_combined = metrics_combined.sort_values('combined_score', ascending=False)

print("\nTOP 20 MOST USEFUL & INTERPRETABLE FEATURES (PCA-based)")

top_20 = metrics_combined.head(20)[['feature', 'feature_group', 'usefulness_score', 
                                     'pca_reconstruction_error', 'combined_score']]
print(top_20.to_string(index=False))

print("\nFEATURE GROUP ANALYSIS")

group_stats = metrics_combined.groupby('feature_group').agg({
    'usefulness_score': 'mean',
    'pca_reconstruction_error_norm': 'mean',
    'combined_score': 'mean',
    'feature': 'count'
}).rename(columns={'feature': 'num_features'})
group_stats = group_stats.sort_values('combined_score', ascending=False)
print(group_stats.round(3))

metrics_combined.to_csv('feature_metrics_cicids_pca.csv', index=False)
print(f"\nMetrics saved to 'feature_metrics_cicids_pca.csv'")

fig, axes = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle('CICIDS2017 Feature Analysis (PCA-based Interpretability)', 
             fontsize=16, fontweight='bold')

ax1 = axes[0, 0]
top_15 = metrics_combined.head(15)
colors = plt.cm.viridis(np.linspace(0, 1, len(top_15)))
ax1.barh(range(len(top_15)), top_15['combined_score'], color=colors)
ax1.set_yticks(range(len(top_15)))
ax1.set_yticklabels(top_15['feature'], fontsize=9)
ax1.set_xlabel('Combined Score', fontweight='bold')
ax1.set_title('Top 15 Features by Combined Score', fontweight='bold')
ax1.invert_yaxis()
ax1.grid(axis='x', alpha=0.3)

ax2 = axes[0, 1]
scatter = ax2.scatter(metrics_combined['usefulness_score'], 
                     metrics_combined['pca_reconstruction_error_norm'],
                     c=metrics_combined['combined_score'],
                     cmap='plasma', s=50, alpha=0.6)
ax2.set_xlabel('Usefulness Score', fontweight='bold')
ax2.set_ylabel('PCA Reconstruction Error (Interpretability)', fontweight='bold')
ax2.set_title('Usefulness vs Interpretability Trade-off', fontweight='bold')
plt.colorbar(scatter, ax=ax2, label='Combined Score')
ax2.grid(alpha=0.3)

for idx, row in metrics_combined.head(8).iterrows():
    ax2.annotate(row['feature'], 
                (row['usefulness_score'], row['pca_reconstruction_error_norm']),
                fontsize=7, alpha=0.7)

ax3 = axes[1, 0]
group_stats_plot = group_stats.sort_values('combined_score', ascending=True)
y_pos = np.arange(len(group_stats_plot))
ax3.barh(y_pos, group_stats_plot['combined_score'], alpha=0.7, color='steelblue')
ax3.set_yticks(y_pos)
ax3.set_yticklabels(group_stats_plot.index, fontsize=7)
ax3.set_xlabel('Average Combined Score', fontweight='bold')
ax3.set_title('Feature Group Performance', fontweight='bold')
ax3.grid(axis='x', alpha=0.3)

ax4 = axes[1, 1]
top_10_metrics = metrics_combined.head(10)
metrics_to_plot = ['importance_norm', 'mutual_info_norm', 'correlation_norm', 
                   'cohens_d_norm', 'pca_reconstruction_error_norm']
metric_labels = ['RF Importance', 'Mutual Info', 'Correlation', 'Cohens D', 'PCA Interp']

x = np.arange(len(top_10_metrics))
width = 0.15

for i, (metric, label) in enumerate(zip(metrics_to_plot, metric_labels)):
    ax4.bar(x + i*width, top_10_metrics[metric], width, label=label, alpha=0.8)

ax4.set_ylabel('Normalized Score', fontweight='bold')
ax4.set_title('Metric Breakdown for Top 10 Features', fontweight='bold')
ax4.set_xticks(x + width * 2)
ax4.set_xticklabels(top_10_metrics['feature'], rotation=45, ha='right', fontsize=7)
ax4.legend(fontsize=8, loc='upper right')
ax4.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig('feature_metrics_visualization_cicids_pca.png', dpi=300, bbox_inches='tight')
print("Visualization saved to 'feature_metrics_visualization_cicids_pca.png'")

plt.show()

print("\nANALYSIS COMPLETE")
print("\nKey Insights:")
print(f"- Most useful feature: {metrics_combined.iloc[0]['feature']}")
print(f"- Most interpretable group: {group_stats.index[0]}")
print(f"- Average usefulness score: {metrics_combined['usefulness_score'].mean():.3f}")
print(f"- Features with high usefulness (>0.5): {len(metrics_combined[metrics_combined['usefulness_score'] > 0.5])}")
print(f"- PCA components used: {n_components}")