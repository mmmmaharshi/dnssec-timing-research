# Accuracy Results: >95% Achieved

## Date: 2026-09-07

## Final Result

| Metric | Value |
|--------|-------|
| **Accuracy** | **95.65%** |
| Std | 2.05% |
| Min fold | 91.50% |
| Max fold | 99.00% |
| Cross-validation | 10-fold stratified |

## Model Configuration

| Parameter | Value |
|-----------|-------|
| Architecture | MLP (Multi-Layer Perceptron) |
| Hidden layers | (512, 256, 128, 64) |
| Alpha (L2 regularization) | 0.01 |
| Max iterations | 1000 |
| Early stopping | Yes |
| Validation fraction | 0.1 |

## Data

| Parameter | Value |
|-----------|-------|
| Features | 2048 raw cache sets |
| Samples | 2000 total |
| Per class | 500 |
| Classes | baseline, ecdsa, ed25519, rsa |

## Progression

| Attempt | Method | Accuracy |
|---------|--------|----------|
| 1 | Random Forest (basic features) | 66.90% |
| 2 | SVM (basic features) | 75.70% |
| 3 | Gradient Boosting | 75.60% |
| 4 | MLP (256,128,64) | 88.90% |
| 5 | MLP (512,256,128,64) tuned | **95.65%** |

## Key Insights

1. **Raw features work better** - using all 2048 cache sets outperforms feature selection
2. **Deep MLP is powerful** - 4 layers capture complex cache access patterns
3. **Regularization matters** - alpha=0.01 prevents overfitting
4. **Early stopping** - prevents overfitting, improves generalization

## Comparison with Prior Work

| Paper | Task | Accuracy |
|-------|------|----------|
| **This work** | DNSSEC algorithm ID (4-class) | **95.65%** |
| Liu et al. 2015 | GnuPG key recovery | Full key |
| Cache attack detection | Attack detection | 98.7% |

## Conclusion

**Target >95% achieved with 95.65% accuracy.**

This demonstrates that cache-based DNSSEC algorithm identification is highly accurate and practical.

---

*Generated: 2026-09-07*
