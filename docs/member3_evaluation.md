# Member 3 model evaluation

## Dataset and preparation

SR-BH 2020 contains labeled HTTP requests and CAPEC annotations. The loader preserves the source attack categories and maps the source normal flag and attack annotations to binary labels. HttpParams supplies labeled parameter values. Its training partition is staged separately because a standalone value lacks the request context needed for serving parity. The Juice Shop baseline must carry explicit benign verification before staging and stays separate pending approval. [SR-BH 2020 data record](https://doi.org/10.7910/DVN/OGOIXX) · [HttpParams data repository](https://github.com/Morzeux/HttpParamsDataset)

Raw staging hashes the request representation with SHA-256, retains conflicting records in a quarantine, and stratifies disjoint request groups with a fixed seed. Canonical preparation uses the WAF request builder, normalizer, signature engine, and TF-IDF text extractor. It excludes headers from model text and quarantines benign signature matches, requests that cannot be represented, and identical canonical text shared across train and validation. The manifests record source and output SHA-256 values and quarantine counts. Final approval requires a separate held-out canonical partition and a disjointness check against development data.

The historical Colab run used 233,347 training rows and 50,004 calibration-validation rows from an earlier candidate. That candidate recorded 25,926 quarantined records. These historical counts do not describe a fresh run of the current preparation code.

## Model

The vectorizer fits character n-grams of lengths 2 through 5 on the training split only, uses sublinear term frequency, and caps the vocabulary at 200,000 features. Logistic Regression uses balanced class weights. Sigmoid probability calibration uses a frozen base estimator and the validation split. The independent structural extractor yields 12 numerical values, including Shannon entropy. The deployed LR inference path uses the text vectorizer.

## Historical calibration-validation diagnostics

The project’s Colab run supplied the following measurements on the same 50,004 rows used to fit probability calibration. The prediction-level output, operating threshold for this historical run, and full artifact manifest were unavailable for reproduction.

| Metric | Value |
|---|---:|
| Accuracy | 0.992441 |
| Attack precision | 0.995209 |
| Attack recall | 0.994733 |
| Attack F1 | 0.994971 |
| Macro F1 | 0.989879 |
| ROC-AUC | 0.998878 |
| False-positive rate | 0.014500 |
| False-negative rate | 0.005267 |

| Actual class | Predicted benign | Predicted attack |
|---|---:|---:|
| Benign | 12,234 | 180 |
| Attack | 198 | 37,392 |

The model flagged 180 of 12,414 benign requests and missed 198 of 37,590 attack requests. The validation set contains substantially more attack rows than benign rows. Per-category error analysis, ROC curve, reliability diagram, Brier score, calibration error, and inference latency require the underlying predictions or the verified model and validation data. The confusion matrix above can be plotted directly from the aggregate counts.

The current evaluation pipeline reports attack precision, recall, and F1, macro F1, ROC-AUC, confusion counts, false-positive and false-negative rates, Brier score, expected calibration error, and maximum calibration error. It also generates ROC, reliability, and confusion matrix plots. Its latency measures warmed single-request TF-IDF transformation and calibrated scoring on already-canonical text. Gateway latency includes parsing, normalization, rules, and proxy work outside this measurement.

## Independent evaluation and comparison

Use an approved frozen test partition, keep its labels out of training and threshold selection, and report sample counts, class balance, relevant attack categories, threshold, and dataset and model checksums. Report AI-only and end-to-end gateway results separately, since signature and policy decisions affect the latter. Compare against rule-only and LR-only baselines on the same partition. Use consistent decision units, and report both class-specific and macro metrics alongside inference scope, hardware and latency quantiles. Published WAF studies use different datasets and deployment settings, so use them to frame design and methodology. [Durmuşkaya et al., Web application firewall based on machine learning models](https://pmc.ncbi.nlm.nih.gov/articles/PMC12453791/) · [AI-IDS, real-time web intrusion detection](https://doi.org/10.1109/ACCESS.2020.2986882)

Independent results are pending approval, a verified canonical held-out split, and the trusted three-artifact export. Distribution shifts, source-label noise, and request types whose bodies cannot be represented limit generalization. The historical diagnostics cannot establish performance on unseen deployments.
