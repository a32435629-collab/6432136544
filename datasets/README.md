# Local PE training workflow

The training pipeline has two offline stages:
1. `lulz_dataset` reads a manifest and statically extracts the current 28 numeric PE features.
2. `lulz_trainer` trains the local MLP and writes a `.lznn` checkpoint plus a `.norm` sidecar.

## 1. Prepare a manifest

Create a UTF-8 CSV named `pe_manifest.csv`:

```csv
label,path
benign,C:\Windows\System32\notepad.exe
benign,C:\Windows\System32\calc.exe
malicious,D:\isolated-samples\sample-01.exe
```

Use at least seven benign and seven malicious PE files (20 total minimum). Paths may be absolute or relative to the manifest file. Paths containing commas are not supported. Labels must be exactly `benign` or `malicious`.

Only use samples whose labels are supported by trustworthy provenance. Do not assume that every file in a Windows directory is benign or that an unknown file is malicious. Keep malware samples in an isolated, access-controlled storage location; the tools read and statically parse files but never execute them.

## 2. Extract features

From the repository root:

```powershell
.\build\Release\lulz_dataset.exe .\datasets\pe_manifest.csv .\datasets\pe_training.csv
```

The output CSV contains `label` and the 28 numeric features in the exact order used by the current extractor. Categorical `binary.format` and `binary.architecture` values are intentionally excluded from this numeric MLP input.

## 3. Train

```powershell
.\build\Release\lulz_trainer.exe .\datasets\pe_training.csv .\models\lulz_pe_0.7.lznn
```

The trainer creates:
- `lulz_pe_0.7.lznn` — neural weights;
- `lulz_pe_0.7.lznn.norm` — feature means/scales calculated from the training split.

The split is stratified by label (70% train, 15% validation, 15% test), with a fixed seed. Training uses only the training split. The test split is held out for evaluation. The model uses one sigmoid output (`0 = benign`, `1 = malicious`).

## Important evaluation limits

The current split is stratified random-by-file, not grouped by malware family, publisher, or collection source. Near-duplicate samples can therefore leak across splits and inflate scores. For meaningful claims, deduplicate samples and create a family/source-grouped holdout before relying on test metrics. Small datasets are useful for exercising the pipeline, not for claiming production detection quality.

The `.norm` sidecar must remain beside its `.lznn` checkpoint. Local inference automatically applies it and checks the feature-name order. Old checkpoints without a sidecar retain their legacy raw-feature behavior.
