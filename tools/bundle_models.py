#!/usr/bin/env python3
"""Assemble the tracked classifier and CNN artifacts into one runtime model directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "detector_lgb_v1_cnn/detector_lgb_v1.onnx": "model.onnx",
    "detector_lgb_v1_cnn/metadata.json": "metadata.json",
    "detector_cnn_v1/cnn_embedding.onnx": "cnn_embedding.onnx",
    "detector_cnn_v1/cnn_metadata.json": "cnn_metadata.json",
    "detector_cnn_sim_v1/cnn_sim_embedding.onnx": "cnn_sim_embedding.onnx",
    "detector_cnn_sim_v1/sim_metadata.json": "sim_metadata.json",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "config/models")
    args = parser.parse_args()
    sources = [(ROOT / "ml/models" / source, args.output / target) for source, target in FILES.items()]
    for source, target in sources:
        if not source.is_file():
            raise FileNotFoundError(source)
        if target.exists() and target.read_bytes() != source.read_bytes():
            raise FileExistsError(f"refusing to overwrite a different model artifact: {target}")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for source, target in sources:
        if not target.exists():
            shutil.copyfile(source, target)
        manifest[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output.resolve())


if __name__ == "__main__":
    main()
