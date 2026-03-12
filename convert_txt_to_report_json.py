#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
from pathlib import Path
from typing import Tuple, Dict, Any, Optional


def extract_first_balanced_json_obj(text: str, start_pos: int = 0) -> str:
    """
    从 text 的 start_pos 之后，提取第一个“括号平衡”的 JSON 对象字符串（{...}）。
    通过栈深度扫描，尽量稳健地处理嵌套结构与跨行文本。
    """
    i = text.find("{", start_pos)
    if i == -1:
        raise ValueError("No '{' found for JSON object extraction.")

    depth = 0
    in_string = False
    escape = False
    started = False

    for j in range(i, len(text)):
        ch = text[j]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            # 字符串内部不处理括号
            continue
        else:
            if ch == '"':
                in_string = True
                continue

            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return text[i : j + 1]

    raise ValueError("Failed to find balanced '}' for JSON object.")


def extract_json_from_txt(txt_content: str) -> Dict[str, Any]:
    """
    优先从 ```json ... ``` 代码块里提取 JSON；
    若不存在，则兜底提取文本中第一个完整的 { ... } JSON 对象。
    """
    # 优先找 fenced code block
    fence_match = re.search(r"```json\b", txt_content, flags=re.IGNORECASE)
    if fence_match:
        # 从 ```json 后开始找第一个完整 { ... }
        start = fence_match.end()
        json_str = extract_first_balanced_json_obj(txt_content, start_pos=start)
        return json.loads(json_str)

    # 兜底：直接从全文提取第一个完整 { ... }
    json_str = extract_first_balanced_json_obj(txt_content, start_pos=0)
    return json.loads(json_str)


def decide_category_and_type(vuln_value: str) -> str:
    """
    若 vuln 含 Attack/attack => malicious，否则 anomalous
    """
    if vuln_value is None:
        return "anomalous"
    return "malicious" if "attack" in str(vuln_value).lower() else "anomalous"


def build_report_json(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 txt 中解析出的 JSON（包含 vuln/position/statement/cause 等）
    封装成目标结构：
    {
      "original_request": "",
      "detection_result": { ... , "type": "malicious|anomalous" },
      "category": "malicious|anomalous"
    }
    """
    if "vuln" not in parsed:
        raise KeyError("Missing required key: 'vuln'")

    cat = decide_category_and_type(parsed.get("vuln"))

    detection_result = dict(parsed)  # 保留原始字段（vuln/position/statement/cause 等 + 可能的其他字段）
    detection_result["type"] = cat

    return {
        "original_request": "",
        "detection_result": detection_result,
        "category": cat,
    }


def parse_request_index(filename: str) -> Optional[str]:
    """
    从 request_xx.json / request_xx.txt 中提取 xx（支持数字或其他非空序号）
    """
    m = re.match(r"^request_(.+?)\.(json|txt)$", filename)
    return m.group(1) if m else None


def main():
    parser = argparse.ArgumentParser(
        description="Convert request_xx.txt (with json block) into report JSON files."
    )
    parser.add_argument("--error_dir", default="xxx-with-GPT-5.2/", help="Directory containing request_xx.json (error logs).")
    parser.add_argument("--llm_dir", default="xxx-with-GPT-5.2/llm/", help="Directory containing request_xx.txt.")
    parser.add_argument("--out_dir", default="xxx-with-GPT-5.2/", help="Output directory to save request_xx.json.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing output files if set.")
    parser.add_argument("--error_dump", default="convert_errors.json", help="Filename to dump error indices and reasons into out_dir.")
    parser.add_argument("--skip_dump", default="convert_skipped_existing.json", help="Filename to dump skipped-existing outputs into out_dir.")
    args = parser.parse_args()

    error_dir = Path(args.error_dir)
    llm_dir = Path(args.llm_dir)
    out_dir = Path(args.out_dir)

    if not error_dir.exists():
        raise FileNotFoundError(f"error_dir not found: {error_dir}")
    if not llm_dir.exists():
        raise FileNotFoundError(f"llm_dir not found: {llm_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)

    errors = []  # [{"idx": "...", "error": "..."}]
    skipped_existing = []  # [{"idx": "...", "path": "..."}]
    converted = 0

    # 遍历 error_dir 下 request_*.json
    for err_json in sorted(error_dir.glob("request_*.json")):
        idx = parse_request_index(err_json.name)
        if idx is None:
            continue

        try:
            txt_path = llm_dir / f"request_{idx}.txt"
            if not txt_path.exists():
                raise FileNotFoundError(f"Missing txt: {txt_path}")

            out_path = out_dir / f"request_{idx}.json"
            if out_path.exists() and not args.overwrite:
                skipped_existing.append({"idx": idx, "path": str(out_path)})
                continue

            txt_content = txt_path.read_text(encoding="utf-8", errors="replace")
            parsed = extract_json_from_txt(txt_content)

            report_json = build_report_json(parsed)

            out_path.write_text(
                json.dumps(report_json, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            converted += 1

        except Exception as e:
            errors.append({"idx": idx, "error": f"{type(e).__name__}: {e}"})

    # 写出错误清单与跳过清单
    (out_dir / args.error_dump).write_text(
        json.dumps(errors, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    (out_dir / args.skip_dump).write_text(
        json.dumps(skipped_existing, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(f"[DONE] converted={converted}, errors={len(errors)}, skipped_existing={len(skipped_existing)}")
    print(f"[INFO] error list -> {out_dir / args.error_dump}")
    print(f"[INFO] skipped list -> {out_dir / args.skip_dump}")


if __name__ == "__main__":
    main()