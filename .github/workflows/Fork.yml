#!/usr/bin/env python3
"""
Egern 规则转换脚本（替代 Fork.yml 里原本用一堆 sed/awk 叠加实现的转换逻辑）

原实现的问题：
  1. `sed -i -e '/^USER-AGENT/d'` 直接删除了所有 USER-AGENT 行，
     跟后面本该把它们转换成 user_agent_set 的诉求是矛盾的（这行代码
     导致 USER-AGENT 规则在早期就被吃掉，根本走不到分类那一步）。
  2. `sed -i '1i\\no_resolve: true'` 里的 `\\n` 被 sed 解析成了
     "从下一行开始插入"的语法标记，而不是字面的换行符，导致实际
     插入的文本丢了开头的 n，变成 "o_resolve: true"（笔误级别的bug）。
  3. 整套转换完全没有处理注释行(# 开头)，如果上游源文件夹带说明性
     注释（这类文件很常见，通常在文件末尾），会被当成普通文本原样
     保留在中间，破坏最终 YAML 的整洁性。
  4. 用多个独立 sed/awk 命令依次处理同一份文件，命令之间没有考虑
     相互影响，纯文本操作层面的"缝合"，没有真正按结构解析文件。

本脚本改为一次性、结构化地解析每个规则集：
  - USER-AGENT 保留并转换成 user_agent_set
  - no_resolve 判定为真时，放在文件最顶层(和 domain_set/ip_cidr_set 等平行)，
    作为影响整个文件所有IP规则的全局字段，而不是写错字段名
  - 注释行(# 开头)和空行一律跳过，不会混入规则数据
  - URL-REGEX 的值统一加双引号（沿用原逻辑的诉求）

用法：
  python3 convert_egern.py <目录>
  会遍历目录下所有 .yaml 文件（这些文件此时内容还是原始的 TYPE,VALUE 格式,
  由 Fork.yml 前面步骤从 .list 复制改名而来），原地转换成最终 Egern YAML 格式。
"""

import sys
import os
import glob

TYPE_MAP = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set",
    "IP-ASN": "asn_set",
    "URL-REGEX": "url_regex_set",
    "GEOIP": "geoip_set",
    "USER-AGENT": "user_agent_set",
}

# Egern YAML 里各分类的输出顺序（未出现的分类会被跳过）
KEY_ORDER = [
    "domain_set", "domain_suffix_set", "domain_keyword_set",
    "ip_cidr_set", "ip_cidr6_set", "asn_set", "url_regex_set",
    "geoip_set", "user_agent_set",
]

# 这几种类型的值在 YAML 里如果本身含有可能引发解析歧义的字符(比如 URL-REGEX
# 常见的正则元字符)，用单引号包一层更安全；沿用原脚本"给URL-REGEX加引号"的诉求，
# 顺带也覆盖 USER-AGENT 里常见的 * 通配符（YAML 里裸 * 是别名语法，必须加引号）
NEEDS_QUOTE_TYPES = {"URL-REGEX", "USER-AGENT"}


def needs_quote(value: str) -> bool:
    # 已经带引号的不用重复加
    if value.startswith(("'", '"')):
        return False
    # YAML 特殊起始字符，裸写会被解析器误判
    return value[:1] in ("*", "&", "!", "|", ">", "%", "@", "`", "#", "-", "?", ":", "[", "{", ",")


def quote_value(value: str) -> str:
    if needs_quote(value):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def parse_file(lines):
    """
    解析原始 TYPE,VALUE 格式的行，返回:
      buckets: {分类key: [值, ...]}
      has_no_resolve: 是否任意一条 IP-CIDR/IP-CIDR6/IP-ASN 行带 no-resolve 标记
    跳过空行和注释行(# 开头)。
    """
    buckets = {key: [] for key in TYPE_MAP.values()}
    has_no_resolve = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",", 1)
        if len(parts) != 2:
            continue

        rule_type = parts[0].strip()
        rest = parts[1].strip()

        if rule_type not in TYPE_MAP:
            continue

        # 判断这一行是否带 no-resolve 后缀（只对 IP 类规则有意义）
        if rule_type in ("IP-CIDR", "IP-CIDR6", "IP-ASN") and rest.endswith(",no-resolve"):
            has_no_resolve = True
            value = rest[: -len(",no-resolve")].strip()
        elif rule_type in ("IP-CIDR", "IP-CIDR6", "IP-ASN") and rest.endswith("no-resolve"):
            # 兼容没有逗号、直接用空格分隔的写法(极少见，但防御一下)
            has_no_resolve = True
            value = rest.rsplit(",", 1)[0].strip() if "," in rest else rest.replace("no-resolve", "").strip()
        else:
            value = rest

        if rule_type in NEEDS_QUOTE_TYPES:
            value = quote_value(value)

        buckets[TYPE_MAP[rule_type]].append(value)

    return buckets, has_no_resolve


def build_yaml(buckets: dict, has_no_resolve: bool, ruleset_name: str) -> str:
    total = sum(len(v) for v in buckets.values())

    lines = []
    lines.append(f"# 规则名称: {ruleset_name}")
    lines.append(f"# 规则统计: {total}")
    lines.append("")

    if has_no_resolve:
        lines.append("no_resolve: true")
        lines.append("")

    for key in KEY_ORDER:
        values = buckets.get(key, [])
        if not values:
            continue
        lines.append(f"{key}:")
        for v in values:
            lines.append(f"  - {v}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def convert_one(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    buckets, has_no_resolve = parse_file(lines)
    ruleset_name = os.path.basename(path)[: -len(".yaml")] if path.endswith(".yaml") else os.path.basename(path)

    yaml_content = build_yaml(buckets, has_no_resolve, ruleset_name)

    with open(path, "w", encoding="utf-8") as f:
        f.write(yaml_content)

    total = sum(len(v) for v in buckets.values())
    print(f"✅ {ruleset_name}: 共 {total} 条规则" + ("（含 no_resolve: true）" if has_no_resolve else ""))


def main():
    if len(sys.argv) != 2:
        print("用法: python3 convert_egern.py <目录>")
        sys.exit(1)

    target_dir = sys.argv[1]
    yaml_files = glob.glob(os.path.join(target_dir, "*.yaml"))

    if not yaml_files:
        print(f"⚠️ {target_dir} 目录下没有找到任何 .yaml 文件")
        return

    for path in yaml_files:
        convert_one(path)


if __name__ == "__main__":
    main()
