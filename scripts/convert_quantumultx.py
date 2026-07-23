#!/usr/bin/env python3
"""
QuantumultX 规则转换脚本（替代 Fork.yml 里原本用 sed/awk 叠加实现的转换逻辑）

原实现（Fork.yml 的 "QuantumultX规则" step）的问题：
  1. `sed -i 's/,no-resolve//g'` 只能匹配无空格写法 ",no-resolve"。源文件里
     少数规则写的是 ", no-resolve"（逗号后带空格），这类行清理不掉，
     "no-resolve" 会原样保留在字段里，接着后面 awk 又无条件在行尾追加
     ",policy"，导致该行变成 "IP-CIDR, x.x.x.x/24, no-resolve,policy"——
     no-resolve 和 policy 的位置全部错位，QuantumultX 解析这行时会把
     no-resolve 误当成 policy 名，真正的 policy 被挤成多余字段，规则失效。
  2. 完全没有处理行内 "//" 注释（如 "DOMAIN, x.com //说明"），注释文字会
     被原样保留并夹在字段中间，同样导致 awk 追加 policy 后字段错位、规则
     解析失败。
  3. 一堆独立的 sed -e 顺序执行，互不感知彼此的处理结果，纯文本层面的
     "缝合"，没有真正按结构解析每一行。

本脚本改为一次性、结构化地解析每个规则集：
  - 先剥离行内 // 注释，再按逗号切分字段，避免注释文字污染字段
  - no-resolve 统一识别（无论源文件是否带空格），转换后作为独立字段正确
    保留在 policy 之前，即 "TYPE,VALUE,no-resolve,POLICY"（QuantumultX
    官方支持该参数，用于仅在已解析出 IP 时匹配，不触发额外 DNS 解析）
  - 规则类型名替换成 QuantumultX 语法：
      DOMAIN            -> HOST
      DOMAIN-SUFFIX     -> HOST-SUFFIX
      DOMAIN-KEYWORD    -> HOST-KEYWORD
      DOMAIN-WILDCARD   -> HOST-WILDCARD
      IP-CIDR6          -> IP6-CIDR
    （IP-CIDR / IP-ASN / GEOIP / USER-AGENT 值不变，QuantumultX 语法与
    Surge 相同）
  - PROCESS-NAME / AND / OR / NOT / DEST-PORT：QuantumultX 官方规则类型
    里没有对应写法（纯网络层代理，不支持进程名匹配；也没有逻辑组合规则
    写法），予以跳过，并汇总提示跳过了哪些类型、各多少条，避免以后上游
    新增字段类型时被静默丢弃却无人发现
  - 末尾统一追加 policy（用规则集文件名作为 policy 名，和原脚本行为一致）

用法：
  python3 convert_quantumultx.py <目录>
  会遍历目录下所有 .list 文件（内容仍是原始 Surge TYPE,VALUE 格式），
  原地转换成最终 QuantumultX 格式。
"""

import sys
import os
import glob

# Surge 类型名 -> QuantumultX 类型名。值不变的类型（IP-CIDR/IP-ASN/GEOIP/
# USER-AGENT/DOMAIN）在 QuantumultX 里也另有惯用写法，但仓库里所有下游
# (Surge/Loon/Stash 等) 都沿用大写形式，QuantumultX 客户端对大小写不敏感，
# 这里只替换官方文档里明确不同名的类型，其余保留原名。
TYPE_RENAME = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "DOMAIN-WILDCARD": "HOST-WILDCARD",
    "IP-CIDR6": "IP6-CIDR",
}

# QuantumultX 官方规则类型里没有对应写法，直接跳过整行
UNSUPPORTED_TYPES = {"PROCESS-NAME", "AND", "OR", "NOT", "DEST-PORT"}

# 支持 no-resolve 参数的类型（跟 Surge 一致：IP 类规则）
NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}


def strip_inline_comment(line: str) -> str:
    """
    剥离源文件里常见的行内注释，如：
      DOMAIN, identity.apple.com //APNs 证书请求门户
    转换成:
      DOMAIN, identity.apple.com
    只处理前面带空白（或行首）的 "//"，避免误伤 URL-REGEX 等规则里
    合法的 "https://"（此时 // 前面是字母，不会被当成注释起点）。
    """
    idx = line.find("//")
    while idx != -1:
        if idx == 0 or line[idx - 1].isspace():
            return line[:idx].rstrip()
        idx = line.find("//", idx + 1)
    return line


def convert_line(line: str, policy: str):
    """
    转换单行规则。返回转换后的行字符串，或 None（该行应跳过：空行/注释行/
    不支持的类型/无法解析的格式）。
    跳过时如果原因是"类型不支持"，通过抛出的 rule_type 由调用方统计。

    多数规则集文件只有 "TYPE,VALUE" 两段，policy 由外部统一指定（用文件名
    补全）。但仓库里也存在少数"整包"规则集（如 Ads_limbopro.list、
    Update.list），每行本身就带了第三段 policy（如
    "DOMAIN,ad.com,reject"）。这种情况如果再无脑在行尾追加文件名当 policy，
    会把原有的 policy 值（如 reject）挤成多余字段、文件名反而变成了错误的
    policy，导致规则的实际处理策略被改写——所以要先识别这种情况，保留原有
    policy，不再重复追加。
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None, None

    stripped = strip_inline_comment(stripped)
    if not stripped:
        return None, None

    parts = stripped.split(",", 1)
    if len(parts) != 2:
        # 无法识别的格式（比如源文件里偶尔混入的非 TYPE,VALUE 结构的行），
        # 原样跳过，不强行转换
        return None, None

    rule_type = parts[0].strip()
    rest = parts[1].strip()

    if rule_type in UNSUPPORTED_TYPES:
        return None, rule_type

    # 识别并剥离 no-resolve（兼容 ",no-resolve" 和 ", no-resolve" 两种写法，
    # 剥离行内注释之后不会再有 "no-resolve //说明" 这种残留情况）
    has_no_resolve = False
    if rule_type in NO_RESOLVE_TYPES:
        if rest.endswith(",no-resolve") or rest.endswith(", no-resolve"):
            has_no_resolve = True
            rest = rest.rsplit(",", 1)[0].strip()

    # 识别 rest 里是否已经自带 policy（即剥离 no-resolve 后仍有逗号分隔的
    # 第二段，例如 "118.89.204.198,reject"）。这种情况下最后一段就是
    # 该行原本指定的 policy，不用外部传入的文件名覆盖它。
    existing_policy = None
    if "," in rest:
        value_part, maybe_policy = rest.rsplit(",", 1)
        maybe_policy = maybe_policy.strip()
        # policy 名不应为空，且不应该看起来像是值的一部分被逗号误切
        # （这里只做最基本的非空校验，真实 policy 名不会是空字符串）
        if maybe_policy:
            existing_policy = maybe_policy
            rest = value_part.strip()

    new_type = TYPE_RENAME.get(rule_type, rule_type)
    effective_policy = existing_policy if existing_policy else policy

    fields = [new_type, rest]
    if has_no_resolve:
        fields.append("no-resolve")
    fields.append(effective_policy)

    return ",".join(fields), None


def convert_one(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    ruleset_name = os.path.basename(path)[: -len(".list")] if path.endswith(".list") else os.path.basename(path)

    out_lines = []
    skipped = {}
    for raw_line in lines:
        converted, skipped_type = convert_line(raw_line, ruleset_name)
        if skipped_type:
            skipped[skipped_type] = skipped.get(skipped_type, 0) + 1
        if converted is not None:
            out_lines.append(converted)

    total = len(out_lines)

    header = [f"# 规则名称: {ruleset_name}", f"# 规则统计: {total}", ""]
    content = "\n".join(header + out_lines).rstrip() + "\n"

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ {ruleset_name}: 共 {total} 条规则")
    return skipped


def main():
    if len(sys.argv) != 2:
        print("用法: python3 convert_quantumultx.py <目录>")
        sys.exit(1)

    target_dir = sys.argv[1]
    list_files = glob.glob(os.path.join(target_dir, "*.list"))

    if not list_files:
        print(f"⚠️ {target_dir} 目录下没有找到任何 .list 文件")
        return

    total_skipped = {}
    for path in list_files:
        skipped = convert_one(path)
        for rule_type, count in skipped.items():
            total_skipped[rule_type] = total_skipped.get(rule_type, 0) + count

    if total_skipped:
        print("\n⚠️ 以下规则类型 QuantumultX 官方语法不支持，已跳过（如需确认可查阅 https://github.com/crossutility/Quantumult-X）：")
        for rule_type, count in sorted(total_skipped.items(), key=lambda x: -x[1]):
            print(f"   {rule_type}: {count} 条")


if __name__ == "__main__":
    main()
