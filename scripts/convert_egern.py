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

字段覆盖范围（对照 Egern 官方文档 Rule Set Fields 表核实过，
https://egernapp.com/docs/configuration/rules）：
  已支持：domain_set / domain_suffix_set / domain_keyword_set /
         domain_regex_set / domain_wildcard_set / geoip_set /
         ip_cidr_set / ip_cidr6_set / asn_set / url_regex_set /
         user_agent_set / dest_port_set / protocol_set
  故意不支持（遇到会打印警告并跳过，不会静默丢弃）：
    - AND/OR/NOT 逻辑组合行：Egern 的 and_set/or_set/not_set 是嵌套的
      子规则结构，跟 Clash "AND,(cond1),(cond2)" 单行语法完全不同，
      直接字符串映射容易生成语义错误的YAML，需要人工核对后手动转换
    - PROCESS-NAME：Egern 规则集官方字段列表里没有对应项，不属于
      规则集(rule set)范畴
  HOST-SUFFIX（非标准 Clash 写法，个别规则源使用，语义等同
  DOMAIN-SUFFIX）按 domain_suffix_set 处理

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
    "HOST": "domain_set",  # 非标准写法(部分Surge规则源使用)，语义等同 DOMAIN
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "HOST-SUFFIX": "domain_suffix_set",  # 非标准写法，语义等同 DOMAIN-SUFFIX
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-REGEX": "domain_regex_set",
    "DOMAIN-WILDCARD": "domain_wildcard_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set",
    "IP-ASN": "asn_set",
    "URL-REGEX": "url_regex_set",
    "GEOIP": "geoip_set",
    "USER-AGENT": "user_agent_set",
    "DEST-PORT": "dest_port_set",
    "PROTOCOL": "protocol_set",
}

# 遇到这些行类型时不静默跳过，打印警告提示需要人工处理
KNOWN_UNSUPPORTED_TYPES = {"AND", "OR", "NOT", "PROCESS-NAME"}

# Egern YAML 里各分类的输出顺序（未出现的分类会被跳过）
KEY_ORDER = [
    "domain_set", "domain_suffix_set", "domain_keyword_set",
    "domain_regex_set", "domain_wildcard_set",
    "ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set",
    "url_regex_set", "user_agent_set", "dest_port_set", "protocol_set",
]

# 这几种类型的值在 YAML 里如果本身含有可能引发解析歧义的字符，用单引号包一层更安全：
#   - URL-REGEX / DOMAIN-REGEX: 正则元字符(^ $ . | 等)裸写容易被误判
#   - USER-AGENT / DOMAIN-WILDCARD: glob通配符常以 * 开头，YAML 里裸 * 是别名引用
#     语法，必须加引号（实测：Ads_SukkaW.list 里的 DOMAIN-WILDCARD 值如
#     "*-pcdn-*.biliapi.net" 不加引号会导致生成的YAML直接解析失败）
NEEDS_QUOTE_TYPES = {"URL-REGEX", "USER-AGENT", "DOMAIN-WILDCARD", "DOMAIN-REGEX"}


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
    解析原始规则行，返回:
      buckets: {分类key: [值, ...]}
      has_no_resolve: 是否任意一条 IP-CIDR/IP-CIDR6/IP-ASN 行带 no-resolve 标记
      skipped: [(行类型, 原始行内容), ...] 遇到已知不支持类型时记录，供调用方打印警告
    跳过空行和注释行(# 开头)。

    兼容两种输入格式：
      1) "TYPE,VALUE" 格式（Clash/Surge 常见写法，如 "DOMAIN-SUFFIX,example.com"）
      2) 裸域名格式（AdGuard/AWAvenue 等规则源常见写法，一行一个域名，无类型前缀、
         无逗号，如 ".example.com" 或 "example.com"）。这类行原先会被
         line.split(",", 1) 判定长度不为2而被直接跳过，导致整份规则集被
         静默清空且不产生任何报错或警告（已用真实数据复现：Ads_AWAvenue.list
         906行全部是这种格式，旧逻辑下会输出"规则统计: 0"）。
         处理方式：以 "." 开头的视为 domain_suffix（前导点表示匹配该域名及其
         所有子域名，语义上等同 DOMAIN-SUFFIX，去掉前导点保留域名本身）；
         不以 "." 开头、且本身像域名（不含空格、含至少一个点）的裸行视为
         domain（等同精确 DOMAIN 匹配）。

    类型名匹配大小写不敏感（已用真实数据复现：Update.list 里同一份文件混用了
    "HOST-SUFFIX,xxx"（大写）和 "host, xxx"（全小写），原逻辑只精确匹配大写，
    小写的 5 行被静默丢弃、不产生任何警告）。

    自动剥离 "TYPE,VALUE,POLICY" 三段式里的 POLICY 尾巴（已用真实数据复现：
    "HOST-SUFFIX,ads.internal.unity3d.com, reject" 这类行，原逻辑把
    ", reject" 也当成域名值的一部分保留了下来，生成 "ads.internal.unity3d.com,
    reject" 这种语法错误的域名，Egern 加载后该条规则会失效）。识别常见策略
    关键字（reject/direct/proxy 及其别名），只在最后一段确实是已知策略词时
    才剥离，避免误伤域名本身含逗号的正常场景（虽然域名不应含逗号，这里仍从
    保守角度只匹配已知策略词做剥离，而不是无条件砍掉最后一段）。
    """
    buckets = {key: [] for key in TYPE_MAP.values()}
    has_no_resolve = False
    skipped = []
    bare_domain_count = 0

    known_policy_words = {
        "reject", "direct", "proxy", "pass", "no-resolve",
        "reject-drop", "reject-tinygif", "reject-dict", "reject-array",
    }

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",", 1)

        if len(parts) != 2:
            # 没有逗号：尝试按裸域名格式处理，而不是直接丢弃
            if " " in line or "\t" in line:
                # 含空白字符，不像单纯的域名行，无法安全识别，跳过
                continue
            if line.startswith("."):
                buckets["domain_suffix_set"].append(line[1:])
                bare_domain_count += 1
            elif "." in line:
                buckets["domain_set"].append(line)
                bare_domain_count += 1
            # 其余（既没逗号也不像域名的行）静默跳过，不计入统计
            continue

        rule_type_raw = parts[0].strip()
        rule_type = rule_type_raw.upper()  # 大小写不敏感匹配
        rest = parts[1].strip()

        if rule_type not in TYPE_MAP:
            if rule_type in KNOWN_UNSUPPORTED_TYPES:
                skipped.append((rule_type_raw, line))
            continue

        # 剥离末尾的 policy 段（如 "xxx.com, reject" -> "xxx.com"），
        # 只在最后一段是已知策略词时才剥离，避免误伤
        while "," in rest:
            head, tail = rest.rsplit(",", 1)
            tail_clean = tail.strip().lower()
            if tail_clean == "no-resolve":
                # no-resolve 单独处理（下面的分支会识别），这里先跳出循环
                break
            if tail_clean in known_policy_words:
                rest = head.strip()
                continue
            break

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

    return buckets, has_no_resolve, skipped, bare_domain_count


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

    buckets, has_no_resolve, skipped, bare_domain_count = parse_file(lines)
    ruleset_name = os.path.basename(path)[: -len(".yaml")] if path.endswith(".yaml") else os.path.basename(path)

    yaml_content = build_yaml(buckets, has_no_resolve, ruleset_name)

    with open(path, "w", encoding="utf-8") as f:
        f.write(yaml_content)

    total = sum(len(v) for v in buckets.values())
    print(f"✅ {ruleset_name}: 共 {total} 条规则" + ("（含 no_resolve: true）" if has_no_resolve else ""))

    if bare_domain_count:
        print(f"  ℹ️ {ruleset_name}: 其中 {bare_domain_count} 条是裸域名格式(无类型前缀)，"
              f"已按 domain/domain_suffix 自动识别")

    if skipped:
        print(f"  ⚠️ {ruleset_name}: 有 {len(skipped)} 行因类型暂不支持自动转换而跳过，需要人工核对：")
        for rule_type, line in skipped[:5]:  # 最多列5条，避免刷屏
            print(f"      [{rule_type}] {line}")
        if len(skipped) > 5:
            print(f"      ...还有 {len(skipped) - 5} 行同类未列出")


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
