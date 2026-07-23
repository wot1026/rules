#!/usr/bin/env python3
"""
批量下载 Loon 插件（供 Fork.yml 的"批量复刻LOON模块"步骤调用）

背景：
  原本 Fork.yml 里这一步是纯 bash for 循环 + 裸 curl，逐个串行下载约174个插件，
  没有任何 TLS 指纹伪装。git.repcz.link 等域名对"看起来像脚本"的请求可能限流/
  拒绝服务，加上没有超时保护，容易导致某个请求卡住，进而拖垮整个 174 个插件的
  下载流程（实测遇到过单个请求卡住超过1分钟、后续插件全部无法下载的情况）。

改进：
  - 复用 sync_loon_unified.py 里已验证有效的下载方式：curl_cffi + impersonate="safari15_5"
    做 TLS 指纹伪装，比裸 curl 更不容易被识别为脚本请求进而限流
  - 加了显式超时(TIMEOUT)，单个插件下载失败/超时只跳过记录，不影响其余插件
  - 加了并发(MAX_WORKERS)，把原本174次串行请求的总耗时大幅压缩

用法：
  从 stdin 读取 "插件名\tURL" 格式的任务列表（一行一个），下载到 OUT_DIR。
  Fork.yml 里的调用方式：
    python3 scripts/download_plugins.py < /tmp/plugin_list.tsv
"""

import sys
import concurrent.futures
from curl_cffi import requests

LOON_UA = "Loon/586 CFNetwork/1568.100.1 Darwin/24.0.0"
OUT_DIR = "rules-repo/Loon/Plugin/Kelee"
MAX_WORKERS = 8
TIMEOUT = 15


def download_one(item):
    name, url = item
    try:
        r = requests.get(
            url,
            impersonate="safari15_5",
            headers={"User-Agent": LOON_UA},
            timeout=TIMEOUT,
        )
        if r.status_code == 200 and len(r.content) > 0:
            with open(f"{OUT_DIR}/{name}.plugin", "wb") as out:
                out.write(r.content)
            return (name, True, r.status_code)
        else:
            return (name, False, r.status_code)
    except Exception as e:
        return (name, False, str(e))


def main():
    tasks = []
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) == 2:
            tasks.append((parts[0], parts[1]))

    if not tasks:
        print("⚠️ 没有读到任何待下载任务，检查输入是否正确传入")
        sys.exit(1)

    fail_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for name, ok, info in pool.map(download_one, tasks):
            if ok:
                print(f"✅ {name}")
            else:
                fail_count += 1
                print(f"⚠️ 下载失败或超时，已跳过: {name} ({info})")

    print(f"\n完成：共 {len(tasks)} 个插件，失败 {fail_count} 个")

    # 失败数超过一半判定为异常（比如域名整体不可达），用非0退出码让上层能感知到
    if fail_count > len(tasks) / 2:
        print("❌ 失败率过高，可能是上游域名整体异常，请检查")
        sys.exit(2)


if __name__ == "__main__":
    main()
