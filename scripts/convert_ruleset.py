#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash Ruleset to Mihomo MRS Converter
======================================
本脚本用于解析 Clash/config/Online.ini 中的 ruleset 列表，
并将所有 .list 规则集通过 mihomo 命令编译为高性能的二进制 .mrs 规则集。
同时生成对应的 Clash/config/Online-MRS.ini。

特性与转换逻辑：
1. 规则分类分流与零损失保留：
   - 对每个 .list 规则文件进行逐行语法解析，分离出 DOMAIN 域名规则、IP-CIDR 网段规则与 OTHER 其它规则（如 DOMAIN-KEYWORD、GEOSITE、PROCESS-NAME、URL-REGEX 等）。
   - 若包含 DOMAIN 规则，清洗为纯域名/通配符（+.example.com / example.com / *.example.com）并生成 <规则名>-DOMAIN.mrs，在配置中使用 clash-domain: 前缀。
   - 若包含 IP-CIDR 规则，清洗为纯 CIDR 格式（无掩码单 IP 自动补全 /32 或 /128）并生成 <规则名>-IPCIDR.mrs，在配置中使用 clash-ipcidr: 前缀并追加 ',no-resolve'。
   - 若包含 OTHER 其它规则（包括 MRS domain 不支持的 DOMAIN-KEYWORD、GEOSITE 及非网络层规则），按原 list 格式写入 Clash/Mrs-Ruleset/unconverted/<原文件名>.list，并在配置中以原格式 URL 引用。
   - 根据文件实际包含的规则种类，动态将单条 ruleset 展开为 1 至 3 条 ruleset 规则，确保所有规则 100% 完整保留。
2. 保持不可转换的内置规则（如 []GEOIP,CN 或 []FINAL）及注释行完全原样不变。
3. 优先检索本地 Clash/Ruleset/ 规则，远程规则自带超时保护与重试机制，可通过 --proxy 指定 HTTP/HTTPS 代理。

代理使用示例：
   python3 scripts/convert_ruleset.py --proxy http://127.0.0.1:7890
   未指定 --proxy 时，保留 urllib 默认的环境变量及系统代理行为；不支持 SOCKS 代理。

输出目录：
   Clash/Mrs-Ruleset/ (MRS 规则文件)
   Clash/Mrs-Ruleset/unconverted/ (无法转为 MRS 的其它规则列表)
输出配置：
   Clash/config/Online-MRS.ini
"""

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_proxy_url(value: str) -> str:
    """校验 urllib 支持的 HTTP/HTTPS 代理地址。"""
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError
        if parsed.port == 0 or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(
            "代理地址须为有效的 HTTP/HTTPS URL，例如 http://127.0.0.1:7890；不支持 SOCKS 代理"
        ) from None
    return value


def parse_arguments() -> argparse.Namespace:
    # 默认以当前脚本所在目录的父目录作为仓库根目录
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="将 Clash/config/Online.ini 中的 ruleset 转换为 mihomo .mrs 二进制规则集，并生成 Online-MRS.ini"
    )
    parser.add_argument(
        "--config",
        "-f",
        type=Path,
        default=repo_root / "Clash" / "config" / "Online.ini",
        help="Online.ini 配置文件路径 (默认: Clash/config/Online.ini)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=repo_root / "Clash" / "Mrs-Ruleset",
        help="mrs 输出目录 (默认: Clash/Mrs-Ruleset)",
    )
    parser.add_argument(
        "--output-ini",
        type=Path,
        default=repo_root / "Clash" / "config" / "Online-MRS.ini",
        help="Online-MRS.ini 配置文件输出路径 (默认: Clash/config/Online-MRS.ini)",
    )
    parser.add_argument(
        "--ruleset-dir",
        type=Path,
        default=repo_root / "Clash" / "Ruleset",
        help="本地 ruleset 存放目录 (默认: Clash/Ruleset)",
    )
    parser.add_argument(
        "--mrs-base-url",
        type=str,
        default="https://raw.githubusercontent.com/evalexp/selfrules/master/Clash/Mrs-Ruleset",
        help="Online-MRS.ini 中引用的 mrs 基础 URL",
    )
    parser.add_argument(
        "--mihomo-bin",
        type=str,
        default="mihomo",
        help="mihomo 可执行文件路径或命令名 (默认: mihomo)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="下载远程规则失败时的最大重试次数 (默认: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="下载远程规则的超时时间 (秒, 默认: 15)",
    )
    parser.add_argument(
        "--proxy",
        type=parse_proxy_url,
        help="下载远程规则使用的 HTTP/HTTPS 代理 (例如 http://127.0.0.1:7890；未指定时使用默认代理设置)",
    )
    return parser.parse_args()


class RuleEntry:
    def __init__(self, raw_line: str, line_no: int, group: str, target: str):
        self.raw_line = raw_line
        self.line_no = line_no
        self.group = group
        self.target = target

    @property
    def is_list(self) -> bool:
        return self.target.lower().endswith(".list")

    @property
    def filename(self) -> str:
        # 获取文件名，若有 URL 参数则去除
        target_path = self.target.split("?")[0]
        return os.path.basename(target_path)

    @property
    def stem(self) -> str:
        base, _ = os.path.splitext(self.filename)
        return base


def check_mihomo(mihomo_bin: str) -> bool:
    """检查 mihomo 是否可用"""
    bin_path = shutil.which(mihomo_bin)
    if not bin_path:
        return False
    try:
        proc = subprocess.run(
            [mihomo_bin, "-v"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def parse_ini_rulesets(config_path: Path) -> List[RuleEntry]:
    """
    从 Online.ini 中解析所有未被注释的生效 ruleset 条目。
    任何以 ';' 或 '#' 开头的注释行均直接忽略。
    """
    if not config_path.exists():
        raise FileNotFoundError(f"未找到配置文件: {config_path}")

    entries = []
    # 正则匹配形如: ruleset=Group,Target
    pattern = re.compile(r"^ruleset=([^,]+),(.*)$")

    with open(config_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            # 忽略以 ; 或 # 开头的注释行
            if line_str.startswith(";") or line_str.startswith("#"):
                continue
            match = pattern.match(line_str)
            if match:
                group, target = match.groups()
                entries.append(
                    RuleEntry(
                        raw_line=line_str,
                        line_no=idx,
                        group=group.strip(),
                        target=target.strip(),
                    )
                )
    return entries


def fetch_file(
    target: str,
    local_ruleset_dir: Path,
    dest_path: Path,
    retries: int = 3,
    timeout: int = 15,
    proxy: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    获取规则文件内容并写入 dest_path。
    优先检索本地 Clash/Ruleset/ 目录，若无则从 URL 下载。
    返回: (成功标志, 描述信息)
    """
    filename = os.path.basename(target.split("?")[0])

    # 1. 优先检查本地是否存在同名规则文件
    local_file = local_ruleset_dir / filename
    if local_file.is_file():
        try:
            shutil.copy2(local_file, dest_path)
            return True, f"本地文件 ({local_file.name})"
        except Exception as e:
            return False, f"复制本地规则失败: {e}"

    # 2. 如果是网络 URL，则下载
    if target.startswith("http://") or target.startswith("https://"):
        req = urllib.request.Request(
            target,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        open_url = urllib.request.urlopen
        if proxy:
            handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            open_url = urllib.request.build_opener(handler).open
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                with open_url(req, timeout=timeout) as response:
                    content = response.read()
                with open(dest_path, "wb") as f:
                    f.write(content)
                return True, f"远程下载成功 (尝试 {attempt}/{retries})"
            except Exception as e:
                last_err = e
                time.sleep(1)
        return False, f"下载失败 ({last_err})"

    return False, f"未知的规则路径或无法访问: {target}"


def extract_rules(source_file: Path) -> Tuple[List[str], List[str], List[str]]:
    """
    解析规则源文件，准确分离出 DOMAIN 规则、IP-CIDR 规则与 OTHER 其它规则。
    - DOMAIN 规则：清洗为纯域名/通配符格式（+.example.com / example.com / *.example.com）
    - IP-CIDR 规则：清洗提取出纯 CIDR 字符串（单 IP 自动补齐 /32 或 /128）
    - OTHER 规则：保留原行格式（如 DOMAIN-KEYWORD、GEOSITE、PROCESS-NAME、URL-REGEX 等）
    返回: (domain_rules, ip_cidrs, other_rules)
    """
    domain_rules = []
    ip_cidrs = []
    other_rules = []

    with open(source_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw_line = line.strip()
            if not raw_line or raw_line.startswith("#") or raw_line.startswith(";"):
                continue

            # 去除行内注释 (支持 // 与 #)
            line_no_comment = raw_line.split("//")[0].strip()
            if not line_no_comment.upper().startswith("URL-REGEX"):
                cleaned_line = line_no_comment.split("#")[0].strip()
            else:
                cleaned_line = line_no_comment

            if not cleaned_line:
                continue

            parts = [p.strip() for p in cleaned_line.split(",")]
            prefix = parts[0].upper()

            # ---------------------------------------------------------
            # 1. 域名规则处理
            # ---------------------------------------------------------
            if prefix == "DOMAIN-SUFFIX" and len(parts) >= 2 and parts[1]:
                # 转换前缀为 '+.'，支持域名本身及其所有子域名匹配
                dom = parts[1].lstrip(".")
                domain_rules.append(f"+.{dom}")

            elif prefix == "DOMAIN" and len(parts) >= 2 and parts[1]:
                # 精确匹配域名，去除前缀
                domain_rules.append(parts[1])

            elif prefix == "DOMAIN-WILDCARD" and len(parts) >= 2 and parts[1]:
                # 通配符域名，去除前缀保留原样 (如 *.example.com)
                domain_rules.append(parts[1])

            elif prefix in ("DOMAIN-KEYWORD", "GEOSITE"):
                # MRS DomainSet 并不支持关键字或 GEOSITE 匹配，必须保留在 classical 规则中
                other_rules.append(cleaned_line)

            elif prefix.startswith("+."):
                domain_rules.append(parts[0])

            elif prefix.startswith("."):
                dom = parts[0].lstrip(".")
                domain_rules.append(f"+.{dom}")

            # ---------------------------------------------------------
            # 2. IP-CIDR 规则处理
            # ---------------------------------------------------------
            elif prefix in ("IP-CIDR", "IP-CIDR6") and len(parts) >= 2 and parts[1]:
                ip_str = parts[1]
                # 补全可能缺失掩码的单 IP
                if "/" not in ip_str:
                    try:
                        addr = ipaddress.ip_address(ip_str)
                        ip_str = f"{ip_str}/32" if addr.version == 4 else f"{ip_str}/128"
                    except ValueError:
                        pass
                ip_cidrs.append(ip_str)

            elif "/" in parts[0] and not prefix.startswith(("PROCESS", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT")):
                try:
                    ipaddress.ip_network(parts[0], strict=False)
                    ip_cidrs.append(parts[0])
                except ValueError:
                    other_rules.append(cleaned_line)

            # ---------------------------------------------------------
            # 3. 其它潜在纯域名或单 IP（无逗号）
            # ---------------------------------------------------------
            elif len(parts) == 1:
                item = parts[0]
                try:
                    addr = ipaddress.ip_address(item)
                    ip_cidrs.append(f"{item}/32" if addr.version == 4 else f"{item}/128")
                except ValueError:
                    if item.startswith("+."):
                        domain_rules.append(item)
                    elif item.startswith("."):
                        domain_rules.append(f"+.{item.lstrip('.')}")
                    elif "." in item:
                        domain_rules.append(item)
                    else:
                        other_rules.append(cleaned_line)

            # ---------------------------------------------------------
            # 4. 其它类型规则（PROCESS-NAME, URL-REGEX, IP-ASN 等）
            # ---------------------------------------------------------
            else:
                other_rules.append(cleaned_line)

    # 去重并保持顺序
    return list(dict.fromkeys(domain_rules)), list(dict.fromkeys(ip_cidrs)), list(dict.fromkeys(other_rules))


def convert_entry(
    mihomo_bin: str,
    source_file: Path,
    stem: str,
    filename: str,
    output_dir: Path,
    unconverted_dir: Path,
    temp_dir: Path,
) -> Tuple[List[Tuple[str, str, int, int]], List[str]]:
    """
    针对单个规则文件进行分类转换与提取：
    - 若含 domain 规则，生成 <stem>-DOMAIN.mrs
    - 若含 ipcidr 规则，生成 <stem>-IPCIDR.mrs
    - 若含 other 规则，直接按原 list 写入 unconverted/<filename>
    返回: (成功生成的列表 [(item_name, behavior, file_size, rule_count)], 错误列表)
    """
    domain_rules, ip_cidrs, other_rules = extract_rules(source_file)
    generated = []
    errors = []

    if not domain_rules and not ip_cidrs and not other_rules:
        errors.append("未在规则集中检测到任何有效规则")
        return generated, errors

    # 1. 编译 DOMAIN 规则
    if domain_rules:
        dom_text = temp_dir / f"{stem}_domain.txt"
        dom_mrs = output_dir / f"{stem}-DOMAIN.mrs"
        try:
            with open(dom_text, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(domain_rules) + "\n")

            proc = subprocess.run(
                [mihomo_bin, "convert-ruleset", "domain", "text", str(dom_text), str(dom_mrs)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0 and dom_mrs.exists() and dom_mrs.stat().st_size > 0:
                generated.append((f"{stem}-DOMAIN.mrs", "domain", dom_mrs.stat().st_size, len(domain_rules)))
            else:
                if dom_mrs.exists():
                    dom_mrs.unlink(missing_ok=True)
                err = (proc.stderr or proc.stdout).strip().splitlines()[0] if (proc.stderr or proc.stdout) else "未知错误"
                errors.append(f"DOMAIN 规则转换失败: {err}")
        except Exception as e:
            if dom_mrs.exists():
                dom_mrs.unlink(missing_ok=True)
            errors.append(f"DOMAIN 规则转换异常: {e}")

    # 2. 编译 IP-CIDR 规则
    if ip_cidrs:
        ip_text = temp_dir / f"{stem}_ipcidr.txt"
        ip_mrs = output_dir / f"{stem}-IPCIDR.mrs"
        try:
            with open(ip_text, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(ip_cidrs) + "\n")

            proc = subprocess.run(
                [mihomo_bin, "convert-ruleset", "ipcidr", "text", str(ip_text), str(ip_mrs)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0 and ip_mrs.exists() and ip_mrs.stat().st_size > 0:
                generated.append((f"{stem}-IPCIDR.mrs", "ipcidr", ip_mrs.stat().st_size, len(ip_cidrs)))
            else:
                if ip_mrs.exists():
                    ip_mrs.unlink(missing_ok=True)
                err = (proc.stderr or proc.stdout).strip().splitlines()[0] if (proc.stderr or proc.stdout) else "未知错误"
                errors.append(f"IPCIDR 规则转换失败: {err}")
        except Exception as e:
            if ip_mrs.exists():
                ip_mrs.unlink(missing_ok=True)
            errors.append(f"IPCIDR 规则转换异常: {e}")

    # 3. 处理 OTHER 无法转为 MRS 的规则 (存为原格式 list)
    if other_rules:
        unconv_file = unconverted_dir / filename
        try:
            with open(unconv_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"# 内容: {stem} (无法转换为 MRS 的其它规则, 如 DOMAIN-KEYWORD / GEOSITE / PROCESS-NAME / URL-REGEX 等)\n")
                f.write(f"# 数量: {len(other_rules)} 条\n")
                f.write("\n".join(other_rules) + "\n")
            generated.append((filename, "unconverted", unconv_file.stat().st_size, len(other_rules)))
        except Exception as e:
            errors.append(f"保存 OTHER 规则失败: {e}")

    return generated, errors


def generate_mrs_ini(
    config_path: Path,
    output_ini_path: Path,
    converted_rules: Dict[str, List[Tuple[str, str]]],
    mrs_base_url: str,
) -> int:
    """
    根据原始 Online.ini 生成 Online-MRS.ini：
    - domain 规则: 添加 clash-domain: 前缀并引用 -DOMAIN.mrs
    - ipcidr 规则: 添加 clash-ipcidr: 前缀并追加 ',no-resolve'，引用 -IPCIDR.mrs
    - unconverted 规则: 按原 Online.ini 格式引用 unconverted/<原文件名>.list
    - 未能转换的规则（如 []GEOIP,CN 或 []FINAL）、注释行、分组配置等保持不变。
    返回: 展开生成的规则数量
    """
    pattern = re.compile(r"^ruleset=([^,]+),(.*)$")
    generated_count = 0
    output_lines = []

    clean_base_url = mrs_base_url.rstrip("/")

    with open(config_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()

            # 注释行保持原样
            if stripped.startswith(";") or stripped.startswith("#"):
                output_lines.append(line)
                continue

            match = pattern.match(stripped)
            if match:
                group = match.group(1).strip()
                rest = match.group(2).strip()

                parts = [p.strip() for p in rest.split(",")]
                target = parts[0]
                extra_args = parts[1:]

                # 若该规则目标已成功编译/提取，进行地址替换与展开
                if target in converted_rules and converted_rules[target]:
                    items = converted_rules[target]
                    newline_char = "\r\n" if line.endswith("\r\n") else "\n"

                    for item_name, behavior in items:
                        if behavior == "domain":
                            prefix_tag = "clash-domain:"
                            new_target = f"{prefix_tag}{clean_base_url}/{item_name}"
                            new_rest = ",".join([new_target] + extra_args)
                        elif behavior == "ipcidr":
                            prefix_tag = "clash-ipcidr:"
                            new_target = f"{prefix_tag}{clean_base_url}/{item_name}"
                            cur_extra = list(extra_args)
                            if "no-resolve" not in cur_extra:
                                cur_extra.append("no-resolve")
                            new_rest = ",".join([new_target] + cur_extra)
                        elif behavior == "unconverted":
                            # 格式和 Online.ini 中一样，直接引用 unconverted list 路径
                            new_target = f"{clean_base_url}/unconverted/{item_name}"
                            new_rest = ",".join([new_target] + extra_args)
                        else:
                            continue

                        output_lines.append(f"ruleset={group},{new_rest}{newline_char}")
                        generated_count += 1
                    continue

            # 其余行（如非 ruleset 配置、不可转换的规则）保持不变
            output_lines.append(line)

    output_ini_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_ini_path, "w", encoding="utf-8") as f:
        f.writelines(output_lines)

    return generated_count


def main():
    args = parse_arguments()

    print("=" * 68)
    print("        Clash Ruleset -> Mihomo MRS 智能分流转换工具")
    print("=" * 68)
    print(f"原始配置:     {args.config}")
    print(f"mrs 目录:     {args.output_dir}")
    print(f"新配置文件:   {args.output_ini}")
    print(f"mrs 引用基址: {args.mrs_base_url}")
    print("-" * 68)

    # 1. 检查 mihomo 可用性
    if not check_mihomo(args.mihomo_bin):
        print(f"❌ 错误: 未找到可用的 mihomo 命令 ('{args.mihomo_bin}')。")
        print("请确保已安装 mihomo 并加入系统 PATH，或通过 --mihomo-bin 参数指定其完整路径。")
        sys.exit(1)

    # 2. 确保输出目录存在，并清理旧文件
    args.output_dir.mkdir(parents=True, exist_ok=True)
    unconverted_dir = args.output_dir / "unconverted"
    unconverted_dir.mkdir(parents=True, exist_ok=True)

    # 清理 output_dir 中的旧 .mrs 文件
    for f in args.output_dir.glob("*.mrs"):
        f.unlink(missing_ok=True)
    # 清理 unconverted_dir 中的旧 .list 文件
    for f in unconverted_dir.glob("*.list"):
        f.unlink(missing_ok=True)

    # 3. 解析生效的 ruleset
    try:
        rulesets = parse_ini_rulesets(args.config)
    except Exception as e:
        print(f"❌ 读取配置文件失败: {e}")
        sys.exit(1)

    print(f"共发现 {len(rulesets)} 条生效的 ruleset 规则定义。\n")

    success_entries = []
    skipped_list = []
    failed_list = []
    # 记录 target -> List[Tuple[item_name, behavior]] 的映射
    converted_rules: Dict[str, List[Tuple[str, str]]] = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_dir_path = Path(tmpdir)

        for entry in rulesets:
            rule_id = f"{entry.group} -> {entry.target}"

            # 检查是否为 .list 规则
            if not entry.is_list:
                reason = "内置非列表规则 (例如 []GEOIP 或 []FINAL)"
                print(f"⏩ [跳过] {rule_id}")
                print(f"    原因: {reason}\n")
                skipped_list.append((entry, reason))
                continue

            # 4. 获取规则源文件
            tmp_source = tmp_dir_path / entry.filename
            fetched, fetch_msg = fetch_file(
                entry.target,
                args.ruleset_dir,
                tmp_source,
                retries=args.retries,
                timeout=args.timeout,
                proxy=args.proxy,
            )
            if not fetched:
                print(f"❌ [获取失败] {entry.filename}")
                print(f"    详情: {fetch_msg}\n")
                failed_list.append((entry, fetch_msg))
                continue

            # 5. 执行分类提取、MRS 编译与未转换规则归档
            generated, errors = convert_entry(
                args.mihomo_bin,
                tmp_source,
                entry.stem,
                entry.filename,
                args.output_dir,
                unconverted_dir,
                tmp_dir_path,
            )

            if generated:
                info_tags = [f"{g[0]} ({g[1]}: {g[3]}条, {g[2]:,}B)" for g in generated]
                print(f"✅ [转换成功] {entry.filename} -> {', '.join(info_tags)}")
                print(f"    来源: {fetch_msg}\n")
                success_entries.append((entry, generated))
                converted_rules[entry.target] = [(g[0], g[1]) for g in generated]
            else:
                reason = "; ".join(errors) if errors else "无有效可转换规则"
                print(f"⏩ [跳过] {entry.filename}")
                print(f"    原因: {reason}\n")
                skipped_list.append((entry, reason))

    # 6. 生成 Online-MRS.ini
    print("-" * 68)
    print("正在生成 Online-MRS.ini 配置文件...")
    generated_rules_num = generate_mrs_ini(
        args.config,
        args.output_ini,
        converted_rules,
        args.mrs_base_url,
    )
    print(f"✅ 已成功生成: {args.output_ini}")
    print(f"   展开后 ruleset 总条数: {generated_rules_num} 条\n")

    # 7. 打印总结报表
    print("=" * 68)
    print("                      转换结果汇总")
    print("=" * 68)
    print(f"源 ruleset 条数:  {len(rulesets)}")
    print(f"源文件成功转换:   {len(success_entries)} 个")
    print(f"源文件跳过条数:   {len(skipped_list)} 个")
    print(f"源文件获取失败:   {len(failed_list)} 个")

    mrs_count = sum(1 for _, g in success_entries for _, beh, _, _ in g if beh in ("domain", "ipcidr"))
    unconv_count = sum(1 for _, g in success_entries for _, beh, _, _ in g if beh == "unconverted")

    print(f"生成 MRS 文件总数: {mrs_count} 个")
    print(f"未转换保留 list:  {unconv_count} 个 (位于 {unconverted_dir.name}/)")
    print(f"Online-MRS 配置条目: {generated_rules_num} 条")
    print("-" * 68)

    if skipped_list:
        print("\n【跳过无法转换的规则 (保持原样)】:")
        for idx, (entry, reason) in enumerate(skipped_list, 1):
            name = entry.filename if entry.is_list else entry.target
            print(f"  {idx}. {name} [{entry.group}]")
            print(f"     原因: {reason}")

    if success_entries:
        print("\n【生成规则文件明细】:")
        count = 1
        for entry, gen_list in success_entries:
            for item_name, beh, sz, rc in gen_list:
                beh_tag = "MRS-DOMAIN" if beh == "domain" else ("MRS-IPCIDR" if beh == "ipcidr" else "UNCONVERTED")
                print(f"  {count:2d}. {item_name:<30} ({beh_tag:<11}) [{rc:>5} 条规则, {sz:>7,} 字节] - [{entry.group}]")
                count += 1

    print("\n完成！")
    print(f"  MRS 规则集输出目录:     {args.output_dir.resolve()}")
    print(f"  未转换列表输出目录:     {unconverted_dir.resolve()}")
    print(f"  MRS 配置文件路径:       {args.output_ini.resolve()}")
    print("=" * 68)


if __name__ == "__main__":
    main()
