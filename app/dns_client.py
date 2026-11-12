"""权威 DNS 客户端：dnspython + TSIG 动态更新，幂等增删 TXT。

关键语义
========
* 多个申请的 TXT 值必须共存：新增前先查询，值已存在则不重复添加（RFC 2136
  对同一 owner 的 TXT 增删是按 RDATA 集合操作的，重复 add 不会产生重复值，
  但先查可让“发布注册表”与真实 DNS 保持一致，并支撑重启续办）。
* 删除只按精确 RDATA 删本模块发布过的那一个值，绝不动同名下其它 TXT。
* 所有网络调用都带超时；故障注入（丢回执 / 延迟回复）在这一层生效，
  由 worker 显式传入开关，便于在 /docs 演示里运行期切换。
"""

from __future__ import annotations

import time
from typing import Iterable

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update


class DnsError(RuntimeError):
    """DNS 操作失败（超时、拒绝、格式错误等）。"""


class DnsClient:
    def __init__(
        self,
        server: str,
        port: int,
        tsig_key_name: str,
        tsig_secret: str,
        tsig_algorithm: str,
        update_timeout: float,
        query_timeout: float,
    ):
        self.server = server
        self.port = port
        self.update_timeout = update_timeout
        self.query_timeout = query_timeout
        self.keyring = dns.tsigkeyring.from_text({tsig_key_name: tsig_secret})
        self.tsig_keyname = tsig_key_name
        self.tsig_algorithm = tsig_algorithm

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def query_txt(self, record_name: str, delay_seconds: float = 0.0) -> list[str]:
        """返回该记录名下当前全部 TXT 值（字符串列表），包含他方 TXT。"""
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        # 统一使用 FQDN（带尾点）：UpdateMessage 对相对名会再拼一次 zone，
        # 会产生 host.acme.test.acme.test 这类错误 owner
        qname = dns.name.from_text(record_name)
        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)
        query = dns.message.make_query(qname, dns.rdatatype.TXT, dns.rdataclass.IN)
        try:
            response = dns.query.udp(
                query,
                self.server,
                port=self.port,
                timeout=self.query_timeout,
            )
        except dns.exception.DNSException as exc:
            raise DnsError(f"查询 TXT 失败 {record_name}: {exc}") from exc
        if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            raise DnsError(
                f"查询 TXT 返回异常 rcode={dns.rcode.to_text(response.rcode())} "
                f"record={record_name}"
            )
        values: list[str] = []
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.TXT:
                continue
            for rdata in rrset:
                # 一条 TXT RDATA 在线上可由多个 character-string 组成（>255 字节时
                # 权威端会拆分），语义上它们拼接成同一个字符串值。
                parts: list[str] = []
                for chunk in rdata.strings:
                    parts.append(
                        chunk.decode("ascii") if isinstance(chunk, bytes) else str(chunk)
                    )
                values.append("".join(parts))
        return values

    def txt_present(self, record_name: str, txt_value: str,
                    delay_seconds: float = 0.0) -> bool:
        return txt_value in self.query_txt(record_name, delay_seconds=delay_seconds)

    # ------------------------------------------------------------------ #
    # TSIG 动态更新
    # ------------------------------------------------------------------ #
    @staticmethod
    def _fqdn(record_name: str) -> dns.name.Name:
        name = dns.name.from_text(record_name)
        if not name.is_absolute():
            name = name.concatenate(dns.name.root)
        return name

    def _send_update(self, update: dns.update.UpdateMessage,
                     delay_seconds: float) -> dns.message.Message:
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        try:
            return dns.query.tcp(
                update,
                self.server,
                port=self.port,
                timeout=self.update_timeout,
            )
        except dns.exception.DNSException as exc:
            raise DnsError(f"TSIG 更新发送失败: {exc}") from exc

    def add_txt(self, zone: str, record_name: str, txt_value: str, ttl: int,
                delay_seconds: float = 0.0) -> None:
        """幂等新增单个 TXT RDATA；已存在则视为成功（多值共存）。"""
        owner = self._fqdn(record_name)
        update = dns.update.UpdateMessage(
            zone,
            keyring=self.keyring,
            keyname=self.tsig_keyname,
            keyalgorithm=self.tsig_algorithm,
        )
        update.present(owner, dns.rdatatype.TXT)
        update.add(owner, ttl, dns.rdatatype.TXT, txt_value)
        # present 失败（记录集不存在）时退化为纯 add
        response = self._send_update(update, delay_seconds)
        if response.rcode() == dns.rcode.YXDOMAIN or response.rcode() == dns.rcode.NOERROR:
            return
        if response.rcode() == dns.rcode.NXRRSET:
            fallback = dns.update.UpdateMessage(
                zone,
                keyring=self.keyring,
                keyname=self.tsig_keyname,
                keyalgorithm=self.tsig_algorithm,
            )
            fallback.add(owner, ttl, dns.rdatatype.TXT, txt_value)
            resp2 = self._send_update(fallback, delay_seconds)
            if resp2.rcode() != dns.rcode.NOERROR:
                raise DnsError(
                    f"新增 TXT 被拒绝 rcode={dns.rcode.to_text(resp2.rcode())} "
                    f"record={record_name}"
                )
            return
        raise DnsError(
            f"新增 TXT 异常 rcode={dns.rcode.to_text(response.rcode())} "
            f"record={record_name}"
        )

    def delete_txt(self, zone: str, record_name: str, txt_value: str,
                   delay_seconds: float = 0.0) -> None:
        """只删除精确匹配的单个 TXT RDATA，保留同名其它 TXT。"""
        owner = self._fqdn(record_name)
        update = dns.update.UpdateMessage(
            zone,
            keyring=self.keyring,
            keyname=self.tsig_keyname,
            keyalgorithm=self.tsig_algorithm,
        )
        update.delete(owner, dns.rdatatype.TXT, txt_value)
        response = self._send_update(update, delay_seconds)
        if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXRRSET):
            raise DnsError(
                f"删除 TXT 异常 rcode={dns.rcode.to_text(response.rcode())} "
                f"record={record_name}"
            )

    def values_present(self, record_name: str, values: Iterable[str],
                       delay_seconds: float = 0.0) -> set[str]:
        current = set(self.query_txt(record_name, delay_seconds=delay_seconds))
        return {v for v in values if v in current}
