import concurrent.futures
import hashlib
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
import requests

from . import policy as settings
from . import storage
from . import validation

def _validate_download_url(url, source_name):
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in settings.ALLOWED_SOURCE_HOSTS:
        raise settings.RuleValidationError(
            f"{source_name}: 仅允许从受信任 HTTPS 主机下载，实际为 {url!r}"
        )


def _read_bounded_response(response, source_name):
    declared_length = response.headers.get("content-length")
    if declared_length:
        try:
            declared_size = int(declared_length)
        except ValueError as exc:
            raise settings.RuleValidationError(f"{source_name}: Content-Length 不合法") from exc
        if declared_size < 0 or declared_size > settings.MAX_SOURCE_BYTES:
            raise settings.RuleValidationError(
                f"{source_name}: 响应体声明大小 {declared_size} 超过上限 {settings.MAX_SOURCE_BYTES}"
            )

    chunks = []
    total_size = 0
    if hasattr(response, "iter_content"):
        iterator = response.iter_content(chunk_size=settings.SOURCE_DOWNLOAD_CHUNK_SIZE)
    else:
        iterator = (response.content,)
    for chunk in iterator:
        if not chunk:
            continue
        total_size += len(chunk)
        if total_size > settings.MAX_SOURCE_BYTES:
            raise settings.RuleValidationError(
                f"{source_name}: 响应体超过上限 {settings.MAX_SOURCE_BYTES} 字节"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _download_source(url, source_name):
    _validate_download_url(url, source_name)
    attempts = max(1, settings.SOURCE_DOWNLOAD_ATTEMPTS)
    last_error = None

    for attempt in range(1, attempts + 1):
        response = None
        try:
            response = requests.get(
                url,
                timeout=(settings.SOURCE_CONNECT_TIMEOUT_SECONDS, settings.SOURCE_TIMEOUT_SECONDS),
                stream=True,
                allow_redirects=True,
            )
            final_url = getattr(response, "url", None) or url
            _validate_download_url(final_url, f"{source_name} 重定向结果")

            if response.status_code == 200:
                return (
                    _read_bounded_response(response, source_name),
                    response.headers.get("content-type", ""),
                )
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                raise requests.HTTPError(f"HTTP {response.status_code}")
            raise settings.RuleValidationError(f"HTTP {response.status_code}")
        except requests.RequestException as exc:
            last_error = exc
            if attempt == attempts:
                raise
        finally:
            if response is not None and callable(getattr(response, "close", None)):
                response.close()

        time.sleep(settings.SOURCE_RETRY_BACKOFF_SECONDS * attempt)

    raise last_error  # pragma: no cover - 循环保证不会到达此处


def fetch_or_fallback(
    url,
    cache_path,
    source_name,
    validator,
    pending_cache_updates=None,
):
    cache_path = Path(cache_path)
    cached_content = None
    cached_count = None

    if cache_path.exists():
        try:
            cached_content = validation.read_text_strict(cache_path, f"{source_name} 本地缓存")
            cached_count = validator(cached_content, f"{source_name} 本地缓存")
        except (OSError, settings.RuleValidationError) as exc:
            print(f"!> {source_name} 本地缓存无效: {exc}", file=sys.stderr)
            cached_content = None
            cached_count = None

    try:
        response_bytes, content_type = _download_source(url, source_name)
        online_content = validation._decode_utf8(response_bytes, source_name)
        validator(online_content, source_name, cached_count, content_type)
        if pending_cache_updates is None:
            storage.atomic_write_text(cache_path, online_content)
        else:
            pending_cache_updates.append((cache_path, online_content))
        return True, online_content
    except (requests.RequestException, OSError, settings.RuleValidationError) as exc:
        print(f"!> {source_name} 在线内容不可用: {exc}", file=sys.stderr)

    if cached_content is not None:
        print(f"-> {source_name} 使用最后一份有效本地缓存")
        return False, cached_content
    return False, None


def fetch_sources_parallel(specifications, journal=None):
    """Fetch independent sources concurrently and preserve specification order."""
    specifications = list(specifications)
    if not specifications:
        return {}, []

    keys = [specification[0] for specification in specifications]
    if len(keys) != len(set(keys)):
        raise settings.RuleValidationError("并行下载清单包含重复键")

    def fetch_one(specification):
        key, url, cache_path, source_name, validator = specification
        local_updates = []
        result = fetch_or_fallback(
            url,
            cache_path,
            source_name,
            validator,
            local_updates,
        )
        return key, result, local_updates

    future_by_key = {}
    worker_count = min(settings.MAX_DOWNLOAD_WORKERS, len(specifications))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        for specification in specifications:
            future = executor.submit(fetch_one, specification)
            future_by_key[specification[0]] = future

        results = {}
        pending_updates = []
        for key in keys:
            returned_key, result, local_updates = future_by_key[key].result()
            results[returned_key] = result
            pending_updates.extend(local_updates)
    if journal is not None:
        for key, url, _, source_name, _ in specifications:
            online, content = results[key]
            journal.append({
                "name": source_name,
                "url": url,
                "mode": "online" if online else ("cache" if content is not None else "unavailable"),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest() if content is not None else None,
            })
    return results, pending_updates
