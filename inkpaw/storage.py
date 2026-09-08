import hashlib
import os
import tempfile
from pathlib import Path

from . import policy as settings

def _stage_bytes(path, data, suffix, mode):
    """Write and fsync bytes to a sibling temporary file."""
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=str(path.parent)
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return Path(temporary_name)


def _fsync_directories(directories):
    for directory in sorted({Path(path) for path in directories}, key=str):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _remove_if_present(path):
    if path is None:
        return
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def transactional_write_text(updates):
    """Publish a set of UTF-8 files together, rolling every target back on error.

    Each replacement is atomic at the filesystem level. The surrounding rollback
    journal makes a multi-file generation behave as a transaction for ordinary
    write/rename failures: either every changed target is published, or the prior
    bytes are restored.
    """
    requested = {}
    order = []
    for raw_path, content in updates:
        target = Path(raw_path).resolve()
        if not isinstance(content, str):
            raise TypeError(f"{target}: 待写内容必须是字符串")
        encoded = content.encode("utf-8")
        if target in requested:
            if requested[target] != encoded:
                raise settings.RuleValidationError(f"发布清单对 {target} 包含相互冲突的内容")
            continue
        requested[target] = encoded
        order.append(target)

    entries = []
    replaced = []
    directories = set()
    try:
        for target in order:
            target.parent.mkdir(parents=True, exist_ok=True)
            directories.add(target.parent)
            existed = target.exists()
            previous = target.read_bytes() if existed else None
            if previous == requested[target]:
                continue

            mode = (target.stat().st_mode & 0o777) if existed else 0o644
            staged = _stage_bytes(target, requested[target], ".publish.tmp", mode)
            try:
                rollback = (
                    _stage_bytes(target, previous, ".rollback.tmp", mode)
                    if previous is not None
                    else None
                )
            except Exception:
                _remove_if_present(staged)
                raise
            entries.append(
                {
                    "target": target,
                    "staged": staged,
                    "rollback": rollback,
                    "existed": existed,
                    "keep_rollback": False,
                }
            )

        for entry in entries:
            os.replace(entry["staged"], entry["target"])
            entry["staged"] = None
            replaced.append(entry)
        _fsync_directories(directories)
    except Exception as publish_error:
        rollback_errors = []
        for entry in reversed(replaced):
            try:
                if entry["existed"]:
                    os.replace(entry["rollback"], entry["target"])
                    entry["rollback"] = None
                else:
                    _remove_if_present(entry["target"])
            except Exception as rollback_error:
                entry["keep_rollback"] = True
                rollback_errors.append(
                    f"{entry['target']} (保留恢复副本 {entry['rollback']}): {rollback_error}"
                )

        for entry in entries:
            _remove_if_present(entry["staged"])
            if not entry["keep_rollback"]:
                _remove_if_present(entry["rollback"])
        try:
            _fsync_directories(directories)
        except OSError as rollback_sync_error:
            rollback_errors.append(f"目录同步: {rollback_sync_error}")

        if rollback_errors:
            details = "; ".join(rollback_errors)
            raise OSError(f"批量发布失败且回滚不完整: {details}") from publish_error
        raise

    for entry in entries:
        _remove_if_present(entry["staged"])
        _remove_if_present(entry["rollback"])
    if entries:
        _fsync_directories(directories)
    return [entry["target"] for entry in entries]


def atomic_write_text(path, content):
    """Atomically replace one UTF-8 text file while preserving its mode."""
    transactional_write_text([(path, content)])


def semantic_config_fingerprint(content):
    """Ignore comments/blank lines when deciding whether a backup is meaningful."""
    active_lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return hashlib.sha256("\n".join(active_lines).encode("utf-8")).hexdigest()


def generator_source_sha256():
    """Return a deterministic provenance fingerprint for the active generator."""
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent.parent
    inputs = sorted((root / "inkpaw").glob("*.py")) + [root / "requirements.txt"]
    inputs += sorted((root / "rules").glob("*/*.list"))
    inputs += sorted((root / "templates").glob("*.conf"))
    inputs += sorted((root / "checks").glob("*.json"))
    for path in inputs:
        if path.name == "generated.list":
            continue
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
