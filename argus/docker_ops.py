"""
docker_ops.py
=============
A thin, mockable seam over the Docker SDK. Every Docker interaction the healer needs
goes through here, which (a) keeps Docker specifics out of the resilience logic and
(b) lets the test-suite substitute a fake so the controller can be exercised without
a live daemon.

On a Windows-11 laptop this talks to the Docker Desktop engine exposed to WSL2, so no
special configuration is needed beyond "Use WSL2 based engine" being enabled.
"""
from __future__ import annotations

import io
import tarfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import List, Optional

from .storage import IncompleteCapture

try:
    import docker  # docker SDK for python
    _HAVE_DOCKER = True
except ImportError:  # pragma: no cover
    _HAVE_DOCKER = False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report a 302 as a 302 instead of silently following it to wherever it points."""

    def redirect_request(self, *args, **kwargs):
        return None


def _keep_permissions(member, dest_path):
    """
    tarfile's "data" filter (refuses traversal, links, devices, setuid) -- with one change.

    It also strips group/other WRITE bits from every member, which turns a world-writable
    upload directory (mode 0777) into 0755. Every snapshot then carries the damage, and the
    app can no longer write to that directory after the next restore from one. Ordinary
    permission bits are part of the content being restored, so they are re-applied; the
    setuid/setgid/sticky bits stay stripped (`member.mode` was already masked to 0o777).
    """
    safe = tarfile.data_filter(member, dest_path)
    return safe.replace(mode=member.mode & 0o777, deep=False)


class DockerOps:
    def __init__(self):
        if not _HAVE_DOCKER:
            raise RuntimeError("docker SDK not available")
        self.client = docker.from_env()

    # ---- lifecycle --------------------------------------------------------
    def run(self, image: str, name: str, network: str, ports: Optional[dict] = None,
            volumes: Optional[dict] = None):
        """
        Launch a container. `volumes` matters for restores: the protected web root is a
        bind mount, and a restored instance that silently dropped it would serve content
        from the image while the host directory (what FIM actually watches) drifted apart.
        """
        return self.client.containers.run(
            image, name=name, detach=True, network=network, ports=ports or {},
            volumes=volumes or {},
        )

    def stop_and_remove(self, name: str) -> None:
        try:
            c = self.client.containers.get(name)
            c.stop(timeout=5)
            c.remove(force=True)
        except docker.errors.NotFound:
            pass

    def commit_forensic(self, name: str, repository: str, tag: str) -> Optional[str]:
        """docker commit the live (compromised) container so its memory/fs state is frozen."""
        try:
            c = self.client.containers.get(name)
            img = c.commit(repository=repository, tag=tag)
            return img.id
        except docker.errors.NotFound:
            return None

    # ---- isolation --------------------------------------------------------
    def disconnect_network(self, name: str, network: str) -> None:
        """Cut the container's network *immediately* -- the 'isolate' step."""
        try:
            net = self.client.networks.get(network)
            net.disconnect(name, force=True)
        except docker.errors.NotFound:
            pass

    # ---- file transfer ----------------------------------------------------
    @staticmethod
    def _extract_stripped(stream, container_path: str, host_dir: Path,
                          strict: bool = True) -> Path:
        """
        Extract a Docker `get_archive` tar into host_dir, stripping the leading directory
        component Docker always adds (archiving /var/www/html yields members named
        "html/...").

        Stripping it is essential: snapshot manifests are keyed on paths relative to the
        snapshot root, and if they came out as "html/index.php" while the golden manifest
        holds "index.php", every file reads as new, every snapshot is marked unclean, and
        the verified-clean restore path can never be selected.

        The archive comes from a container that is assumed COMPROMISED, so its member
        names are attacker-controlled. Every member is vetted *before* anything is written:

          * a name containing ".." or escaping the wrapper directory is refused;
          * only regular files and directories are extracted -- symlinks, hardlinks and
            device nodes are skipped (manifests cover regular files only, and a link is
            the classic way to make a later write land outside the destination);
          * the resolved destination must stay inside host_dir;
          * permission bits are masked to 0o777 (no setuid/setgid), and where available
            tarfile's own "data" filter is applied as a second layer (see
            `_keep_permissions` for the one way it is relaxed).

        Anything refused as unsafe, or that fails to extract, is collected. With
        `strict=True` (snapshots) that raises IncompleteCapture, so a capture that quietly
        lost files can never be mistaken for a complete one; with `strict=False`
        (forensics, golden seeding) the capture is best-effort.
        """
        host_dir = Path(host_dir)
        host_dir.mkdir(parents=True, exist_ok=True)
        base = host_dir.resolve()
        top = PurePosixPath(container_path.rstrip("/")).name
        problems: List[str] = []

        raw = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=raw) as tar:
            for member in tar.getmembers():
                parts = PurePosixPath(member.name).parts
                if not parts:
                    continue
                if parts[0] != top:
                    problems.append(f"outside wrapper dir: {member.name}")
                    continue
                if len(parts) == 1:
                    continue                      # the wrapper dir entry itself
                rel = parts[1:]
                if ".." in rel or PurePosixPath(*rel).is_absolute():
                    problems.append(f"path traversal: {member.name}")
                    continue
                if not (member.isfile() or member.isdir()):
                    continue                      # link / device / fifo: never extracted
                dest = (base.joinpath(*rel)).resolve()
                if base != dest and base not in dest.parents:
                    problems.append(f"escapes destination: {member.name}")
                    continue

                member.name = PurePosixPath(*rel).as_posix()
                member.mode &= 0o777
                try:
                    if hasattr(tarfile, "data_filter"):
                        tar.extract(member, base, filter=_keep_permissions)
                    else:                         # older Python without the filter: vetted above
                        tar.extract(member, base)
                except (tarfile.TarError, OSError) as exc:
                    problems.append(f"{member.name}: {exc}")

        if problems and strict:
            raise IncompleteCapture(problems)
        return host_dir

    def copy_out(self, name: str, container_path: str, host_dir: Path,
                 strict: bool = True) -> Path:
        """Copy a directory *out* of a container to the host (for snapshots/forensics)."""
        c = self.client.containers.get(name)
        stream, _ = c.get_archive(container_path)
        return self._extract_stripped(stream, container_path, Path(host_dir), strict)

    def seed_from_image(self, image: str, container_path: str, host_dir: Path) -> Path:
        """
        Copy a path out of an *image* (via a throwaway container) without running it.

        Used to rebuild the host web root from the known-good golden image when no
        verified-clean snapshot is available.
        """
        c = self.client.containers.create(image, command="true")
        try:
            stream, _ = c.get_archive(container_path)
            return self._extract_stripped(stream, container_path, Path(host_dir),
                                          strict=False)
        finally:
            try:
                c.remove(force=True)
            except Exception:
                pass

    # ---- health -----------------------------------------------------------
    @staticmethod
    def http_ok(url: str, timeout: float = 3.0) -> bool:
        """
        Health check used before promotion.

        Pure Python on purpose: shelling out to `curl` depended on the host's PATH (and on
        `/dev/null` existing), so on Windows every check could fail for a platform reason
        and the trial would silently drop out of the results. A 200 or a 302 is healthy;
        redirects are not followed, so a 302 is judged as itself.
        """
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        try:
            with opener.open(url, timeout=timeout) as resp:
                return resp.status in {200, 302}
        except urllib.error.HTTPError as exc:
            return exc.code in {200, 302}
        except Exception:
            return False
