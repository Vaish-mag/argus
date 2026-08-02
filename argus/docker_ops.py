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

import subprocess
import tarfile
import io
from pathlib import Path
from typing import Optional

try:
    import docker  # docker SDK for python
    _HAVE_DOCKER = True
except ImportError:  # pragma: no cover
    _HAVE_DOCKER = False


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

    def connect_network(self, name: str, network: str) -> None:
        net = self.client.networks.get(network)
        net.connect(name)

    # ---- file transfer ----------------------------------------------------
    @staticmethod
    def _extract_stripped(stream, container_path: str, host_dir: Path) -> Path:
        """
        Extract a Docker `get_archive` tar into host_dir, stripping the leading directory
        component Docker always adds (archiving /var/www/html yields members named
        "html/...").

        Stripping it is essential: snapshot manifests are keyed on paths relative to the
        snapshot root, and if they came out as "html/index.php" while the golden manifest
        holds "index.php", every file reads as new, every snapshot is marked unclean, and
        the verified-clean restore path can never be selected. It also keeps copy_out
        symmetric with copy_in, which expects host_dir to *be* the directory contents.
        """
        host_dir = Path(host_dir)
        host_dir.mkdir(parents=True, exist_ok=True)
        top = Path(container_path.rstrip("/")).name
        raw = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=raw) as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != top or len(parts) == 1:
                    continue                      # skip the wrapper dir entry itself
                member.name = Path(*parts[1:]).as_posix()
                try:
                    tar.extract(member, host_dir, filter="data")
                except TypeError:                 # Python < 3.12 has no filter kwarg
                    tar.extract(member, host_dir)
                except Exception:
                    continue                      # forgiving: a single odd member (link,
                                                  # device node) must not abort the capture
        return host_dir

    def copy_out(self, name: str, container_path: str, host_dir: Path) -> Path:
        """Copy a directory *out* of a container to the host (for snapshots/forensics)."""
        c = self.client.containers.get(name)
        stream, _ = c.get_archive(container_path)
        return self._extract_stripped(stream, container_path, Path(host_dir))

    def seed_from_image(self, image: str, container_path: str, host_dir: Path) -> Path:
        """
        Copy a path out of an *image* (via a throwaway container) without running it.

        Used to rebuild the host web root from the known-good golden image when no
        verified-clean snapshot is available.
        """
        c = self.client.containers.create(image, command="true")
        try:
            stream, _ = c.get_archive(container_path)
            return self._extract_stripped(stream, container_path, Path(host_dir))
        finally:
            try:
                c.remove(force=True)
            except Exception:
                pass

    def copy_in(self, name: str, host_dir: Path, container_parent: str) -> None:
        """Copy a directory *into* a container (restoring verified-clean files)."""
        c = self.client.containers.get(name)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(host_dir, arcname=Path(container_parent).name)
        buf.seek(0)
        c.put_archive(str(Path(container_parent).parent), buf.read())

    # ---- health -----------------------------------------------------------
    @staticmethod
    def http_ok(url: str, timeout: float = 3.0) -> bool:
        """Health check used before promotion. Uses curl to avoid extra deps."""
        try:
            out = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time",
                 str(int(timeout)), url],
                capture_output=True, text=True, timeout=timeout + 1,
            )
            return out.stdout.strip() in {"200", "302"}
        except Exception:
            return False
