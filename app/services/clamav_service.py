import asyncio
import logging
from pathlib import Path
import struct
from typing import Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


class ClamAVScanError(Exception):
    """Exception raised when communication with ClamAV fails."""
    pass


class ClamAVService:
    """Async ClamAV scanner client using the INSTREAM protocol."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[int] = None,
    ):
        self.host = host or settings.CLAMAV_HOST
        self.port = port or settings.CLAMAV_PORT
        self.timeout = timeout or settings.CLAMAV_SCAN_TIMEOUT

    async def ping(self) -> bool:
        """Send PING command to verify ClamAV daemon connectivity."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=2.0,
            )
            writer.write(b"zPING\0")
            await writer.drain()
            response = await asyncio.wait_for(reader.readuntil(b"\0"), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return response.strip(b"\0") == b"PONG"
        except Exception as e:
            logger.debug("ClamAV ping failed: %s", str(e))
            return False

    async def scan_file(self, file_path: Path) -> Tuple[str, Optional[str]]:
        """Stream file to ClamAV daemon via INSTREAM command.

        Returns:
            Tuple[str, Optional[str]]:
                - ("OK", None) if file is clean
                - ("FOUND", virus_name) if malware is detected
                - ("ERROR", error_detail) on scanner error, timeout, or protocol violation
        """
        if not file_path.is_file():
            return "ERROR", f"File not found: {file_path.name}"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=float(self.timeout),
            )
        except Exception as e:
            logger.error("Failed to connect to ClamAV daemon at %s:%d: %s", self.host, self.port, str(e))
            return "ERROR", f"Connection failed: {type(e).__name__}"

        try:
            # Send INSTREAM command
            writer.write(b"zINSTREAM\0")
            await writer.drain()

            # Stream file in chunks <= 2048 bytes
            chunk_size = 2048
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    # Prefix with 4-byte big-endian unsigned length
                    header = struct.pack(">I", len(chunk))
                    writer.write(header + chunk)
                    await writer.drain()

            # Zero-length chunk signals EOF
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()

            # Read response (terminated by \0 or newline)
            response_bytes = await asyncio.wait_for(
                reader.read(4096),
                timeout=float(self.timeout),
            )
            raw_response = response_bytes.decode("utf-8", errors="replace").strip("\0\r\n ")

            if "stream: OK" in raw_response:
                return "OK", None
            elif " FOUND" in raw_response:
                # E.g. "stream: Eicar-Signature FOUND"
                parts = raw_response.split(" FOUND")[0]
                virus = parts.replace("stream: ", "").strip()
                logger.warning("ClamAV malware detected in file: signature=%s", virus)
                return "FOUND", virus
            else:
                logger.error("Unexpected ClamAV response: %s", raw_response)
                return "ERROR", f"Unexpected response: {raw_response[:64]}"

        except asyncio.TimeoutError:
            logger.error("ClamAV scan timed out after %s seconds for %s", self.timeout, file_path.name)
            return "ERROR", "Scan timed out"
        except Exception as e:
            logger.error("ClamAV scan error for %s: %s", file_path.name, str(e))
            return "ERROR", f"Scan exception: {type(e).__name__}"
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


clamav_service = ClamAVService()
