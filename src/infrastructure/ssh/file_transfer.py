# ═══════════════════════════════════════════════════════════════
# SSH File Transfer (SFTP)
# Transfers files between local and remote servers
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime
import paramiko

from .connection_manager import SSHConnection

logger = logging.getLogger("raglox.infrastructure.ssh.transfer")


@dataclass
class TransferResult:
    """File transfer result"""
    local_path: str
    remote_path: str
    direction: str  # 'upload' or 'download'
    size_bytes: int
    success: bool
    error_message: Optional[str] = None
    transfer_time_ms: int = 0
    transferred_at: datetime = None


class SSHFileTransfer:
    """
    Handles file transfers via SFTP.
    
    Features:
    - Upload files/directories
    - Download files/directories
    - Progress tracking (future)
    - Recursive directory transfer
    - Transfer statistics
    """
    
    def __init__(self, connection: SSHConnection):
        self.connection = connection
        self._sftp_client: Optional[paramiko.SFTPClient] = None
        self._transfer_history: List[TransferResult] = []
        self._stats = {
            'total_uploads': 0,
            'total_downloads': 0,
            'total_bytes_uploaded': 0,
            'total_bytes_downloaded': 0,
            'failed_transfers': 0
        }
    
    async def _get_sftp_client(self) -> paramiko.SFTPClient:
        """Get or create SFTP client"""
        if self._sftp_client is None:
            await self.connection.ensure_connected()
            
            # Create SFTP client (blocking operation)
            self._sftp_client = await asyncio.get_event_loop().run_in_executor(
                None,
                self.connection._client.open_sftp
            )
            
            logger.info(f"SFTP client opened for {self.connection.connection_id}")
        
        return self._sftp_client
    
    async def upload_file(
        self,
        local_path: str,
        remote_path: str,
        create_dirs: bool = True
    ) -> TransferResult:
        """
        Upload a file to remote server.
        
        Args:
            local_path: Local file path
            remote_path: Remote file path
            create_dirs: Create remote directories if needed
            
        Returns:
            TransferResult
        """
        logger.info(f"Uploading {local_path} -> {remote_path}")
        
        start_time = datetime.utcnow()
        
        try:
            # Check local file exists
            if not os.path.exists(local_path):
                raise FileNotFoundError(f"Local file not found: {local_path}")
            
            # Get file size
            file_size = os.path.getsize(local_path)
            
            # Get SFTP client
            sftp = await self._get_sftp_client()
            
            # Create remote directories if needed
            if create_dirs:
                remote_dir = os.path.dirname(remote_path)
                if remote_dir:
                    await self._create_remote_directory(sftp, remote_dir)
            
            # Upload file (blocking operation)
            await asyncio.get_event_loop().run_in_executor(
                None,
                sftp.put,
                local_path,
                remote_path
            )
            
            end_time = datetime.utcnow()
            transfer_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Create result
            result = TransferResult(
                local_path=local_path,
                remote_path=remote_path,
                direction='upload',
                size_bytes=file_size,
                success=True,
                transfer_time_ms=transfer_time_ms,
                transferred_at=start_time
            )
            
            # Update statistics
            self._stats['total_uploads'] += 1
            self._stats['total_bytes_uploaded'] += file_size
            self._transfer_history.append(result)
            
            logger.info(
                f"Upload completed: {file_size} bytes in {transfer_time_ms}ms "
                f"({self._format_speed(file_size, transfer_time_ms)})"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Upload failed: {e}", exc_info=True)
            
            end_time = datetime.utcnow()
            transfer_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            result = TransferResult(
                local_path=local_path,
                remote_path=remote_path,
                direction='upload',
                size_bytes=0,
                success=False,
                error_message=str(e),
                transfer_time_ms=transfer_time_ms,
                transferred_at=start_time
            )
            
            self._stats['failed_transfers'] += 1
            
            return result
    
    async def download_file(
        self,
        remote_path: str,
        local_path: str,
        create_dirs: bool = True
    ) -> TransferResult:
        """
        Download a file from remote server.
        
        Args:
            remote_path: Remote file path
            local_path: Local file path
            create_dirs: Create local directories if needed
            
        Returns:
            TransferResult
        """
        logger.info(f"Downloading {remote_path} -> {local_path}")
        
        start_time = datetime.utcnow()
        
        try:
            # Get SFTP client
            sftp = await self._get_sftp_client()
            
            # Check remote file exists
            try:
                file_stat = await asyncio.get_event_loop().run_in_executor(
                    None,
                    sftp.stat,
                    remote_path
                )
                file_size = file_stat.st_size
            except Exception:
                raise FileNotFoundError(f"Remote file not found: {remote_path}")
            
            # Create local directories if needed
            if create_dirs:
                local_dir = os.path.dirname(local_path)
                if local_dir:
                    os.makedirs(local_dir, exist_ok=True)
            
            # Download file (blocking operation)
            await asyncio.get_event_loop().run_in_executor(
                None,
                sftp.get,
                remote_path,
                local_path
            )
            
            end_time = datetime.utcnow()
            transfer_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Create result
            result = TransferResult(
                local_path=local_path,
                remote_path=remote_path,
                direction='download',
                size_bytes=file_size,
                success=True,
                transfer_time_ms=transfer_time_ms,
                transferred_at=start_time
            )
            
            # Update statistics
            self._stats['total_downloads'] += 1
            self._stats['total_bytes_downloaded'] += file_size
            self._transfer_history.append(result)
            
            logger.info(
                f"Download completed: {file_size} bytes in {transfer_time_ms}ms "
                f"({self._format_speed(file_size, transfer_time_ms)})"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Download failed: {e}", exc_info=True)
            
            end_time = datetime.utcnow()
            transfer_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            result = TransferResult(
                local_path=local_path,
                remote_path=remote_path,
                direction='download',
                size_bytes=0,
                success=False,
                error_message=str(e),
                transfer_time_ms=transfer_time_ms,
                transferred_at=start_time
            )
            
            self._stats['failed_transfers'] += 1
            
            return result
    
    async def upload_directory(
        self,
        local_dir: str,
        remote_dir: str,
        recursive: bool = True
    ) -> List[TransferResult]:
        """
        Upload entire directory.
        
        Args:
            local_dir: Local directory path
            remote_dir: Remote directory path
            recursive: Upload subdirectories
            
        Returns:
            List of TransferResults
        """
        logger.info(f"Uploading directory {local_dir} -> {remote_dir}")
        
        results = []
        
        # Get SFTP client
        sftp = await self._get_sftp_client()
        
        # Create remote base directory
        await self._create_remote_directory(sftp, remote_dir)
        
        # Walk through local directory
        for root, dirs, files in os.walk(local_dir):
            # Calculate relative path
            rel_path = os.path.relpath(root, local_dir)
            if rel_path == '.':
                current_remote_dir = remote_dir
            else:
                current_remote_dir = os.path.join(remote_dir, rel_path).replace('\\', '/')
            
            # Create remote directory
            if current_remote_dir != remote_dir:
                await self._create_remote_directory(sftp, current_remote_dir)
            
            # Upload files
            for file in files:
                local_file = os.path.join(root, file)
                remote_file = os.path.join(current_remote_dir, file).replace('\\', '/')
                
                result = await self.upload_file(local_file, remote_file, create_dirs=False)
                results.append(result)
            
            # Stop if not recursive
            if not recursive:
                break
        
        success_count = sum(1 for r in results if r.success)
        logger.info(
            f"Directory upload completed: {success_count}/{len(results)} files successful"
        )
        
        return results
    
    async def download_directory(
        self,
        remote_dir: str,
        local_dir: str,
        recursive: bool = True
    ) -> List[TransferResult]:
        """
        Download entire directory.
        
        Args:
            remote_dir: Remote directory path
            local_dir: Local directory path
            recursive: Download subdirectories
            
        Returns:
            List of TransferResults
        """
        logger.info(f"Downloading directory {remote_dir} -> {local_dir}")
        
        results = []
        
        # Get SFTP client
        sftp = await self._get_sftp_client()
        
        # Create local base directory
        os.makedirs(local_dir, exist_ok=True)
        
        # List remote directory recursively
        remote_files = await self._list_remote_directory(sftp, remote_dir, recursive)
        
        # Download files
        for remote_file in remote_files:
            rel_path = os.path.relpath(remote_file, remote_dir)
            local_file = os.path.join(local_dir, rel_path)
            
            result = await self.download_file(remote_file, local_file, create_dirs=True)
            results.append(result)
        
        success_count = sum(1 for r in results if r.success)
        logger.info(
            f"Directory download completed: {success_count}/{len(results)} files successful"
        )
        
        return results
    
    async def _create_remote_directory(self, sftp: paramiko.SFTPClient, remote_dir: str):
        """Create remote directory recursively"""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                sftp.stat,
                remote_dir
            )
        except Exception:
            # Directory doesn't exist, create it
            parent_dir = os.path.dirname(remote_dir)
            if parent_dir and parent_dir != remote_dir:
                await self._create_remote_directory(sftp, parent_dir)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                sftp.mkdir,
                remote_dir
            )
    
    async def _list_remote_directory(
        self,
        sftp: paramiko.SFTPClient,
        remote_dir: str,
        recursive: bool
    ) -> List[str]:
        """List files in remote directory"""
        files = []
        
        try:
            items = await asyncio.get_event_loop().run_in_executor(
                None,
                sftp.listdir_attr,
                remote_dir
            )
            
            for item in items:
                full_path = os.path.join(remote_dir, item.filename).replace('\\', '/')
                
                if paramiko.sftp_attr.S_ISDIR(item.st_mode):
                    if recursive:
                        sub_files = await self._list_remote_directory(sftp, full_path, recursive)
                        files.extend(sub_files)
                else:
                    files.append(full_path)
        except Exception as e:
            logger.error(f"Failed to list directory {remote_dir}: {e}")
        
        return files
    
    def _format_speed(self, size_bytes: int, time_ms: int) -> str:
        """Format transfer speed"""
        if time_ms == 0:
            return "N/A"
        
        speed_bps = (size_bytes / time_ms) * 1000
        
        if speed_bps < 1024:
            return f"{speed_bps:.2f} B/s"
        elif speed_bps < 1024 * 1024:
            return f"{speed_bps / 1024:.2f} KB/s"
        else:
            return f"{speed_bps / (1024 * 1024):.2f} MB/s"
    
    def get_transfer_history(self, limit: int = 50) -> List[TransferResult]:
        """Get transfer history"""
        return self._transfer_history[-limit:]
    
    def get_statistics(self) -> Dict[str, any]:
        """Get transfer statistics"""
        return {
            **self._stats,
            'total_bytes_uploaded_mb': self._stats['total_bytes_uploaded'] / (1024 * 1024),
            'total_bytes_downloaded_mb': self._stats['total_bytes_downloaded'] / (1024 * 1024)
        }
    
    async def close(self):
        """Close SFTP client"""
        if self._sftp_client:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._sftp_client.close
                )
                logger.info("SFTP client closed")
            except Exception as e:
                logger.error(f"Error closing SFTP client: {e}")
            finally:
                self._sftp_client = None
