import logging
import json
import time
from typing import List, Optional
from pathlib import Path
import asyncio


class VolatilityAnalyzer:
    """Performs memory forensics analysis using Volatility 3 with automatic system detection"""

    def __init__(self, volatility_path, memory_image, output_dir=None):
        """Initializes the analyzer.

        Args:
            volatility_path (str): Path to Volatility 3 executable.
            memory_image (str): Path to memory dump image file.
            output_dir (Optional[str], optional): Directory to store analysis results. Defaults to None.
        """
        self.volatility_path = Path(volatility_path).resolve()
        self.memory_image = Path(memory_image).resolve()
        self.output_dir = self._setup_output_dir(output_dir)
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Sets up logging configuration."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(self.output_dir / 'volatility_analysis.log')
        file_handler.setFormatter(formatter)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)

    def _setup_output_dir(self, output_dir: Optional[str]) -> Path:
        if not output_dir:
            timestamp = time.strftime('%Y-%m-%d_%H:%M:%S')
            output_dir = Path('/tmp') / f'volatility_analysis_{timestamp}'
        else:
            output_dir = Path(output_dir)  # Ensure output_dir is a Path object
        
        output_dir.mkdir(parents=True, exist_ok=True)  # Create directory recursively
        return output_dir

    async def detect_os(self) -> str:
        os_checks = {
            "windows": "windows.info",
            "linux": "linux.info",
            "mac": "mac.info"
        }

        for os_type, plugin in os_checks.items():
            try:
                result = await self._run_command([
                    'python3', str(self.volatility_path),
                    "-f", str(self.memory_image),
                    plugin
                ])
                if os_type.capitalize() in result.stdout.decode():
                    return os_type
            except Exception as e:
                self.logger.warning(f"Error detecting {os_type} with {self.volatility_path}: {e}")

        return "unknown"

    async def _run_command(self, command: List[str]) -> asyncio.subprocess.Process:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return process

    def _get_plugins_for_scan(self, scan_type: str, scan_os: str = "windows") -> List[str]:
        """
        Reads the JSON file with predefined scan types and their associated plugins.
        :param scan_type: Name of the scan type.
        :return: List of plugins associated with the scan type.
        """
        try:
            if scan_os == "windows":
                with open('scans/windows_scan.json', 'r') as f:
                    scan_types_plugins = json.load(f)
                    return scan_types_plugins.get(scan_type, scan_types_plugins['normal'])
        except FileNotFoundError:
            self.logger.error("The file 'scans/windows_scan.json' was not found.")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing 'scans/windows_scan.json': {e}")
            raise
        except TypeError:
            self.logger.error("Got None or invalid type for 'scan_type' or 'scan_os'")
            raise

    async def _run_plugin(self, plugin: str) -> None:
        output_file = self.output_dir / f"{plugin.replace('.', '_')}.txt"
        error_file = self.output_dir / f"errors.txt"

        try:
            process = await asyncio.create_subprocess_exec(
                'python3', str(self.volatility_path),
                "-f", str(self.memory_image),
                plugin,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            output_file.write_bytes(stdout)
            if stderr:
                error_file.write_bytes(stderr)
            else:
                error_file.unlink(missing_ok=True)

            self.logger.info(f"Completed plugin: {plugin}")

        except Exception as e:
            self.logger.error(f"Error running plugin {plugin}: {e}")

    async def run_analysis(self, scan_type: str = 'normal', max_concurrent: int = 5) -> None:
        plugins = self._get_plugins_for_scan(scan_type)

        tasks = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_with_semaphore(plugin):
            async with semaphore:
                await self._run_plugin(plugin)

        for plugin in plugins:
            task = run_with_semaphore(plugin)
            tasks.append(task)

        await asyncio.gather(*tasks)
