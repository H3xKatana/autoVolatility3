import os
import sys
import argparse
import subprocess
from datetime import datetime

def detect_memory_dump_os(volatility_path, memory_image):
    """
    
    
    Args:
        volatility_path (str): Path to Volatility executable
        memory_image (str): Path to the memory dump file
    
    Returns:
        str: Detected operating system (windows, linux, mac, or unknown)
    """
    try:
        # Windows detection first
        windows_info_cmd = [
            "python3", volatility_path, "-f", memory_image, "windows.info"
        ]
        windows_result = subprocess.run(
            windows_info_cmd, 
            capture_output=True, 
            text=True
        )
        
        # Check if Windows detection was successful
        if "Windows" in windows_result.stdout:
            return "windows"
        
        # Add placeholders for future OS detection if needed
        # Linux detection
        linux_info_cmd = [
            "python3", volatility_path, "-f", memory_image, "linux.info"
        ]
        linux_result = subprocess.run(
            linux_info_cmd, 
            capture_output=True, 
            text=True
        )
        
        if "Linux" in linux_result.stdout:
            return "linux"
        
        # Mac detection
        mac_info_cmd = [
            "python3", volatility_path, "-f", memory_image, "mac.info"
        ]
        mac_result = subprocess.run(
            mac_info_cmd, 
            capture_output=True, 
            text=True
        )
        
        if "Mac" in mac_result.stdout:
            return "mac"
        
        # If no OS detected
        return "unknown"
    
    except Exception as e:
        print(f"Error detecting memory dump OS: {e}")
        return "unknown"

def run_volatility_analysis(volatility_path, memory_image, scan_type='normal', output_dir=None):
    """
    Run Volatility analysis with specified scan type.
    
    Args:
        volatility_path (str): Path to Volatility executable
        memory_image (str): Path to the memory dump file
        scan_type (str): Type of scan to perform ('minimal', 'normal', or 'full')
        output_dir (str): Directory to save analysis results
    """
    # Create timestamped output directory if not specified
    if not output_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("/tmp", f"volatility_analysis_{timestamp}")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Scan type specific plugins
    scan_types_plugins = {
        'minimal': [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
        ],
        'normal': [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.psxview",
            "windows.modules",
            "windows.netscan",
            "windows.cmdline",
            "windows.malfind",
            "windows.dlllist",
        ],
        'full': [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.sessions"
            "windows.modules",
            "windows.dlllist",
            "windows.filescan",
            "windows.netscan",
            "windows.cmdline",
            "windows.sockets",
            "windows.malfind",
            "windows.getsids",
            "windows.scheduled_tasks",
            "windows.registry.hivelist",
            "windows.registry.printkey",
        ]
    }
    
    # Select plugins based on scan type
    plugins = scan_types_plugins.get(scan_type, scan_types_plugins['normal'])
    
    # Run selected plugins
    for plugin in plugins:
        print(f"Running plugin: {plugin}")
        
        # Create output and error files
        output_file = os.path.join(output_dir, f"{plugin.replace('.', '_')}.txt")
        error_file = os.path.join(output_dir, f"{plugin.replace('.', '_')}_errors.txt")
        
        try:
            # Run Volatility plugin
            with open(output_file, "w") as f_out, open(error_file, "w") as f_err:
                result = subprocess.run(
                    ["python3", volatility_path, "-f", memory_image, plugin],
                    stdout=f_out,
                    stderr=f_err,
                    text=True
                )
            
            # Check for errors
            if os.path.getsize(error_file) > 0:
                print(f"Warnings/Errors found for {plugin}. Check {error_file}")
            else:
                # Remove empty error files
                os.remove(error_file)
            
            print(f"Output saved to: {output_file}")
        
        except Exception as e:
            print(f"Error running plugin {plugin}: {e}")
    
    print(f"\nAnalysis complete. Results stored in: {output_dir}")
    return output_dir

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Volatility 3 Memory Forensics Automation")
    parser.add_argument('-f', '--memory-file', 
                        required=True,
                        help='Path to the memory dump file')
    parser.add_argument('-s', '--scan-type', 
                        choices=['minimal', 'normal', 'full'], 
                        default='normal', 
                        help='Type of scan to perform')
    parser.add_argument('-o', '--output-dir', 
                        help='Directory to save analysis results')
    parser.add_argument('--volatility-path', 
                        default="/opt/volatility3/vol.py",
                        help='Custom path to Volatility 3 executable')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate memory dump file exists
    if not os.path.exists(args.memory_file):
        print(f"Error: Memory dump file not found - {args.memory_file}")
        sys.exit(1)
    
    # Validate Volatility executable exists
    if not os.path.exists(args.volatility_path):
        print(f"Error: Volatility executable not found - {args.volatility_path}")
        sys.exit(1)
    
    # Detect memory dump OS (currently focusing on Windows)
    detected_os = detect_memory_dump_os(args.volatility_path, args.memory_file)
    print(f"Detected Memory Dump OS: {detected_os}")
    
    # Run analysis
    try:
        output_dir = run_volatility_analysis(
            args.volatility_path, 
            args.memory_file, 
            args.scan_type, 
            args.output_dir
        )
        print(f"\nForensic analysis complete. Detailed results are in: {output_dir}")
    
    except Exception as e:
        print(f"An error occurred during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()