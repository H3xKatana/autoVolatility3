#!/usr/bin/env python3

import asyncio
import logging 
import sys  
import argparse
from analyzer import VolatilityAnalyzer



def main():
    parser = argparse.ArgumentParser(description="Enhanced Volatility 3 Memory Forensics Automation")
    parser.add_argument('-f', '--memory-file', required=True, help='Path to memory dump')
    parser.add_argument('-s', '--scan-type', choices=['minimal', 'normal', 'full','triage','forensics','registry','malware','network'], 
                      default='normal', help='Scan type')
    parser.add_argument('-o', '--output-dir', help='Output directory')
    parser.add_argument('--volatility-path', default="/opt/volatility3/vol.py",
                      help='Volatility 3 executable path')
    parser.add_argument('-t','--threads', type=int, default=5,
                      help='max number of threads')
    
    args = parser.parse_args()
    
    try:
        analyzer = VolatilityAnalyzer(
            args.volatility_path,
            args.memory_file,
            args.output_dir
        )
        
        asyncio.run(analyzer.run_analysis(
            scan_type=args.scan_type,
            max_concurrent=args.threads
        ))
        
    except Exception as e:
        logging.error(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

