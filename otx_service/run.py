#!/usr/bin/env python3
"""
OTX Service Runner
Simple script to run the OTX ingestion service
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import main

if __name__ == "__main__":
    asyncio.run(main())