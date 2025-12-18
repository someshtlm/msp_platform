#!/usr/bin/env python3
"""
Security Reporting System - Entry Point

This is the main entry point for the security reporting system.
It imports and runs the main function from the src module.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main function
if __name__ == "__main__":
    from src.main import main
    import asyncio
    asyncio.run(main())