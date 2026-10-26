#!/usr/bin/env python3
"""
Test enterprise signature detection in Go surface_graph engine.
Verifies that Akamai, Adobe, and Tealium signatures are properly detected.
"""

import json
import subprocess
import os
from pathlib import Path

def test_akamai_detection():
    """Test Akamai Bot Manager signature detection via cookies."""
    payload = {
        "endpoints": ["/api/test", "/admin/login"],
        "headers": {
            "Server": "AkamaiGHost",
            "Set-Cookie": "_abck=12345; bm_mi=67890; akamai_session=abcdef"
        },
        "content": "<html><body>Akamai protected content</body></html>"
    }
    
    engine_path = Path(__file__).parent.parent / "bin" / "surface_graph"
    if not engine_path.exists():
        print(f"Engine not found at {engine_path}")
        return False
    
    try:
        result = subprocess.run(
            [str(engine_path), json.dumps(payload)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = json.loads(result.stdout)
        techs = output.get("technologies", [])
        
        akamai_found = any("Akamai" in tech.get("name", "") for tech in techs)
        print(f"Akamai detection test: {'PASS' if akamai_found else 'FAIL'}")
        print(f"Detected technologies: {[t.get('name') for t in techs]}")
        return akamai_found
        
    except Exception as e:
        print(f"Akamai test failed with error: {e}")
        return False

def test_adobe_detection():
    """Test Adobe Experience Cloud signature detection via cookies."""
    payload = {
        "endpoints": ["/api/marketing", "/analytics"],
        "headers": {
            "Set-Cookie": "mbox=session123; amcv=visitor456"
        },
        "content": "<html><body>Adobe marketing content</body></html>"
    }
    
    engine_path = Path(__file__).parent.parent / "bin" / "surface_graph"
    if not engine_path.exists():
        print(f"Engine not found at {engine_path}")
        return False
    
    try:
        result = subprocess.run(
            [str(engine_path), json.dumps(payload)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = json.loads(result.stdout)
        techs = output.get("technologies", [])
        
        adobe_found = any("Adobe" in tech.get("name", "") for tech in techs)
        print(f"Adobe detection test: {'PASS' if adobe_found else 'FAIL'}")
        print(f"Detected technologies: {[t.get('name') for t in techs]}")
        return adobe_found
        
    except Exception as e:
        print(f"Adobe test failed with error: {e}")
        return False

def test_tealium_detection():
    """Test Tealium iQ Tag Management signature detection via scripts."""
    payload = {
        "endpoints": ["/tag-manager", "/analytics"],
        "headers": {},
        "content": """
        <html>
        <head>
            <script src="utag.sync"></script>
            <script src="utag.js"></script>
        </head>
        <body>Tealium managed site</body>
        </html>
        """
    }
    
    engine_path = Path(__file__).parent.parent / "bin" / "surface_graph"
    if not engine_path.exists():
        print(f"Engine not found at {engine_path}")
        return False
    
    try:
        result = subprocess.run(
            [str(engine_path), json.dumps(payload)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = json.loads(result.stdout)
        techs = output.get("technologies", [])
        
        tealium_found = any("Tealium" in tech.get("name", "") for tech in techs)
        print(f"Tealium detection test: {'PASS' if tealium_found else 'FAIL'}")
        print(f"Detected technologies: {[t.get('name') for t in techs]}")
        return tealium_found
        
    except Exception as e:
        print(f"Tealium test failed with error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("ENTERPRISE SIGNATURE DETECTION TESTS")
    print("=" * 60)
    
    results = []
    results.append(("Akamai", test_akamai_detection()))
    results.append(("Adobe", test_adobe_detection()))
    results.append(("Tealium", test_tealium_detection()))
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results:
        print(f"{name}: {'✓ PASS' if passed else '✗ FAIL'}")
    
    all_passed = all(passed for _, passed in results)
    print(f"\nOverall: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
    exit(0 if all_passed else 1)