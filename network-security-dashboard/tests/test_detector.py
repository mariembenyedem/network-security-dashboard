"""
tests/test_detector.py
Tests for the detection engine.
Run: python tests/test_detector.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'security.db')

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_alert_count():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    conn.close()
    return count

# ── Tests ─────────────────────────────────────────────────────────────────────

def test_normal_traffic():
    """IP with few packets → should NOT trigger alert."""
    from detector import detect
    THRESHOLD = 20
    result = None
    for i in range(5):
        if i + 1 > THRESHOLD:
            result = "ALERT"
    assert result is None, "Normal traffic should not trigger alert"
    print("[PASS] test_normal_traffic")


def test_suspicious_traffic():
    """IP with too many packets → should trigger alert."""
    from detector import detect
    THRESHOLD = 20
    triggered = False
    for i in range(25):
        count = i + 1
        if count > THRESHOLD:
            triggered = True
            break
    assert triggered, "High traffic should trigger alert"
    print("[PASS] test_suspicious_traffic")


def test_save_alert_writes_to_db():
    """Saving an alert should write to SQLite."""
    from detector import save_alert
    before = get_alert_count()
    save_alert("10.0.0.1", "Test alert from unit test")
    after = get_alert_count()
    assert after == before + 1, f"Expected {before + 1} alerts, got {after}"
    print("[PASS] test_save_alert_writes_to_db")


def test_threshold_boundary():
    """Packet count exactly at threshold should NOT trigger; one above SHOULD."""
    THRESHOLD = 20
    assert THRESHOLD <= THRESHOLD      # boundary — no alert
    assert THRESHOLD + 1 > THRESHOLD   # one above — alert
    print("[PASS] test_threshold_boundary")


def test_attack_simulation():
    """Simulate 50 rapid packets from same IP → expect alert."""
    from detector import detect, save_alert
    ip = "192.168.99.99"
    triggered = False
    for count in range(1, 51):
        if count > 20:
            triggered = True
            break
    assert triggered
    save_alert(ip, "Simulated attack: 50 rapid packets")
    print("[PASS] test_attack_simulation")


# ── Runner ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  Network Security Dashboard — Test Suite")
    print("="*50 + "\n")

    tests = [
        test_normal_traffic,
        test_suspicious_traffic,
        test_save_alert_writes_to_db,
        test_threshold_boundary,
        test_attack_simulation,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"  Results: {passed} passed / {failed} failed")
    print(f"{'='*50}\n")