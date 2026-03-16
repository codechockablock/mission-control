"""
Mission Control — Audit Trail Verification

Demonstrates governance chain verification for tamper-evidence.
"""

from mission_control import MissionControl, Action


def main():
    mc = MissionControl()
    session_id = mc.start_session(session_id="audit_demo")
    print(f"Session: {session_id}")

    # Run several actions to build up the chain
    commands = [
        "ls -la",
        "cat README.md",
        "python3 analyze.py --input data.csv",
        "rm -rf /tmp/scratch",  # This should be allowed (not root /)
        "git push origin main",
    ]

    for cmd in commands:
        result = mc.evaluate(Action(tool_type="shell_exec", content=cmd))
        print(f"  Step {result.recorder.step if result.recorder else '?'}: "
              f"{'PASS' if result.allowed else 'BLOCKED'} — {cmd}")

    # Verify chain integrity before closing
    print(f"\n--- Chain Verification ---")
    valid = mc.recorder.verify_chain()
    chain = mc.recorder.chain
    head = chain.head()
    print(f"  Valid: {valid}")
    print(f"  Length: {head.step}")
    print(f"  Head hash: {head.chain_hash[:32]}...")

    # End session
    summary = mc.end_session()
    print(f"\n--- Final Summary ---")
    print(f"  Duration: {summary.duration_seconds:.2f}s")
    print(f"  Steps: {summary.total_steps}")
    print(f"  Final chain hash: {summary.chain_hash[:32]}...")


if __name__ == "__main__":
    main()
