"""CLI entry point for mission-control."""

from __future__ import annotations

import argparse
import json
import sys
import time


def cmd_serve(args):
    """Start the Mission Control server."""
    import uvicorn
    from mission_control import MissionControl
    from mission_control.server.app import create_app

    mc = MissionControl()
    if args.constitution:
        try:
            from frontier_ops.boundary.constitution import ConstitutionSpec
            spec = getattr(ConstitutionSpec, args.constitution, None)
            if callable(spec):
                mc = MissionControl(constitution=spec())
        except Exception:
            pass

    app = create_app(mc=mc)
    print(f"Mission Control server starting on port {args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


def cmd_eval(args):
    """Evaluate a single action locally (no server needed)."""
    from mission_control import MissionControl, Action

    mc = MissionControl()
    mc.start_session()

    action = Action(tool_type=args.tool_type, content=args.content)
    result = mc.evaluate(action)

    output = {
        "allowed": result.allowed,
        "blocked_by": result.blocked_by,
        "circuit_breaker": {
            "allowed": result.breaker.allowed,
            "matched_rules": [
                {"name": r.name, "category": r.category.value, "severity": r.severity}
                for r in result.breaker.matched_rules
            ],
            "evaluation_time_us": result.breaker.evaluation_time_us,
        },
    }

    if result.recorder:
        output["flight_recorder"] = {
            "step": result.recorder.step,
            "alert_level": result.recorder.alert_level,
        }

    mc.end_session()
    print(json.dumps(output, indent=2))

    if not result.allowed:
        sys.exit(1)


def cmd_replay(args):
    """Replay a JSONL log through the pipeline."""
    from mission_control import MissionControl, Action

    mc = MissionControl()
    mc.start_session()

    blocked = 0
    total = 0

    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            tool_type = entry.get("tool_type", "unknown")
            content = entry.get("content", entry.get("text", ""))
            if not content:
                continue

            total += 1
            action = Action(tool_type=tool_type, content=content)
            result = mc.evaluate(action)

            status = "PASS" if result.allowed else "BLOCKED"
            alert = ""
            if result.recorder:
                alert = f" alert={result.recorder.alert_level:.2f}"
            print(f"[{total:4d}] {status:7s}{alert}  {content[:80]}")

            if not result.allowed:
                blocked += 1

    summary = mc.end_session()
    print(f"\n--- Replay Summary ---")
    print(f"  Total actions: {total}")
    print(f"  Blocked: {blocked}")
    if summary:
        print(f"  Verdicts: {summary.verdict_distribution}")
        print(f"  Max alert: {summary.max_alert_level:.2f}")
        print(f"  Chain hash: {summary.chain_hash[:16]}...")


def cmd_audit_verify(args):
    """Verify a governance chain."""
    from mission_control import MissionControl

    mc = MissionControl()
    mc.start_session()

    # If a file is given, replay it first to build the chain
    if args.chain_file:
        with open(args.chain_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                content = entry.get("content", entry.get("text", ""))
                if content and mc.recorder:
                    mc.recorder.record(content, entry.get("tool_type"))

    if mc.recorder:
        valid = mc.recorder.verify_chain()
        chain = mc.recorder.chain
        head = chain.head() if chain else None
        print(f"Chain valid: {valid}")
        if head:
            print(f"Chain length: {head.step}")
            print(f"Head hash: {head.chain_hash[:16]}...")
        mc.end_session()
        sys.exit(0 if valid else 1)
    else:
        print("No flight recorder available")
        mc.end_session()
        sys.exit(1)


def cmd_stats(args):
    """Show statistics."""
    from mission_control import MissionControl

    mc = MissionControl()

    if args.session:
        entries = mc.recorder._storage.get_session(args.session)
        if not entries:
            print(f"No data for session {args.session}")
            sys.exit(1)
        blocked = sum(1 for e in entries if e.get("blocked"))
        max_alert = max((e.get("alert_level", 0) for e in entries), default=0)
        verdicts = {}
        for e in entries:
            v = e.get("verdict", "UNKNOWN")
            verdicts[v] = verdicts.get(v, 0) + 1
        print(f"Session: {args.session}")
        print(f"  Steps: {len(entries)}")
        print(f"  Blocked: {blocked}")
        print(f"  Max alert: {max_alert:.2f}")
        print(f"  Verdicts: {verdicts}")
    else:
        agg = mc.recorder._storage.get_stats()
        print(f"Aggregate Statistics:")
        print(f"  Sessions: {agg.total_sessions}")
        print(f"  Steps: {agg.total_steps}")
        print(f"  Blocked: {agg.blocked_count}")
        print(f"  Max alert: {agg.max_alert_level:.2f}")


def cmd_rules_list(args):
    """List built-in circuit breaker rules."""
    from mission_control.circuit_breaker.builtins import get_default_rules, get_domain_rules, DOMAIN_RULES

    if args.domain:
        try:
            rules = get_domain_rules(args.domain)
        except ValueError as e:
            print(str(e))
            sys.exit(1)
        print(f"Rules for domain: {args.domain} ({len(rules)} rules)")
    else:
        rules = get_default_rules()
        print(f"Default rules ({len(rules)} rules)")

    print()

    # Group by category
    by_category = {}
    for r in rules:
        cat = r.category.value
        by_category.setdefault(cat, []).append(r)

    for cat, cat_rules in sorted(by_category.items()):
        print(f"  [{cat}]")
        for r in cat_rules:
            tools = ", ".join(r.tool_types) if r.tool_types else "all"
            print(f"    {r.name:40s} {r.severity:10s} ({tools})")
            print(f"      {r.description}")
        print()

    if not args.domain:
        print(f"Available domains: {', '.join(sorted(DOMAIN_RULES.keys()))}")


def cmd_dashboard(args):
    """Serve the dashboard."""
    import uvicorn
    from mission_control.dashboard.app import create_dashboard_app

    app = create_dashboard_app(api_url=f"http://localhost:{args.api_port}")
    print(f"Mission Control Dashboard on port {args.port}")
    print(f"  API server expected at http://localhost:{args.api_port}")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


def main():
    parser = argparse.ArgumentParser(
        prog="mission-control",
        description="Mission Control — Runtime Agent Safety Platform",
    )
    sub = parser.add_subparsers(dest="command")

    # serve
    p_serve = sub.add_parser("serve", help="Start the Mission Control server")
    p_serve.add_argument("--port", type=int, default=8420)
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--constitution", default=None)

    # eval
    p_eval = sub.add_parser("eval", help="Evaluate a single action")
    p_eval.add_argument("content", help="Action content to evaluate")
    p_eval.add_argument("--tool-type", default="shell_exec")

    # replay
    p_replay = sub.add_parser("replay", help="Replay a JSONL log through pipeline")
    p_replay.add_argument("file", help="JSONL file to replay")
    p_replay.add_argument("--constitution", default=None)

    # audit
    p_audit = sub.add_parser("audit", help="Audit operations")
    audit_sub = p_audit.add_subparsers(dest="audit_command")
    p_verify = audit_sub.add_parser("verify", help="Verify governance chain")
    p_verify.add_argument("chain_file", nargs="?", default=None)

    # stats
    p_stats = sub.add_parser("stats", help="Show statistics")
    p_stats.add_argument("--session", default=None)
    p_stats.add_argument("--all", action="store_true")

    # rules
    p_rules = sub.add_parser("rules", help="Rule operations")
    rules_sub = p_rules.add_subparsers(dest="rules_command")
    p_rules_list = rules_sub.add_parser("list", help="List built-in rules")
    p_rules_list.add_argument("--domain", default=None)

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Serve the dashboard")
    p_dash.add_argument("--port", type=int, default=8421)
    p_dash.add_argument("--api-port", type=int, default=8420)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "serve": cmd_serve,
        "eval": cmd_eval,
        "replay": cmd_replay,
        "stats": cmd_stats,
        "dashboard": cmd_dashboard,
    }

    if args.command == "audit":
        if args.audit_command == "verify":
            cmd_audit_verify(args)
        else:
            p_audit.print_help()
    elif args.command == "rules":
        if args.rules_command == "list":
            cmd_rules_list(args)
        else:
            p_rules.print_help()
    elif args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
