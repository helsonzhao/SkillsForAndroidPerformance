#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main Thread Performance Analyzer

Extracts and analyzes main thread activity from Android logcat output to identify
performance bottlenecks, frame drops, ANR indicators, and slow operations.

Usage:
  python3 main_thread_analyzer.py logcat.txt
  python3 main_thread_analyzer.py logcat.txt --threshold 32
  python3 main_thread_analyzer.py logcat.txt --output-format json
"""

import sys
import re
import argparse
import json
from collections import defaultdict


# ============================================================================
# Handlers and Parsers
# ============================================================================

class LogParser:
    """Parses standard Android logcat formats (threadtime, time, brief, etc.)."""
    
    # Matches: 10-25 10:15:30.123 1234 5678 D Tag: Message
    # Group 1: Time, Group 2: PID, Group 3: TID, Group 4: Level, Group 5: Tag, Group 6: Msg
    THREADTIME_RE = re.compile(
        r'^\d{2}-\d{2}\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(.*?)\s*:\s+(.*)$'
    )
    
    # Matches Looper message dispatch logs
    # e.g., ">>>>> Dispatching to Handler (android.view.ViewRootImpl$ViewRootHandler) {12345} android.view.ViewRootImpl$ViewRootHandler:123"
    DISPATCH_START_RE = re.compile(r'>>>>> Dispatching to Handler \((.*?)\) \{.*?\} (.*?)(?::(\d+))?\s*$')
    
    # Matches: "<<<<< Finished to Handler (android.view.ViewRootImpl$ViewRootHandler) {12345} android.view.ViewRootImpl$ViewRootHandler"
    DISPATCH_END_RE = re.compile(r'<<<<< Finished to Handler \((.*?)\)')
    
    # Matches Choreographer skipped frames
    # e.g., "Skipped 45 frames!  The application may be doing too much work on its main thread."
    CHOREOGRAPHER_RE = re.compile(r'Skipped (\d+) frames!.*?main thread')
    
    # Matches Android ANR in ActivityManager
    ANR_RE = re.compile(r'ANR in (.*?)(?:\s|\n)')
    
    # Matches GC Logs (Dalvik/ART)
    GC_RE = re.compile(r'(?:GC_FOR_ALLOC|GC_CONCURRENT|GC_EXPLICIT|Background GC).*?paused\s+\d+ms.*?total\s+(\d+)ms')


# ============================================================================
# Analyzer Engine
# ============================================================================

class AnalyzerState:
    def __init__(self, threshold_ms):
        self.threshold_ms = threshold_ms
        self.main_tid = None
        self.current_pid = None
        
        # Tracking Looper dispatching
        self.active_dispatch = None  # Dict with start info
        self.slow_dispatches = []
        
        # Tracking frame drops
        self.frame_drops = []
        
        # Tracking ANRs
        self.anrs = []
        
        # Tracking GC pauses that affect main thread
        self.gc_pauses = []
        
        # General slow messages (custom app logs)
        self.custom_slow_logs = []
        
        # Stats
        self.total_lines_parsed = 0
        self.main_thread_lines = 0


def analyze_log_file(filepath, threshold_ms, target_pid=None):
    """
    Reads the log file line by line and extracts main thread performance issues.
    """
    state = AnalyzerState(threshold_ms)
    state.current_pid = target_pid
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line_no, line in enumerate(f, 1):
                state.total_lines_parsed += 1
                
                # Assume standard threadtime format for robust parsing
                match = LogParser.THREADTIME_RE.match(line)
                if not match:
                    continue
                
                time, pid, tid, level, tag, msg = match.groups()
                
                # Filter by PID if provided
                if state.current_pid and pid != state.current_pid:
                    continue
                
                # In standard Android apps, main thread TID equals process PID
                if tid == pid:
                    state.main_tid = tid
                    state.current_pid = pid
                    state.main_thread_lines += 1
                    
                    _process_main_thread_line(state, line_no, time, level, tag.strip(), msg.strip())
                else:
                    # Check for GC pauses (can happen on background threads but pause the world)
                    _process_bg_thread_line(state, line_no, time, pid, tid, level, tag.strip(), msg.strip())
                    
    except Exception as e:
        print(f"Error reading log file '{filepath}': {e}", file=sys.stderr)
        return None
        
    return state


def _process_main_thread_line(state, line_no, time, level, tag, msg):
    """Process a log line that belongs to the main thread."""
    
    # 1. Looper Message Dispatching
    if tag == 'Looper' or tag == 'Handler':
        # Start of dispatch
        if msg.startswith('>>>>> Dispatching'):
            m = LogParser.DISPATCH_START_RE.search(msg)
            if m:
                handler_class = m.group(1)
                callback = m.group(2) if m.group(2) else "Unknown"
                state.active_dispatch = {
                    'start_time': time,
                    'line_no': line_no,
                    'handler': handler_class,
                    'callback': callback
                }
        
        # End of dispatch
        elif msg.startswith('<<<<< Finished') and state.active_dispatch:
            # We don't have exact ms duration from simple logcat timestamps easily,
            # but Android 10+ sometimes logs "Finished... (X ms)"
            
            # Look for duration in ms
            duration_m = re.search(r'\(\s*(\d+)\s*ms\s*\)', msg)
            if duration_m:
                duration = int(duration_m.group(1))
                if duration >= state.threshold_ms:
                    state.slow_dispatches.append({
                        'duration_ms': duration,
                        'start_time': state.active_dispatch['start_time'],
                        'end_time': time,
                        'handler': state.active_dispatch['handler'],
                        'callback': state.active_dispatch['callback'],
                        'line_no': state.active_dispatch['line_no']
                    })
            # Clear active dispatch
            state.active_dispatch = None

    # 2. Choreographer Skipped Frames
    elif tag == 'Choreographer':
        m = LogParser.CHOREOGRAPHER_RE.search(msg)
        if m:
            frames = int(m.group(1))
            # 1 frame ~ 16.6ms at 60fps
            estimated_ms = frames * 16
            if estimated_ms >= state.threshold_ms:
                state.frame_drops.append({
                    'frames': frames,
                    'estimated_ms': estimated_ms,
                    'time': time,
                    'line_no': line_no
                })

    # 3. ActivityManager ANRs (sometimes logged by system server, but good to catch)
    elif tag == 'ActivityManager' and 'ANR' in msg:
        m = LogParser.ANR_RE.search(msg)
        pkg = m.group(1) if m else "Unknown"
        state.anrs.append({
            'package': pkg,
            'time': time,
            'line_no': line_no,
            'msg': msg[:100] + "..." if len(msg) > 100 else msg
        })


def _process_bg_thread_line(state, line_no, time, pid, tid, level, tag, msg):
    """Process lines from background threads (like GC) that impact main thread."""
    if tag in ('art', 'dalvikvm'):
        m = LogParser.GC_RE.search(msg)
        if m:
            duration = int(m.group(1))
            if duration >= state.threshold_ms:
                state.gc_pauses.append({
                    'duration_ms': duration,
                    'time': time,
                    'line_no': line_no,
                    'msg': msg
                })


# ============================================================================
# Output Formatters
# ============================================================================

def generate_text_report(state, top_n=10):
    """Generates a human-readable text report."""
    print("=" * 70)
    print(f"📱 Main Thread Performance Report")
    print("=" * 70)
    print(f"Total Lines Parsed: {state.total_lines_parsed}")
    print(f"Main Thread Lines:  {state.main_thread_lines}")
    if state.current_pid:
        print(f"Target Process PID: {state.current_pid}")
    print(f"Slow Threshold:     >= {state.threshold_ms}ms")
    print("-" * 70)

    # 1. ANRs
    if state.anrs:
        print(f"\n🚨 ANRs Detected ({len(state.anrs)}):")
        for anr in state.anrs[:top_n]:
            print(f"  [{anr['time']}] Line {anr['line_no']} - {anr['package']}")
            print(f"    {anr['msg']}")

    # 2. Frame Drops
    if state.frame_drops:
        print(f"\n⚠️ Frame Drops (Choreographer) ({len(state.frame_drops)}):")
        sorted_drops = sorted(state.frame_drops, key=lambda x: x['frames'], reverse=True)
        for drop in sorted_drops[:top_n]:
            print(f"  [{drop['time']}] Line {drop['line_no']} - Skipped {drop['frames']} frames (~{drop['estimated_ms']}ms)")

    # 3. Slow Looper Dispatches
    if state.slow_dispatches:
        print(f"\n🐢 Slow Message Dispatches ({len(state.slow_dispatches)}):")
        sorted_dispatches = sorted(state.slow_dispatches, key=lambda x: x['duration_ms'], reverse=True)
        for d in sorted_dispatches[:top_n]:
            print(f"  [{d['start_time']}] Line {d['line_no']} - {d['duration_ms']}ms")
            print(f"    Handler:  {d['handler']}")
            print(f"    Callback: {d['callback']}")

    # 4. GC Pauses
    if state.gc_pauses:
        print(f"\n🗑️ Heavy GC Pauses affecting performance ({len(state.gc_pauses)}):")
        sorted_gc = sorted(state.gc_pauses, key=lambda x: x['duration_ms'], reverse=True)
        for gc in sorted_gc[:top_n]:
            print(f"  [{gc['time']}] Line {gc['line_no']} - Pause: {gc['duration_ms']}ms")

    # Summary & Recommendations
    print("\n" + "=" * 70)
    print("💡 Optimization Suggestions")
    print("=" * 70)
    
    issues_found = False
    
    if state.frame_drops:
        issues_found = True
        print("- You have Choreographer frame drops. The UI thread is doing too much work.")
        print("  Suggest: Move heavy I/O, database queries, or complex processing to a background thread.")
        print("  Suggest: Simplify View hierarchies to speed up measure/layout passes.")
        
    if state.slow_dispatches:
        issues_found = True
        print("- Slow Looper dispatches detected.")
        print("  Suggest: Inspect the specific Handler/Callback listed above.")
        print("  Suggest: Ensure you aren't doing blocking operations inside UI event listeners (onClick, etc).")
        
    if state.gc_pauses:
        issues_found = True
        print("- Heavy Garbage Collection pauses found.")
        print("  Suggest: Avoid allocating objects in tight loops, especially in custom View onDraw() methods.")
        print("  Suggest: Use memory profiler to find object thrashing.")
        
    if state.anrs:
        issues_found = True
        print("- Application Not Responding (ANR) detected.")
        print("  Suggest: The main thread was blocked for > 5 seconds. Check /data/anr/traces.txt for exact stack traces.")
        
    if not issues_found:
        print("✅ No major main thread blocks detected exceeding threshold.")


def generate_json_report(state, top_n=10):
    """Generates a JSON report for CI/CD or further processing."""
    report = {
        'metadata': {
            'total_lines': state.total_lines_parsed,
            'main_thread_lines': state.main_thread_lines,
            'pid': state.current_pid,
            'threshold_ms': state.threshold_ms
        },
        'anrs': sorted(state.anrs, key=lambda x: x['time'])[:top_n],
        'frame_drops': sorted(state.frame_drops, key=lambda x: x['frames'], reverse=True)[:top_n],
        'slow_dispatches': sorted(state.slow_dispatches, key=lambda x: x['duration_ms'], reverse=True)[:top_n],
        'gc_pauses': sorted(state.gc_pauses, key=lambda x: x['duration_ms'], reverse=True)[:top_n]
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))


# ============================================================================
# Main Entry
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Main Thread Performance Analyzer: Extracts slow ops, frame drops, and ANRs from logcat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s logcat.txt                    Analyze logfile using defaults
  %(prog)s logcat.txt --pid 1234         Only analyze process 1234
  %(prog)s logcat.txt --threshold 32     Flag operations taking >32ms (default is 16ms)
  %(prog)s logcat.txt --output-format json
        """
    )
    
    parser.add_argument("log_file", help="Path to the Android logcat file.")
    parser.add_argument("--threshold", type=int, default=16, 
                        help="Slow operation threshold in milliseconds (default: 16)")
    parser.add_argument("--pid", type=str, default=None,
                        help="Analyze specific PID (if omitted, analyzer attempts auto-detection via TID==PID rules)")
    parser.add_argument("--top", type=int, default=10,
                        help="Show Top N slowest operations per category (default: 10)")
    parser.add_argument("--output-format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
                        
    args = parser.parse_args()
    
    state = analyze_log_file(args.log_file, args.threshold, args.pid)
    
    if state:
        if args.output_format == "json":
            generate_json_report(state, args.top)
        else:
            generate_text_report(state, args.top)
    else:
        sys.exit(1)
