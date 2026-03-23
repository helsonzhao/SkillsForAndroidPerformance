---
name: main-thread-analyze
description: |
  Extract main thread logs from Android logcat output or log files, identify performance bottlenecks
  such as slow operations, frame drops, ANR indicators, and long message dispatching.
  Provides a detailed analysis report with optimization suggestions.
  Use this skill when the user wants to analyze main thread performance, find jank sources,
  or debug ANR issues from log files.
tags:
  - android
  - performance
  - main-thread
  - jank
  - anr
  - logcat
  - optimization
dependencies:
  - Python 3.6+
---

# Main Thread Performance Analyzer

Extracts and analyzes main thread activity from Android logcat output or log files to identify performance bottlenecks, frame drops, ANR indicators, and slow operations.

## 🎯 Core Features

1. **Main Thread Extraction**: Filters log lines belonging to the main (UI) thread
2. **Slow Operation Detection**: Identifies operations exceeding a configurable threshold
3. **Frame Drop Analysis**: Detects Choreographer frame skip warnings
4. **ANR Detection**: Finds ANR (Application Not Responding) markers and related traces
5. **Message Dispatch Analysis**: Parses `Looper` slow dispatch logs to find heavy message handlers
6. **Binder Transaction Analysis**: Detects slow binder (IPC) calls on the main thread
7. **GC Pause Detection**: Identifies garbage collection pauses impacting the main thread
8. **Optimization Suggestions**: Provides actionable recommendations based on findings
9. **Multiple Output Formats**: Supports `text` (human-readable) and `json` (for CI/CD)

## 📋 Usage Guide

### Prerequisites

- **Python 3.6+** is required
- A log file from Android (logcat output, saved log, etc.)

### Capturing Logs

Before using this tool, capture logs from your Android device or emulator:

```bash
# Capture all logcat to a file (run your app scenario, then Ctrl+C)
adb logcat > my_app_log.txt

# Capture with timestamps (recommended)
adb logcat -v time > my_app_log.txt

# Capture only for a specific package (requires PID)
adb shell pidof com.example.myapp
adb logcat --pid=<PID> > my_app_log.txt

# Capture threadtime format (includes thread IDs, recommended)
adb logcat -v threadtime > my_app_log.txt
```

### Basic Commands

#### Analyze a log file (default threshold: 16ms)
```bash
python3 main_thread_analyzer.py /path/to/logcat.txt
```

#### Set custom slow operation threshold
```bash
python3 main_thread_analyzer.py /path/to/logcat.txt --threshold 32
```

#### Specify the main thread PID/TID
```bash
python3 main_thread_analyzer.py /path/to/logcat.txt --pid 12345
```

#### Output as JSON
```bash
python3 main_thread_analyzer.py /path/to/logcat.txt --output-format json
```

#### Show top N slowest operations
```bash
python3 main_thread_analyzer.py /path/to/logcat.txt --top 20
```

### Parameters

| Parameter | Description | Default |
|---|---|---|
| `log_file` | Path to the logcat/log file (required) | — |
| `--threshold` | Slow operation threshold in milliseconds | 16 |
| `--pid` | Main thread PID to filter (auto-detected if not specified) | auto |
| `--top` | Number of top slowest operations to show | 10 |
| `--output-format` | Output format: `text` or `json` | `text` |

## 🤖 AI Assistant Integration

### When to Use This Skill
- User reports "app is laggy", "UI freezes", "jank", "frame drops"
- User asks about "main thread performance", "ANR analysis"
- User has a logcat file and wants to understand performance issues
- User wants optimization suggestions for their Android app

### Workflow
1. **Help capture logs**: Guide the user to capture logcat with `adb logcat -v threadtime > log.txt`
2. **Run analysis**: Execute the analyzer with an appropriate threshold
3. **Interpret results**: Explain the findings:
   - **Slow dispatches**: Heavy work on the main thread handler
   - **Frame drops**: Choreographer skipping frames
   - **Binder calls**: IPC calls blocking the main thread
   - **GC pauses**: Excessive memory allocation causing pauses
   - **ANR markers**: Application Not Responding indicators
4. **Provide recommendations**: Suggest specific fixes based on the identified issues

### Common Optimization Suggestions
- Move I/O operations to background threads (Kotlin Coroutines, RxJava, Executor)
- Use `RecyclerView` with `DiffUtil` instead of `notifyDataSetChanged()`
- Reduce `onDraw()` complexity and avoid allocations in draw calls
- Use `ViewStub` for defer-loading complex layouts
- Move binder (IPC) calls off the main thread
- Profile with Android Studio Profiler for precise method-level analysis
