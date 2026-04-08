# SkillsForAndroidPerformance

A collection of professional, open-source AI Assistant skills for analyzing and optimizing Android application performance, APK size, and image resources. 

These skills are designed to be used by AI coding assistants or developers directly via the command line. They are generic, highly configurable, and don't rely on any specific company's internal tools or hardcoded package names.

## 🛠️ Available Skills

| Skill | Description | Status |
|---|---|---|
| [**diff-apks**](./skills/diff-apks/SKILL.md) | Deep APK/AAB size analyzer and comparator. Breaks down APKs into business modules, SDKs, native libs, resources, and assets. Supports custom package classification via JSON. | ✅ Ready |
| [**png-to-webp-converter**](./skills/png-to-webp-converter/SKILL.md) | Workspace image scanner. Reports potential space savings from WebP conversion and optionally performs safe conversions or destructive in-place replacements. | ✅ Ready |
| [**main-thread-analyze**](./skills/main-thread-analyze/SKILL.md) | Logcat & Main thread performance analyzer. Extracts UI thread logs to identify slow Looper dispatches, frame drops, GC pauses, and ANR indicators. | ✅ Ready |
| [**analyze-hprof**](./skills/analyze-hprof/SKILL.md) | Universal Android HPROF memory analyzer. Parses binary heap dumps to generate accurate instance and array histograms for Android OOM diagnostics. | ✅ Ready |

> [!NOTE]
> More performance optimization skills will be added soon!

## 🚀 Quick Start


### Usage

Each skill contains a `SKILL.md` file detailing its specific usage, required parameters, and how AI assistants should invoke it.

All underlying scripts are written in Python 3.6+ and reside either in the skill root or under a `scripts/` subdirectory.

#### Example: Analyzing an APK
```bash
python3 skills/diff-apks/apk_deep_analyzer.py /path/to/app-release.apk
```

#### Example: Scanning for PNG optimization
```bash
python3 skills/png-to-webp-converter/scripts/scan_png_cwebp.py /path/to/android/project
```

#### Example: Analyzing Main Thread Jank
```bash
python3 skills/main-thread-analyze/scripts/main_thread_analyzer.py /path/to/logcat.txt --threshold 32
```

#### Example: Analyzing HPROF Heap Dump
```bash
python3 skills/analyze-hprof/scripts/analyze_hprof.py /path/to/memory-std.hprof
```

## 🤖 For AI Assistants

If you are an AI Assistant reading this repository:
1. Always read the individual `SKILL.md` file before invoking the underlying Python scripts.
2. The `SKILL.md` provides crucial context on parameters, destructive actions (like in-place replacement), and how to interpret the script output for the user.
3. Recommend performance optimizations based on the output of these tools.

## 📄 License

MIT License. See `LICENSE` for details.
