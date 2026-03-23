---
name: diff-apks
description: |
  Deep APK/AAB size analyzer and comparator. Analyzes the composition of an APK/AAB file,
  breaking down size by category (business modules, SDKs, native libs, resources, assets).
  Can also compare two APK/AAB files to show size differences across all categories.
  Use this skill when the user wants to analyze APK size, compare builds, or find size optimization opportunities.
tags:
  - android
  - apk
  - performance
  - size-analysis
  - optimization
dependencies:
  - Python 3.6+
  - aapt (optional, for extracting version info from APK)
---

# APK Deep Size Analyzer & Comparator

A professional APK/AAB size analysis tool that breaks down the file composition into meaningful categories (business modules, third-party SDKs, native libraries, resources, assets, etc.) and provides detailed size reports. Supports both single-APK analysis and two-APK comparison (diff).

## 🎯 Core Features

1. **Single APK Analysis**: Breaks down the APK into categorized components with size, percentage, and class count
2. **Two-APK Comparison (Diff)**: Compares two APK/AAB files side-by-side showing size changes per category
3. **DEX Deep Parsing**: Parses DEX files at the bytecode level to attribute code size to specific packages
4. **Custom Classification Rules**: Supports external JSON rule files for project-specific package classification
5. **Auto Package Detection**: Automatically detects the app's main package from AndroidManifest.xml
6. **Multiple Output Formats**: Supports `text` (human-readable table) and `json` (for CI/CD integration)

## 📋 Usage Guide

### Prerequisites

- **Python 3.6+** is required
- **aapt** (optional) — used for extracting version info from APK files. Part of Android SDK Build Tools.

### Basic Commands

#### Analyze a single APK
```bash
python3 apk_deep_analyzer.py /path/to/app.apk
```

#### Compare two APKs (diff)
```bash
python3 apk_deep_analyzer.py /path/to/old.apk /path/to/new.apk
```

#### Use custom classification rules
```bash
python3 apk_deep_analyzer.py --rules my_rules.json /path/to/app.apk
```

#### Output as JSON (for CI pipelines)
```bash
python3 apk_deep_analyzer.py --output-format json /path/to/app.apk
```

### Custom Rules File (JSON)

You can provide a JSON file to classify your own business packages. The file should contain an array of rule objects:

```json
[
  {
    "pattern": "^Lcom/mycompany/feature/([^/]+)/",
    "category": "Business: {0}",
    "comment": "Classify feature modules under com.mycompany.feature"
  },
  {
    "pattern": "^Lcom/mycompany/core/",
    "category": "Business: Core",
    "comment": "Core module"
  },
  {
    "pattern": "^Lcom/partnersdk/",
    "category": "SDK: PartnerSDK",
    "comment": "Partner SDK integration"
  }
]
```

**Rule format:**
- `pattern` (required): A regex pattern to match against DEX class descriptors (e.g., `Lcom/example/Foo;`)
- `category` (required): The category name. Use `{0}` as a placeholder for the first capture group
- `comment` (optional): A human-readable description of the rule

Custom rules are evaluated **before** the built-in SDK rules, so your project-specific classifications take priority.

### Parameters

| Parameter | Description | Default |
|---|---|---|
| `paths` | One or two APK/AAB file paths | (auto-search current directory) |
| `--rules` | Path to a JSON rules file for custom package classification | (none, use built-in rules only) |
| `--output-format` | Output format: `text` or `json` | `text` |

## 🤖 AI Assistant Integration

### When to Use This Skill
- User asks to "analyze APK size", "check app size", "what's taking space in the APK"
- User asks to "compare APK sizes", "diff builds", "what changed between versions"
- User wants to find size optimization opportunities

### Workflow
1. **Locate APK files**: Help the user find APK/AAB files in `build/outputs/apk/` or similar paths
2. **Check for custom rules**: If the user has a specific app, suggest creating a rules file for better classification
3. **Run analysis**: Execute the script with appropriate arguments
4. **Interpret results**: Highlight the largest categories and suggest optimization strategies:
   - Large native libs → consider ABI splits or dynamic delivery
   - Large resources → consider WebP conversion, resource shrinking
   - Large DEX → consider ProGuard/R8 optimization, removing unused SDKs
   - Large assets → consider compression or on-demand downloading

### Example AI Interaction

```
User: "Analyze the APK size of our latest build"

1. Find the APK: look in build/outputs/apk/ or ask the user
2. Run: python3 apk_deep_analyzer.py /path/to/app-release.apk
3. Present results with optimization recommendations
```
