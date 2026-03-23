---
name: png-to-webp-converter
description: |
  Scan a project workspace for PNG images, analyze potential space savings from WebP conversion,
  and optionally perform the conversion or in-place replacement.
  Use this skill when the user wants to optimize image sizes, convert image formats, or analyze
  image resource usage in an Android or general project.
tags:
  - images
  - optimization
  - webp
  - png
  - file-conversion
  - android
dependencies:
  - cwebp (from libwebp command-line tools)
  - Python 3.6+
---

# PNG to WebP Converter

A professional image optimization tool that scans a project workspace for PNG images, reports potential space savings from WebP conversion, and can optionally perform the conversion.

## 🎯 Core Features

1. **Analysis Mode** (default): Scan the workspace, calculate PNG → WebP savings potential without modifying any files
2. **Safe Convert Mode**: Convert PNG files to WebP and save to a separate output directory (originals preserved)
3. **In-Place Replace Mode** (destructive): Replace PNG files with WebP equivalents and delete originals
4. **Flexible Scanning**: Configurable include/exclude glob patterns for scanning any project structure
5. **Per-Repository Report**: Groups results by Git repository for multi-repo workspaces

## 📋 Usage Guide

### Prerequisites

- **Python 3.6+** is required
- **cwebp** (from libwebp) must be installed and available in PATH:
  - macOS: `brew install webp`
  - Ubuntu/Debian: `sudo apt install webp`
  - Windows: Download from [Google's WebP page](https://developers.google.com/speed/webp/download)

### Basic Commands

#### Analyze only (default, no files modified)
```bash
python3 scan_png_cwebp.py /path/to/project
```

#### Convert to output directory (originals preserved)
```bash
python3 scan_png_cwebp.py /path/to/project --convert -o ./webp_output
```

#### In-place replacement (⚠️ destructive, deletes original PNGs)
```bash
python3 scan_png_cwebp.py /path/to/project --replace-in-place
```

#### Custom quality and verbose output
```bash
python3 scan_png_cwebp.py /path/to/project -q 85 -v
```

#### Scan only specific directories
```bash
python3 scan_png_cwebp.py /path/to/project --include "*/res/*" --include "*/assets/*"
```

#### Exclude certain directories
```bash
python3 scan_png_cwebp.py /path/to/project --exclude "*/test/*" --exclude "*/debug/*"
```

### Parameters

| Parameter | Description | Default |
|---|---|---|
| `workspace_directory` | Root directory to scan (required) | — |
| `--convert` | Safe convert mode: save WebP files to output directory | off |
| `--replace-in-place` | ⚠️ Destructive: replace PNG with WebP, delete originals | off |
| `-o, --output` | Output directory for converted files | `webp_output` |
| `-q, --quality` | WebP quality (1-100, higher = better quality, larger file) | 75 |
| `--include` | Glob patterns for directories/files to include (can repeat) | scan all |
| `--exclude` | Glob patterns for directories/files to exclude (can repeat) | — |
| `--skip-9patch` | Skip Android 9-patch PNG files (*.9.png) | on (default) |
| `--include-9patch` | Include 9-patch files in scanning | off |
| `-v, --verbose` | Show each file being processed | off |

### Important Warnings

> ⚠️ **`--replace-in-place` is a destructive operation**:
> - Original PNG files will be **permanently deleted**
> - Replaced with same-named `.webp` files
> - **Always run in analysis mode first** to review the impact
> - **Back up your project** before using this mode

## 🤖 AI Assistant Integration

### When to Use This Skill
- User mentions "optimize images", "reduce image size", "convert PNG to WebP"
- User asks about image resource optimization in an Android project
- User wants to analyze image assets in a project

### Workflow
1. **Analyze first**: Always start with analysis mode to show savings potential
2. **Recommend quality**: 75–85 for most use cases, 90+ for high-quality needs
3. **Suggest safe convert**: Recommend `--convert` mode before `--replace-in-place`
4. **Warn about 9-patch**: Android 9-patch (.9.png) files should typically NOT be converted
5. **Review results**: Highlight repositories/directories with the most optimization potential

### Example Interaction

```
User: "Can you help optimize the PNG images in our project?"

1. Run analysis: python3 scan_png_cwebp.py /path/to/project -v
2. Present the savings report to the user
3. If user wants to proceed, suggest: python3 scan_png_cwebp.py /path/to/project --convert -o ./webp_output -q 80
4. Let user review the converted files before any in-place replacement
```