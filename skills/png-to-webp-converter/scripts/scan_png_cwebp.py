#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PNG to WebP Converter

Scans a project workspace for PNG images, analyzes potential space savings
from WebP conversion, and optionally performs the conversion or in-place replacement.

Prerequisites:
  - cwebp (from libwebp) must be installed and in PATH
  - Python 3.6+

Usage:
  python3 scan_png_cwebp.py /path/to/project                     # Analyze only
  python3 scan_png_cwebp.py /path/to/project --convert            # Safe convert
  python3 scan_png_cwebp.py /path/to/project --replace-in-place   # Destructive replace
"""

import os
import sys
import argparse
import shutil
import subprocess
import fnmatch
from pathlib import Path
from collections import defaultdict


def format_size(size_bytes):
    """Format byte count into human-readable KB, MB, GB."""
    if size_bytes < 1024:
        return f"{size_bytes} Bytes"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"


def find_repo_root(path, workspace_root):
    """Walk up from the file to find the nearest .git directory (repository root)."""
    current_path = Path(path).parent
    while len(str(current_path)) >= len(str(workspace_root)):
        if (current_path / ".git").is_dir():
            return str(current_path)
        if current_path == current_path.parent:
            break
        current_path = current_path.parent
    return workspace_root


def _find_cwebp():
    """Locate the cwebp executable."""
    candidate = shutil.which("cwebp")
    if candidate:
        return candidate
    for p in ["/usr/local/bin/cwebp", "/usr/bin/cwebp", "/bin/cwebp"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _run_cwebp(cwebp_path, src_path, dst_path, quality, method=6, alpha_q=90):
    """
    Run cwebp to convert a PNG to WebP.
    Args:
        cwebp_path: Path to cwebp binary
        src_path: Source PNG file
        dst_path: Destination WebP file
        quality: WebP quality (1-100)
        method: Compression method (0-6, higher = slower but better)
        alpha_q: Alpha channel quality (0-100)
    Returns True if conversion succeeded.
    """
    cmd = [
        cwebp_path, "-quiet",
        "-q", str(quality),
        "-m", str(method),
        "-alpha_q", str(alpha_q),
        "-mt",
        src_path, "-o", dst_path
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return proc.returncode == 0
    except Exception:
        return False


# Default directories to skip during scanning
DEFAULT_SKIP_DIRS = {
    'build', '.git', '.idea', '.gradle', 'Pods', 'node_modules',
    '.svn', '.hg', '__pycache__', '.pytest_cache', 'venv', '.venv',
    'dist', '.next', '.nuxt',
}


def should_include_file(file_path, workspace_root, include_patterns, exclude_patterns):
    """
    Check if a file matches include/exclude patterns.
    If include_patterns is empty, all files are included by default.
    Exclude patterns always take precedence.
    """
    rel_path = os.path.relpath(file_path, workspace_root)

    # Check exclude patterns first (they take precedence)
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_path, pattern):
            return False

    # If no include patterns specified, include everything
    if not include_patterns:
        return True

    # Check include patterns
    for pattern in include_patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_path, pattern):
            return True

    return False


def analyze_and_convert_workspace(
    workspace_path, quality, do_convert=False, output_dir="webp_output",
    do_replace=False, verbose=False, include_patterns=None, exclude_patterns=None,
    include_9patch=False
):
    """
    Scan, analyze, and optionally convert or replace PNG images in a workspace.

    Args:
        workspace_path: Root directory to scan
        quality: WebP quality (1-100)
        do_convert: If True, convert and save to output_dir
        output_dir: Directory for converted files
        do_replace: If True, replace originals with WebP (destructive)
        verbose: If True, print each file being processed
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude
        include_9patch: If True, also convert .9.png files
    """
    cwebp_path = _find_cwebp()
    if not cwebp_path:
        print("Error: 'cwebp' executable not found.")
        print("Please install libwebp command-line tools and ensure 'cwebp' is in PATH.")
        print("  macOS:          brew install webp")
        print("  Ubuntu/Debian:  sudo apt install webp")
        print("  Windows:        https://developers.google.com/speed/webp/download")
        sys.exit(2)

    if include_patterns is None:
        include_patterns = []
    if exclude_patterns is None:
        exclude_patterns = []

    repo_stats = defaultdict(lambda: {
        "png_count": 0, "original_size": 0, "webp_size": 0,
        "converted_count": 0, "replaced_count": 0, "failed_files": []
    })

    print(f"🚀 Starting workspace scan: {workspace_path}\n")
    if do_replace:
        print(f"🔥 \033[1;91mWARNING: In-place replace mode is enabled. Original PNG files will be DELETED.\033[0m")
        confirm = input("Are you sure you want to continue? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Operation cancelled by user.")
            return
        print("\nConfirmed. Performing replacement...\n")
    elif do_convert:
        print(f"✅ Safe convert mode enabled. Results will be saved to: {os.path.abspath(output_dir)}\n")

    workspace_abspath = os.path.abspath(workspace_path)

    for root, dirs, files in os.walk(workspace_abspath):
        # Skip default directories
        dirs[:] = [d for d in dirs if d not in DEFAULT_SKIP_DIRS]

        for file in files:
            name = file.lower()

            # Check if it's a PNG file
            if not name.endswith(".png"):
                continue

            # Skip 9-patch files unless explicitly included
            if name.endswith(".9.png") and not include_9patch:
                continue

            file_path = os.path.join(root, file)

            # Apply include/exclude patterns
            if not should_include_file(file_path, workspace_abspath, include_patterns, exclude_patterns):
                continue

            repo_root = find_repo_root(file_path, workspace_abspath)

            if verbose:
                repo_name = os.path.basename(repo_root)
                relative_path = os.path.relpath(file_path, workspace_abspath)
                print(f"  -> Processing [{repo_name}]: {relative_path}")

            try:
                original_size = os.path.getsize(file_path)
                repo_stats[repo_root]['original_size'] += original_size
                repo_stats[repo_root]['png_count'] += 1

                # Convert to a temporary WebP file using cwebp
                tmp_webp = file_path + ".webp.tmp"
                success = _run_cwebp(cwebp_path, file_path, tmp_webp, quality=int(quality))

                if not success or not os.path.exists(tmp_webp):
                    raise RuntimeError("cwebp conversion failed or produced no output file.")

                webp_size = os.path.getsize(tmp_webp)
                repo_stats[repo_root]['webp_size'] += webp_size

                if do_replace:
                    # Mode 1: In-place replacement (destructive)
                    webp_path = os.path.splitext(file_path)[0] + '.webp'
                    try:
                        os.replace(tmp_webp, webp_path)
                        os.remove(file_path)
                        repo_stats[repo_root]['replaced_count'] += 1
                    except Exception as e:
                        if os.path.exists(tmp_webp):
                            try:
                                os.remove(tmp_webp)
                            except Exception:
                                pass
                        repo_stats[repo_root]['failed_files'].append((file_path, str(e)))

                elif do_convert:
                    # Mode 2: Safe convert to output directory
                    relative_path = os.path.relpath(file_path, workspace_abspath)
                    webp_relative_path = os.path.splitext(relative_path)[0] + '.webp'
                    output_path = os.path.join(output_dir, webp_relative_path)
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    try:
                        os.replace(tmp_webp, output_path)
                        repo_stats[repo_root]['converted_count'] += 1
                    except Exception as e:
                        if os.path.exists(tmp_webp):
                            try:
                                os.remove(tmp_webp)
                            except Exception:
                                pass
                        repo_stats[repo_root]['failed_files'].append((file_path, str(e)))

                else:
                    # Mode 0: Analysis only — clean up temp file
                    if os.path.exists(tmp_webp):
                        try:
                            os.remove(tmp_webp)
                        except Exception:
                            pass

            except Exception as e:
                repo_stats[repo_root]['failed_files'].append((file_path, str(e)))

    # ---- Final Report ----

    if not repo_stats:
        print("No PNG files found in the workspace.")
        if include_patterns:
            print(f"  Include patterns: {include_patterns}")
        if exclude_patterns:
            print(f"  Exclude patterns: {exclude_patterns}")
        return

    # 1. Per-repository detailed report
    print("\n" + "=" * 60)
    print("📋 Per-Repository Analysis Report")
    print("=" * 60)

    sorted_repos = sorted(repo_stats.items(), key=lambda item: item[1]['original_size'], reverse=True)

    for repo_root, stats in sorted_repos:
        repo_name = os.path.basename(repo_root)
        saved = stats['original_size'] - stats['webp_size']
        percentage = (saved / stats['original_size']) * 100 if stats['original_size'] > 0 else 0

        print(f"\n--- Repository: {repo_name} ---")
        print(f"  Path:             {repo_root}")
        print(f"  PNG count:        {stats['png_count']}")
        print(f"  Original size:    {format_size(stats['original_size'])}")
        print(f"  Estimated WebP:   {format_size(stats['webp_size'])}")
        print(f"  \033[1;32mPotential savings: {format_size(saved)} ({percentage:.2f}%)\033[0m")

    # 2. Summary totals
    total_png_count = sum(s['png_count'] for s in repo_stats.values())
    total_original_size = sum(s['original_size'] for s in repo_stats.values())
    total_webp_size = sum(s['webp_size'] for s in repo_stats.values())
    total_saved_size = total_original_size - total_webp_size
    total_percentage_saved = (total_saved_size / total_original_size) * 100 if total_original_size > 0 else 0

    print("\n" + "=" * 60)
    print("📊 Workspace Summary")
    print("=" * 60)
    print(f"🖼️  Total PNG count:      {total_png_count}")
    print(f"🗂️  Total original size:  {format_size(total_original_size)}")
    print(f"🚀 Estimated WebP size:  {format_size(total_webp_size)}")
    print("-" * 60)
    print(f"✅ \033[1;32mTotal potential savings: {format_size(total_saved_size)}\033[0m")
    print(f"💰 \033[1;32mOverall savings ratio:  {total_percentage_saved:.2f}%\033[0m")

    # 3. Conversion/replacement report
    if do_replace:
        total_replaced = sum(s['replaced_count'] for s in repo_stats.values())
        print("\n" + "-" * 60)
        print("🔧 \033[1;91mIn-Place Replacement Report\033[0m")
        print(f"  Files replaced: {total_replaced} / {total_png_count}")
        print("-" * 60)
    elif do_convert:
        total_converted = sum(s['converted_count'] for s in repo_stats.values())
        print("\n" + "-" * 60)
        print("🔧 \033[1;34mSafe Conversion Report\033[0m")
        print(f"  Files converted: {total_converted} / {total_png_count}")
        print(f"  Output directory: {os.path.abspath(output_dir)}")
        print("-" * 60)

    # 4. Failure report
    all_failed_files = [item for stats in repo_stats.values() for item in stats['failed_files']]
    if all_failed_files:
        print("\n" + "=" * 60)
        print(f"⚠️ \033[1;31m{len(all_failed_files)} file(s) failed to process:\033[0m")
        print("=" * 60)
        for path, error in all_failed_files:
            print(f"  - File:   {path}\n    Reason: {error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan a workspace for PNG images, report WebP conversion savings, "
                    "and optionally convert or replace files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project                          Analyze only
  %(prog)s /path/to/project --convert -o ./out        Safe convert to output dir
  %(prog)s /path/to/project --replace-in-place        Destructive in-place replace
  %(prog)s /path/to/project --include "*/res/*" -v    Scan only res/ directories
  %(prog)s /path/to/project --exclude "*/test/*"      Exclude test directories
        """
    )
    parser.add_argument(
        "workspace_directory",
        help="Root directory to scan for PNG images."
    )
    parser.add_argument(
        "--convert",
        action="store_true",
        help="Convert PNGs to WebP and save to output directory (originals preserved)."
    )
    parser.add_argument(
        "--replace-in-place",
        action="store_true",
        dest="do_replace",
        help="⚠️ DESTRUCTIVE: Replace original PNGs with WebP files in-place. "
             "Original PNGs will be deleted."
    )
    parser.add_argument(
        "-o", "--output",
        default="webp_output",
        help="Output directory for converted WebP files (used with --convert). Default: 'webp_output'."
    )
    parser.add_argument(
        "-q", "--quality",
        type=int,
        default=75,
        help="WebP conversion quality (1-100). Higher = better quality but larger files. Default: 75."
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        dest="include_patterns",
        help="Glob pattern for files/directories to include (can be specified multiple times). "
             "Example: --include '*/res/*' --include '*/assets/*'"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        dest="exclude_patterns",
        help="Glob pattern for files/directories to exclude (can be specified multiple times). "
             "Example: --exclude '*/test/*' --exclude '*/debug/*'"
    )
    parser.add_argument(
        "--include-9patch",
        action="store_true",
        help="Include Android 9-patch (.9.png) files in scanning. By default they are skipped."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show each file being found and processed."
    )

    args = parser.parse_args()

    if not os.path.isdir(args.workspace_directory):
        print(f"Error: '{args.workspace_directory}' is not a valid directory.")
        sys.exit(1)

    analyze_and_convert_workspace(
        args.workspace_directory,
        args.quality,
        args.convert,
        args.output,
        args.do_replace,
        args.verbose,
        args.include_patterns,
        args.exclude_patterns,
        args.include_9patch,
    )
