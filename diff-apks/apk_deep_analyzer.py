#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK/AAB Deep Size Analyzer & Comparator

Analyzes the composition of Android APK/AAB files by breaking down size
into meaningful categories (business modules, third-party SDKs, native
libraries, resources, assets, etc.).

Supports:
  - Single APK analysis with detailed breakdown
  - Two-APK comparison (diff) showing size changes
  - Custom classification rules via JSON config file
  - Auto-detection of app main package from AndroidManifest.xml
  - Text and JSON output formats

Usage:
  python3 apk_deep_analyzer.py app.apk
  python3 apk_deep_analyzer.py old.apk new.apk
  python3 apk_deep_analyzer.py --rules my_rules.json app.apk
  python3 apk_deep_analyzer.py --output-format json app.apk
"""

import os
import zipfile
import struct
import re
import argparse
import glob
import json
import subprocess
import shutil
import sys

# ============================================================================
# DEX Parser
# ============================================================================

class DexParser:
    """Parses standard DEX file format to extract class descriptors and code size weights."""

    def __init__(self, data):
        self.data = data
        self.cursor = 0
        self.string_ids = []
        self.type_ids = []
        self.valid = True

    def read_uint(self):
        val = struct.unpack_from('<I', self.data, self.cursor)[0]
        self.cursor += 4
        return val

    def read_uint_at(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]

    def read_ushort(self):
        val = struct.unpack_from('<H', self.data, self.cursor)[0]
        self.cursor += 2
        return val

    def read_ubyte(self):
        val = struct.unpack_from('<B', self.data, self.cursor)[0]
        self.cursor += 1
        return val

    def read_uleb128(self):
        val = 0
        shift = 0
        while True:
            byte = self.data[self.cursor]
            self.cursor += 1
            val |= (byte & 0x7f) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return val

    def read_uleb128_at(self, offset):
        cursor = offset
        val = 0
        shift = 0
        while True:
            byte = self.data[cursor]
            cursor += 1
            val |= (byte & 0x7f) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return val, cursor - offset

    def parse(self):
        if len(self.data) < 112:
            return []

        if self.data[0:3] != b'dex':
            self.valid = False
            return []

        # Read essential offsets from header
        self.cursor = 56  # string_ids_size offset
        string_ids_size = self.read_uint()
        string_ids_off = self.read_uint()
        type_ids_size = self.read_uint()
        type_ids_off = self.read_uint()

        # Read String IDs
        self.cursor = string_ids_off
        string_data_offsets = []
        for _ in range(string_ids_size):
            string_data_offsets.append(self.read_uint())

        # Read Type IDs
        self.cursor = type_ids_off
        for _ in range(type_ids_size):
            self.type_ids.append(self.read_uint())

        # Read Class Defs (class_defs_size at offset 96)
        self.cursor = 96
        class_defs_size = self.read_uint()
        class_defs_off = self.read_uint()

        def get_string(idx):
            if idx >= len(string_data_offsets):
                return ""
            offset = string_data_offsets[idx]
            cursor = offset
            while True:
                byte = self.data[cursor]
                cursor += 1
                if (byte & 0x80) == 0:
                    break
            end = cursor
            while end < len(self.data) and self.data[end] != 0:
                end += 1
            return self.data[cursor:end].decode('utf-8', errors='replace')

        classes_info = []

        self.cursor = class_defs_off
        for _ in range(class_defs_size):
            class_idx = self.read_uint()
            self.cursor += 20  # skip access_flags, superclass, interfaces, source, annotations
            class_data_off = self.read_uint()
            self.cursor += 4   # skip static_values_off

            class_name = ""
            if class_idx < len(self.type_ids):
                type_idx = self.type_ids[class_idx]
                class_name = get_string(type_idx)

            class_code_size = 0
            if class_data_off != 0:
                saved_cursor = self.cursor
                self.cursor = class_data_off

                static_fields_size = self.read_uleb128()
                instance_fields_size = self.read_uleb128()
                direct_methods_size = self.read_uleb128()
                virtual_methods_size = self.read_uleb128()

                for _ in range(static_fields_size):
                    self.read_uleb128()
                    self.read_uleb128()
                for _ in range(instance_fields_size):
                    self.read_uleb128()
                    self.read_uleb128()

                def process_methods(count):
                    size = 0
                    for _ in range(count):
                        self.read_uleb128()  # method_idx_diff
                        self.read_uleb128()  # access_flags
                        code_off = self.read_uleb128()
                        if code_off != 0:
                            insns_size = self.read_uint_at(code_off + 12)
                            size += insns_size * 2
                    return size

                class_code_size += process_methods(direct_methods_size)
                class_code_size += process_methods(virtual_methods_size)

                self.cursor = saved_cursor

            classes_info.append((class_name, class_code_size))

        return classes_info


def get_dex_classes_info(dex_bytes):
    """Returns a list of (class_name, estimated_size) tuples."""
    parser = DexParser(dex_bytes)
    return parser.parse()


# ============================================================================
# Classification Rules
# ============================================================================

# ============================================================================

def get_default_rules():
    """Load default SDK rules from sdk_rules.json in the script directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sdk_rules_path = os.path.join(script_dir, 'sdk_rules.json')
    rules = []
    
    if os.path.exists(sdk_rules_path):
        try:
            with open(sdk_rules_path, 'r', encoding='utf-8') as f:
                json_rules = json.load(f)
                for r in json_rules:
                    if "pattern" in r and "category" in r:
                        rules.append((r["pattern"], r["category"]))
        except Exception as e:
            print(f"Warning: Failed to load sdk_rules.json: {e}")
            
    # Always append the catch-all
    rules.append((r'^L', 'Unclassified Classes'))
    return rules


def load_custom_rules(rules_path):
    """
    Load custom classification rules from a JSON file.

    Expected format:
    [
      {"pattern": "^Lcom/myapp/feature/([^/]+)/", "category": "Business: {0}"},
      {"pattern": "^Lcom/myapp/core/", "category": "Business: Core"}
    ]
    """
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        rules = []
        for item in data:
            pattern = item.get('pattern', '')
            category = item.get('category', 'Custom')
            if pattern:
                rules.append((pattern, category))
        return rules
    except Exception as e:
        print(f"Warning: Failed to load custom rules from {rules_path}: {e}")
        return []


def detect_app_package(apk_path):
    """
    Attempt to detect the app's main package name from AndroidManifest.xml using aapt.
    Returns the package name string or None.
    """
    try:
        if shutil.which('aapt'):
            abs_path = os.path.abspath(apk_path)
            result = subprocess.run(
                ['aapt', 'dump', 'badging', abs_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                match = re.search(r"package: name='([^']+)'", result.stdout)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return None


def build_rules(custom_rules_path=None, apk_path=None):
    """
    Build the final classification rules list.
    Priority: custom rules > user rules > app autodetected > sdk_rules.
    """
    rules = []

    # 1. Custom rules from JSON file (highest priority)
    if custom_rules_path:
        custom = load_custom_rules(custom_rules_path)
        if custom:
            rules.extend(custom)
            print(f"Loaded {len(custom)} custom rule(s) from {custom_rules_path}")

    # 2. Add user_rules.json (interactive/auto mappings)
    user_rules_path = "user_rules.json"
    if os.path.exists(user_rules_path) and user_rules_path != custom_rules_path:
        user_rules = load_custom_rules(user_rules_path)
        if user_rules:
            rules.extend(user_rules)
            
    # 3. Auto-detect app main package and add a custom business rule
    if apk_path:
        pkg = detect_app_package(apk_path)
        if pkg:
            # Convert dot notation to path: com.example.app -> Lcom/example/app/
            pkg_path = pkg.replace('.', '/')
            # Add a dynamic rule for the app's own package
            auto_rule = (f'^L{pkg_path}/([^/]+)/', 'Business: {0}')
            rules.append(auto_rule)
            print(f"Auto-detected app package: {pkg}")

    # 4. Built-in SDK rules
    rules.extend(get_default_rules())

    return rules


# ============================================================================
# Helper Functions
# ============================================================================

def get_category_priority(cat_name):
    """Returns a priority integer for sorting categories."""
    if cat_name.startswith("Business:"):
        return 0
    elif cat_name.startswith("SDK:"):
        return 1
    elif cat_name.startswith("Native Libs"):
        return 10
    elif cat_name.startswith("Resources") or cat_name == "Resources Index" or cat_name == "Manifest":
        return 11
    elif cat_name.startswith("Assets"):
        return 12
    elif cat_name.startswith("Unclassified Classes"):
        return 3
    elif cat_name in ["Meta-INF", "Other Files"]:
        return 13
    return 2


def consolidate_categories(category_sizes, category_files, category_packages):
    """Aggregates small 'Unclassified Classes: ...' items into a single misc category."""
    new_sizes = category_sizes.copy()
    new_files = category_files.copy()
    new_packages = category_packages.copy()

    threshold = 10 * 1024  # 10 KB
    misc_cat = "Unclassified Classes (tail)"

    keys = list(new_sizes.keys())
    for cat in keys:
        if cat.startswith("Unclassified Classes:"):
            size = new_sizes[cat]
            if size < threshold:
                new_sizes[misc_cat] = new_sizes.get(misc_cat, 0) + size
                new_files[misc_cat] = new_files.get(misc_cat, 0) + new_files[cat]
                del new_sizes[cat]
                del new_files[cat]
                if cat in new_packages:
                    del new_packages[cat]

    return new_sizes, new_files, new_packages


def format_bytes(size, signed=False):
    """Format a byte count into a human-readable string."""
    sign = ""
    if signed and size > 0:
        sign = "+"

    abs_size = abs(size)

    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs_size < 1024.0:
            return f"{sign}{size:.2f} {unit}"
        size /= 1024.0
        abs_size /= 1024.0
    return f"{sign}{size:.2f} TB"


# ============================================================================
# Analysis Logic
# ============================================================================

def get_apk_analysis(apk_path, rules, silent=False):
    """
    Perform deep analysis of an APK/AAB file.
    Returns a dict with category breakdowns and totals.
    """
    if not silent:
        print(f"Deep Analyzing APK: {apk_path}")
        print("-" * 100)

    category_sizes = {}
    category_files = {}
    category_packages = {}

    total_apk_size = 0
    total_dex_size = 0

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            file_list = z.infolist()

            for file_info in file_list:
                file_name = file_info.filename

                # 🚀 NEW: AAB module filter
                # If it's an AAB, we only want to analyze the "base" module and global metadata
                if apk_path.lower().endswith('.aab'):
                    top_dir = file_name.split('/')[0]
                    # Allowed top-level dirs in AAB: base, META-INF, BUNDLE-METADATA
                    if top_dir not in ['base', 'META-INF', 'BUNDLE-METADATA'] and '/' in file_name:
                        continue # Skip split bundles (like feature/, frostfire/, invoice/)

                file_size = file_info.compress_size
                total_apk_size += file_size

                if file_name.endswith('.dex'):
                    total_dex_size += file_size
                    if not silent:
                        print(f"Processing DEX: {file_name} ({file_size/1024:.2f} KB)...")
                    try:
                        dex_bytes = z.read(file_name)
                        classes_info = get_dex_classes_info(dex_bytes)
                        if not classes_info:
                            category = "Unparsable DEX"
                            category_sizes[category] = category_sizes.get(category, 0) + file_size
                            continue

                        total_code_size = sum(info[1] for info in classes_info)

                        for cls, code_size in classes_info:
                            if total_code_size > 0:
                                weight = code_size / total_code_size
                            else:
                                weight = 1.0 / len(classes_info)

                            size_contribution = file_size * weight

                            matched_cat = "Unclassified Classes"
                            for pattern, category in rules:
                                match = re.match(pattern, cls)
                                if match:
                                    if '{0}' in category:
                                        group_val = match.group(1)
                                        dyn_name = group_val.capitalize()
                                        matched_cat = category.format(dyn_name)
                                    else:
                                        matched_cat = category

                                    if category.startswith('Business:') or category.startswith('SDK:'):
                                        raw_pkg = match.group(0)
                                        clean_pkg = raw_pkg.lstrip('L').rstrip('/')
                                        dotted_pkg = clean_pkg.replace('/', '.')
                                        if matched_cat not in category_packages:
                                            category_packages[matched_cat] = dotted_pkg
                                    break

                            if matched_cat == "Unclassified Classes":
                                clean_name = cls.lstrip('L').rstrip(';')
                                parts = clean_name.split('/')
                                package_parts = parts[:-1]

                                if package_parts:
                                    depth = min(len(package_parts), 3)
                                    sub_pkg = ".".join(package_parts[:depth])
                                    matched_cat = f"Unclassified Classes: {sub_pkg}"
                                    if matched_cat not in category_packages:
                                        category_packages[matched_cat] = f"{sub_pkg}*"

                            category_sizes[matched_cat] = category_sizes.get(matched_cat, 0) + size_contribution
                            category_files[matched_cat] = category_files.get(matched_cat, 0) + 1

                    except Exception as e:
                        print(f"Error parsing DEX {file_name}: {e}")
                        category_sizes["Error DEX"] = category_sizes.get("Error DEX", 0) + file_size

                else:
                    # Non-DEX file classification
                    category = "Other Files"
                    
                    # AABs often prefix files with `base/` or `feature_name/`.
                    # We strip the first directory if the second directory is a known root (res, lib, assets)
                    parsed_name = file_name
                    parts = parsed_name.split('/')
                    if len(parts) > 1 and parts[1] in ['res', 'lib', 'assets', 'dex', 'manifest']:
                        # e.g. base/res/mipmap... -> res/mipmap...
                        parsed_name = '/'.join(parts[1:])
                        parts = parts[1:]

                    if parsed_name.startswith("lib/"):
                        if len(parts) > 1:
                            arch = parts[1]
                            category = f"Native Libs: {arch}"
                        else:
                            category = "Native Libs"
                    elif parsed_name.startswith("assets/"):
                        if len(parts) > 1:
                            sub = parts[1]
                            if len(parts) == 2:
                                category = "Assets: Root Files"
                            else:
                                category = f"Assets: {sub}"
                        else:
                            category = "Assets"
                    elif parsed_name.startswith("res/"):
                        if len(parts) > 1:
                            res_type = parts[1].split('-')[0]
                            category = f"Resources: {res_type}"
                        else:
                            category = "Resources"
                    elif parsed_name.startswith("META-INF/") or file_name.startswith("META-INF/"):
                        category = "Meta-INF"
                    elif parsed_name == "AndroidManifest.xml" or file_name.endswith("AndroidManifest.xml"):
                        category = "Manifest"
                    elif parsed_name == "resources.arsc" or file_name.endswith("resources.arsc"):
                        category = "Resources Index"
                    else:
                        # Fallback for remaining Other Files: break them down by extension
                        _, ext = os.path.splitext(file_name)
                        ext = ext.lower()
                        if ext in ['.png', '.jpg', '.jpeg', '.webp', '.gif', '.svg']:
                            category = "Other Files (Images)"
                        elif ext in ['.xml', '.json', '.html', '.css', '.js']:
                            category = "Other Files (Text/Markup)"
                        elif ext in ['.ttf', '.otf', '.woff', '.woff2']:
                            category = "Other Files (Fonts)"
                        elif ext in ['.mp3', '.mp4', '.wav', '.ogg']:
                            category = "Other Files (Media)"
                        elif ext in ['.so', '.a', '.dll']:
                            category = "Other Files (Native)"
                        elif not ext:
                            category = "Other Files (No Extension)"
                        else:
                            category = f"Other Files (Misc {ext})"

                    category_sizes[category] = category_sizes.get(category, 0) + file_size
                    category_files[category] = category_files.get(category, 0) + 1

        return {
            'category_sizes': category_sizes,
            'category_files': category_files,
            'category_packages': category_packages,
            'total_apk_size': total_apk_size,
            'total_dex_size': total_dex_size,
            'success': True
        }

    except zipfile.BadZipFile:
        print(f"Error: Invalid APK file {apk_path}")
        return {'success': False}


# ============================================================================
# Output Formatters
# ============================================================================

PRIORITY_NAMES = {
    0: "Business Modules",
    1: "SDKs",
    2: "Common Libraries",
    3: "Unclassified (DEX)",
    10: "Native Libs",
    11: "Resources",
    12: "Assets",
    13: "Other Files",
    99: "Unclassified",
}


def _display_cat_name(cat):
    """Shorten verbose unclassified category names for display."""
    if cat.startswith("Unclassified Classes:"):
        return cat.split(':')[0]
    return cat


def auto_package_mapping(results, custom_rules_path):
    """
    Find large unclassified packages and automatically map them to business categories.
    Updates the results in-place and saves rules to the JSON file.
    """
    unclassified = {}
    
    for res in results:
        if not res.get('success'): continue
        cats = res.get('category_sizes', {})
        for cat, size in cats.items():
            if cat.startswith("Unclassified Classes: "):
                pkg_name = cat.replace("Unclassified Classes: ", "").strip()
                unclassified[pkg_name] = max(unclassified.get(pkg_name, 0), size) # Use max size across APKs to decide
                
    # Filter for significant packages (e.g., > 100KB)
    threshold = 100 * 1024
    candidates = [(pkg, size) for pkg, size in unclassified.items() if size > threshold]
    candidates.sort(key=lambda x: x[1], reverse=True)
    
    if not candidates:
        return
        
    print("\n" + "=" * 60)
    print("🧠 Auto Package Mapping")
    print("=" * 60)
    print(f"Found {len(candidates)} large unclassified package(s). Automatically grouping them.")
    
    if not custom_rules_path:
        custom_rules_path = "user_rules.json"
        
    new_rules = []
    
    for pkg, size in candidates:
        parts = pkg.split('.')
        # Use the last part or last two parts of the package as a readable name
        short_name = parts[-1].capitalize() if len(parts) > 0 else pkg
        if len(parts) > 1 and len(parts[-1]) < 4:
           short_name = f"{parts[-2].capitalize()} {short_name}"
            
        # Any package reaching here wasn't caught by sdk_rules.json, so treat as Business
        cat_input = f"Business: {short_name}"
        
        rule_pattern = f"^L{pkg.replace('.', '/')}/"
        new_rules.append({
            "pattern": rule_pattern,
            "category": cat_input,
            "comment": "Auto-mapped by script"
        })
        
        # Update results in place
        old_cat = f"Unclassified Classes: {pkg}"
        for res in results:
            if not res.get('success'): continue
            
            # Move sizes
            if old_cat in res['category_sizes']:
                old_size = res['category_sizes'].pop(old_cat)
                res['category_sizes'][cat_input] = res['category_sizes'].get(cat_input, 0) + old_size
                
            # Move files count
            if old_cat in res['category_files']:
                old_count = res['category_files'].pop(old_cat)
                res['category_files'][cat_input] = res['category_files'].get(cat_input, 0) + old_count
                
            # Update package strings
            if old_cat in res.get('category_packages', {}):
                res['category_packages'].pop(old_cat)
            res.setdefault('category_packages', {})[cat_input] = f"{pkg}*"
            
    if new_rules:
        existing_rules = []
        if os.path.exists(custom_rules_path):
            try:
                with open(custom_rules_path, 'r', encoding='utf-8') as f:
                    existing_rules = json.load(f)
            except Exception:
                pass
                
        existing_rules.extend(new_rules)
        try:
            with open(custom_rules_path, 'w', encoding='utf-8') as f:
                json.dump(existing_rules, f, indent=2, ensure_ascii=False)
            print(f"✅ Auto-mapped {len(new_rules)} package(s) and saved to '{custom_rules_path}'.")
            print("💡 Tip: You can edit this file to rename the categories or adjust the rules.")
        except Exception as e:
            print(f"Failed to save rules: {e}")


def analyze_apk_text(result):
    """Print single-APK analysis as a formatted text table."""
    category_sizes, category_files, category_packages = consolidate_categories(
        result['category_sizes'], result['category_files'], result.get('category_packages', {})
    )

    total_apk_size = result['total_apk_size']
    total_dex_size = result['total_dex_size']

    cat_items = []
    max_cat_len = 30
    for cat, size in category_sizes.items():
        priority = get_category_priority(cat)
        display_cat = _display_cat_name(cat)
        max_cat_len = max(max_cat_len, len(display_cat))
        cat_items.append({'name': cat, 'size': size, 'priority': priority})

    col_width = max_cat_len + 2
    header_title = 'Category / SDK / Module'
    if len(header_title) > col_width:
        col_width = len(header_title) + 2

    max_pkg_len = 10
    for pkg in category_packages.values():
        max_pkg_len = max(max_pkg_len, len(pkg))
    pkg_col_width = max_pkg_len + 2

    separator_len = col_width + 12 + 8 + 8 + pkg_col_width + 4 * 3

    print("\n" + "=" * separator_len)
    print(f"{header_title:<{col_width}} | {'Size':<12} | {'Share':<8} | {'Count':<8} | {'Package':<{pkg_col_width}}")
    print("-" * separator_len)

    cat_items.sort(key=lambda x: (x['priority'], -x['size']))

    group_sizes = {}
    for item in cat_items:
        group_sizes[item['priority']] = group_sizes.get(item['priority'], 0) + item['size']

    last_priority = None

    for item in cat_items:
        priority = item['priority']

        if last_priority is None or priority != last_priority:
            if last_priority is not None:
                print("-" * separator_len)

            group_name = PRIORITY_NAMES.get(priority, f"Group {priority} Total")
            group_total = group_sizes.get(priority, 0)
            group_percent = (group_total / total_apk_size) * 100 if total_apk_size > 0 else 0

            print(f">>> {group_name:<{col_width-4}} | {format_bytes(group_total):<12} | {group_percent:5.1f}% | {'-':<8} | {'-':<{pkg_col_width}}")
            print("-" * separator_len)

        last_priority = priority

        cat = item['name']
        size = item['size']
        pkg_name = category_packages.get(cat, "-")
        display_cat = _display_cat_name(cat)
        percent = (size / total_apk_size) * 100 if total_apk_size > 0 else 0
        count = category_files.get(cat, 0)
        count_str = f"{count}" if count > 0 else "-"

        print(f"{display_cat:<{col_width}} | {format_bytes(size):<12} | {percent:5.1f}% | {count_str:<8} | {pkg_name:<{pkg_col_width}}")

    print("=" * separator_len)
    print(f"{'Total APK Size':<{col_width}} | {format_bytes(total_apk_size):<12}")
    print(f"{'Total DEX Size':<{col_width}} | {format_bytes(total_dex_size):<12}")
    print("=" * separator_len)


def analyze_apk_json(result):
    """Print single-APK analysis as JSON."""
    category_sizes, category_files, category_packages = consolidate_categories(
        result['category_sizes'], result['category_files'], result.get('category_packages', {})
    )

    output = {
        'total_apk_size': result['total_apk_size'],
        'total_dex_size': result['total_dex_size'],
        'categories': []
    }

    for cat, size in sorted(category_sizes.items(), key=lambda x: -x[1]):
        output['categories'].append({
            'name': cat,
            'size': round(size, 2),
            'percentage': round((size / result['total_apk_size']) * 100, 2) if result['total_apk_size'] > 0 else 0,
            'file_count': category_files.get(cat, 0),
            'package': category_packages.get(cat, None),
            'group': PRIORITY_NAMES.get(get_category_priority(cat), "Other"),
        })

    print(json.dumps(output, indent=2, ensure_ascii=False))


def get_apk_version(path):
    """Extract version name from APK using aapt or filename heuristics."""
    try:
        if shutil.which('aapt'):
            abs_path = os.path.abspath(path)
            result = subprocess.run(
                ['aapt', 'dump', 'badging', abs_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                vn = re.search(r"versionName='([^']+)'", result.stdout)
                if vn:
                    return f"(v{vn.group(1)})"
    except Exception:
        pass

    filename = os.path.basename(path)
    match = re.search(r'(v?\d+\.\d+(\.\d+)?)', filename)
    if match:
        v = match.group(1)
        if not v.startswith('v'):
            v = f"v{v}"
        return f"({v})"

    return ""


# ============================================================================
# Comparison Logic
# ============================================================================

def compare_apks_text(path1, path2, res1, res2):
    """Compare two APKs and print a text diff table."""
    print(f"Comparing APKs:\nBase: {path1}\nTarget: {path2}")

    ver1 = get_apk_version(path1)
    ver2 = get_apk_version(path2)

    if not res1['success'] or not res2['success']:
        return

    sizes1, _, pkgs1 = consolidate_categories(res1['category_sizes'], res1['category_files'], res1.get('category_packages', {}))
    sizes2, _, pkgs2 = consolidate_categories(res2['category_sizes'], res2['category_files'], res2.get('category_packages', {}))

    all_cats = set(sizes1.keys()) | set(sizes2.keys())

    total_diff = res2['total_apk_size'] - res1['total_apk_size']
    dex_diff = res2['total_dex_size'] - res1['total_dex_size']

    diff_data = []
    max_cat_len = 30

    all_packages = pkgs1.copy()
    all_packages.update(pkgs2)

    max_pkg_len = 10
    for pkg in all_packages.values():
        max_pkg_len = max(max_pkg_len, len(pkg))
    pkg_col_width = max_pkg_len + 2

    for cat in all_cats:
        size1 = sizes1.get(cat, 0)
        size2 = sizes2.get(cat, 0)
        diff = size2 - size1
        priority = get_category_priority(cat)
        pkg_name = all_packages.get(cat, "-")

        if size1 > 0:
            change_pct = (diff / size1) * 100
            change_str = f"{change_pct:+.1f}%"
        else:
            change_str = "New" if size2 > 0 else "-"

        display_cat = _display_cat_name(cat)
        max_cat_len = max(max_cat_len, len(display_cat))

        diff_data.append({
            'name': cat,
            'display_name': display_cat,
            'size1': size1,
            'size2': size2,
            'diff': diff,
            'change_str': change_str,
            'priority': priority,
            'pkg_name': pkg_name
        })

    col_width = max_cat_len + 2
    line_len = col_width + 15 + 15 + 12 + 8 + pkg_col_width + 4 * 4

    print("\n" + "=" * line_len)
    base_title = f"Base {ver1}" if ver1 else "Base Size"
    target_title = f"Target {ver2}" if ver2 else "Target Size"

    print(f"{'Metric':<50} | {base_title:<15} | {target_title:<15} | {'Diff':<12} | {'Change':<8}")
    print("-" * 120)
    print(f"{'Total APK Size':<50} | {format_bytes(res1['total_apk_size']):<15} | {format_bytes(res2['total_apk_size']):<15} | {format_bytes(total_diff, signed=True):<12} | {'':<8}")
    print(f"{'Total DEX Size':<50} | {format_bytes(res1['total_dex_size']):<15} | {format_bytes(res2['total_dex_size']):<15} | {format_bytes(dex_diff, signed=True):<12} | {'':<8}")
    print("=" * line_len)

    print(f"{'Category / SDK / Module':<{col_width}} | {base_title:<15} | {target_title:<15} | {'Diff':<12} | {'Change':<8} | {'Package':<{pkg_col_width}}")
    print("-" * line_len)

    diff_data.sort(key=lambda x: (x['priority'], -x['size2']))

    last_priority = None
    group_stats = {}

    for item in diff_data:
        p = item['priority']
        if p not in group_stats:
            group_stats[p] = {'size1': 0, 'size2': 0}
        group_stats[p]['size1'] += item['size1']
        group_stats[p]['size2'] += item['size2']

    for item in diff_data:
        priority = item['priority']

        if last_priority is None or priority != last_priority:
            if last_priority is not None:
                print("-" * line_len)

            group_name = PRIORITY_NAMES.get(priority, f"Group {priority}")
            stats = group_stats.get(priority, {'size1': 0, 'size2': 0})
            g_diff = stats['size2'] - stats['size1']
            if stats['size1'] > 0:
                g_chg = f"{(g_diff / stats['size1']) * 100:+.1f}%"
            else:
                g_chg = "New" if stats['size2'] > 0 else "-"

            print(f">>> {group_name:<{col_width-4}} | {format_bytes(stats['size1']):<15} | {format_bytes(stats['size2']):<15} | {format_bytes(g_diff, signed=True):<12} | {g_chg:<8} | {'-':<{pkg_col_width}}")
            print("-" * line_len)

        last_priority = priority

        print(f"{item['display_name']:<{col_width}} | {format_bytes(item['size1']):<15} | {format_bytes(item['size2']):<15} | {format_bytes(item['diff'], signed=True):<12} | {item['change_str']:<8} | {item['pkg_name']:<{pkg_col_width}}")

    print("=" * line_len)


def compare_apks_json(path1, path2, res1, res2):
    """Compare two APKs and print a JSON diff report."""
    if not res1['success']:
        print(json.dumps({"error": f"Failed to analyze {path1}"}))
        return

    if not res2['success']:
        print(json.dumps({"error": f"Failed to analyze {path2}"}))
        return

    sizes1, _, pkgs1 = consolidate_categories(res1['category_sizes'], res1['category_files'], res1.get('category_packages', {}))
    sizes2, _, pkgs2 = consolidate_categories(res2['category_sizes'], res2['category_files'], res2.get('category_packages', {}))

    all_cats = set(sizes1.keys()) | set(sizes2.keys())
    all_packages = pkgs1.copy()
    all_packages.update(pkgs2)

    output = {
        'base': {
            'path': path1,
            'version': get_apk_version(path1),
            'total_apk_size': res1['total_apk_size'],
            'total_dex_size': res1['total_dex_size'],
        },
        'target': {
            'path': path2,
            'version': get_apk_version(path2),
            'total_apk_size': res2['total_apk_size'],
            'total_dex_size': res2['total_dex_size'],
        },
        'total_diff': res2['total_apk_size'] - res1['total_apk_size'],
        'categories': []
    }

    for cat in sorted(all_cats):
        size1 = sizes1.get(cat, 0)
        size2 = sizes2.get(cat, 0)
        diff = size2 - size1
        output['categories'].append({
            'name': cat,
            'base_size': round(size1, 2),
            'target_size': round(size2, 2),
            'diff': round(diff, 2),
            'change_percent': round((diff / size1) * 100, 2) if size1 > 0 else None,
            'package': all_packages.get(cat, None),
            'group': PRIORITY_NAMES.get(get_category_priority(cat), "Other"),
        })

    print(json.dumps(output, indent=2, ensure_ascii=False))


# ============================================================================
# APK File Discovery
# ============================================================================

def find_apk_file(root_dir):
    """Walk the directory tree to find an APK/AAB file, skipping build intermediates."""
    for dirpath, _, filenames in os.walk(root_dir):
        if 'intermediates' in dirpath:
            continue
        for filename in filenames:
            if filename.endswith('.apk') or filename.endswith('.aab'):
                return os.path.join(dirpath, filename)
    return None


def find_apk_file_list(root_dir):
    """Walk the directory tree to find all APK/AAB files, skipping intermediates."""
    found = []
    for dirpath, _, filenames in os.walk(root_dir):
        if 'intermediates' in dirpath:
            continue
        for filename in filenames:
            if filename.endswith('.apk') or filename.endswith('.aab'):
                found.append(os.path.join(dirpath, filename))
    return found


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='APK/AAB Deep Size Analyzer & Comparator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app-release.apk                    Analyze a single APK
  %(prog)s old.apk new.apk                    Compare two APKs
  %(prog)s --rules my_rules.json app.apk      Use custom classification rules
  %(prog)s --output-format json app.apk        Output as JSON
        """
    )
    parser.add_argument(
        'paths', nargs='*',
        help='Path to APK/AAB file(s). Provide one to analyze, two to compare.'
    )
    parser.add_argument(
        '--rules',
        help='Path to a JSON file with custom package classification rules.'
    )
    parser.add_argument(
        '--output-format',
        choices=['text', 'json'],
        default='text',
        help='Output format: text (default) or json.'
    )
    args = parser.parse_args()

    targets = args.paths

    valid_targets = []
    if targets:
        for t in targets:
            if os.path.exists(t):
                valid_targets.append(t)
            else:
                print(f"Error: Path not found: {t}")

    if not valid_targets:
        apks_dir = os.path.join(os.getcwd(), 'apks')
        if not os.path.exists(apks_dir):
            os.makedirs(apks_dir)
            print("============================================================")
            print(f"📁 Created an 'apks' directory at:\n   {apks_dir}")
            print("Please drag and drop your APK/AAB files into this folder,")
            print("or directly input their paths below.")
            print("============================================================\n")
        else:
            apks_found = find_apk_file_list(apks_dir)
            if len(apks_found) > 0:
                print(f"Found {len(apks_found)} APK/AAB file(s) in the 'apks' directory:")
                for f in apks_found:
                    print(f"  - {os.path.basename(f)}")
                if len(apks_found) <= 2:
                    try:
                        use_auto = input("Do you want to use these files? (Y/n): ").strip().lower()
                        if use_auto != 'n':
                            valid_targets.extend(apks_found)
                    except EOFError:
                        pass

        if not valid_targets:
            print("Please enter the APK/AAB file path(s).")
            print("To compare two files, enter them separated by space, or enter them one by one.")
            try:
                user_input = input("Path(s) (drag & drop file here or press Enter to auto-search): ").strip()
                if user_input:
                    import shlex
                    try:
                        inputs = shlex.split(user_input)
                        for inp in inputs:
                            if os.path.exists(inp):
                                valid_targets.append(inp)
                            else:
                                print(f"Error: File not found: {inp}")
                    except Exception:
                        inputs = user_input.split()
                        for inp in inputs:
                            if os.path.exists(inp):
                                valid_targets.append(inp)
            except EOFError:
                pass

    if not valid_targets:
        print("Searching for APK/AAB files in current directory...")
        found = find_apk_file(os.getcwd())
        if found:
            print(f"Found: {found}")
            valid_targets.append(found)

    # Build classification rules
    rules = build_rules(
        custom_rules_path=args.rules,
        apk_path=valid_targets[0] if valid_targets else None
    )

    if len(valid_targets) == 1:
        result = get_apk_analysis(valid_targets[0], rules, silent=False)
        if result['success']:
            if args.output_format == 'json':
                analyze_apk_json(result)
            else:
                auto_package_mapping([result], args.rules)
                analyze_apk_text(result)
    elif len(valid_targets) >= 2:
        res1 = get_apk_analysis(valid_targets[0], rules, silent=args.output_format == 'json')
        res2 = get_apk_analysis(valid_targets[1], rules, silent=args.output_format == 'json')
        
        if res1['success'] and res2['success'] and args.output_format != 'json':
            auto_package_mapping([res1, res2], args.rules)
            
        if args.output_format == 'json':
            compare_apks_json(valid_targets[0], valid_targets[1], res1, res2)
        else:
            compare_apks_text(valid_targets[0], valid_targets[1], res1, res2)
    else:
        print("No APK/AAB file found. Please provide a path or build the project.")