---
name: analyze-hprof
description: "Analyze Java/Android HPROF heap dump files to identify memory issues, generate class histograms, and provide optimization recommendations. Use this skill whenever the user mentions heap dump, hprof, memory analysis, OOM investigation, memory leak detection, or wants to understand what is consuming JVM or Android Dalvik heap memory."
metadata:
  short-description: "General Java/Android HPROF memory analysis and optimization"
---

# Analyze HPROF Heap Dump

Analyze standard Java and Android HPROF heap dump files to produce actionable memory reports.

## Workflow

### 1. Locate and Validate the HPROF File

Confirm the file exists and check its size. Standard Java HPROF files (e.g., from `jmap`, Spring Boot, or `-XX:+HeapDumpOnOutOfMemoryError`) are ready for analysis out-of-the box. Android Dalvik heap dumps require conversion prior to analysis.

### 2. Convert if Needed (Android Only)

Android heap dumps use a non-standard Dalvik format. Convert them using the Android SDK tool:

```bash
hprof-conv <input.hprof> /tmp/memory-std.hprof
```

Find `hprof-conv` at: `$ANDROID_HOME/platform-tools/hprof-conv` or search with:
```bash
find ~/Library/Android/sdk -name "hprof-conv" 2>/dev/null | head -1
```

If the file is already in standard J2SE format (from standard JVMs), skip this step and use the original file.

### 3. Run the Analysis Script

Execute the bundled analysis script:

```bash
python3 <skill-base-dir>/scripts/analyze_hprof.py /tmp/memory-std.hprof > /tmp/hprof_result.txt 2>&1
```
*(If you skipped conversion, replace `/tmp/memory-std.hprof` with the original file path)*

Read and present the full output to the user.

### 4. Interpret Results and Provide Recommendations

After getting the histogram data, provide a structured analysis:

#### Memory Breakdown Table
Create a clear breakdown table showing the top memory consumers with:
- Class/type name
- Instance count
- Shallow size (MB)
- Percentage of total heap

#### Categorize Findings
Group findings into actionable categories:

| Category | What to Look For | Typical Causes |
|----------|-----------------|----------------|
| **Primitive arrays** | `byte[]`, `char[]`, `int[]` | DB buffers, Image/Network caches, serialized data, large payloads |
| **String bloat** | `java.lang.String` with high count | JSON parsing residue, excessive logging, duplicated strings, HTTP request caches |
| **JSON/Serialization residue** | `LinkedTreeMap`, `HashMap`, Jackson/Gson nodes | Deserializing large JSON into raw Maps instead of typed objects/POJOs |
| **Framework/UI leaks** | View/Activity classes, UI Components | UI components or contexts not gracefully destroyed; Static DOM/View references |
| **Collection overhead** | `HashMap$Node[]`, `ArrayList`, `ConcurrentHashMap$Node` | Unbounded collections, Session caching, ThreadLocal maps, redundant caches |
| **Classloader/Thread leaks** | `ThreadLocalMap$Entry`, custom ClassLoaders | Unbounded thread pools, un-cleaned ThreadLocals in web servers |

#### Optimization Recommendations
Provide prioritized (P0/P1/P2) recommendations with:
- What to fix
- Estimated memory savings
- Concrete JVM / Android code-level suggestions

### 5. Deep Dive (Optional)

If the user wants deeper analysis on specific classes:
- The script output shows shallow size only. Explain that retained size (the real impact) is usually much larger.
- Suggest using Eclipse MAT (Memory Analyzer Tool) or Android Studio Memory Profiler for dominator tree analysis.
- Offer to search the codebase for specific classes to trace the root cause.

## Key Concepts for Interpretation

- **Shallow size**: Memory consumed by the object itself (fields only)
- **Retained size**: Memory that would be freed if this object were garbage collected (includes referenced objects)
- **Dominator**: The object whose removal would free the most retained memory
- A single `byte[]` of 60MB could be one large buffer or millions of small ones — the count column tells you which
- High `String` count often correlates with JSON payload deserializations or heavy logging
- Unbounded collections are the most frequent JVM memory offenders — always look for massive `Map` and `List` implementations.

## Common JVM & Android Memory Patterns

1. **Unbounded Caches** — Collections (`HashMap`, `ArrayList`) growing continuously without size limits or eviction policies.
2. **ThreadLocal Leaks (JVM)** — Java EE/Spring typical issue: worker threads pool with lingering `ThreadLocal` variables continuously consuming memory.
3. **JSON to Map mappings** — Caching API responses as untyped `Map<String, Object>` creating thousands of small Node structures.
4. **Context/View Leaks (Android)** — Asynchronous operations holding static references to Activities/Views thereby preventing GC.
5. **Session Bloat (Backend)** — Keeping excessive user data within HTTP sessions without aggressive expiry.
