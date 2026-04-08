---
name: analyze-hprof
description: "Analyze Android HPROF heap dump files to identify memory issues, generate class histograms, and provide optimization recommendations. Use this skill whenever the user mentions Android heap dump, hprof, memory analysis, OOM investigation, memory leak detection, or wants to understand what is consuming Android app memory."
metadata:
  short-description: "Android HPROF memory analysis and optimization"
---

# Analyze Android HPROF Heap Dump

Analyze Android HPROF heap dump files to produce actionable memory reports.

## Workflow

### 1. Locate and Validate the HPROF File

Confirm the file exists and check its size. HPROF files exported from Android devices or Android Studio are typically in Dalvik format and require conversion before analysis.

### 2. Convert Dalvik HPROF

Android heap dumps use a non-standard format. Convert them to the standard J2SE format using the Android SDK tool:

```bash
hprof-conv <input.hprof> /tmp/memory-std.hprof
```

Find `hprof-conv` at: `$ANDROID_HOME/platform-tools/hprof-conv` or search with:
```bash
find ~/Library/Android/sdk -name "hprof-conv" 2>/dev/null | head -1
```

### 3. Run the Analysis Script

Execute the bundled analysis script:

```bash
python3 <skill-base-dir>/scripts/analyze_hprof.py /tmp/memory-std.hprof > /tmp/hprof_result.txt 2>&1
```

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
| **Primitive arrays** | `byte[]`, `char[]`, `int[]` | Image buffers, network response caching, large serialized payloads |
| **String bloat** | `java.lang.String` with high count | JSON parsing residue, excessive URL caching, redundant logging |
| **JSON/Serialization residue** | `LinkedTreeMap$Node`, `HashMap` | Deserializing large JSON into raw Maps instead of typed classes/POJOs |
| **View/Activity leaks** | Android `View`, `Activity`, `Fragment` classes | UI components, Contexts not gracefully destroyed or held by static references |
| **Collection overhead** | `HashMap$Node[]`, `ArrayList` | Over-sized or redundant in-memory caches, unbounded collections |
| **Framework overhead** | ConstraintLayout solver classes | Complex layout hierarchies, repetitive View inflation without recycling |

#### Optimization Recommendations
Provide prioritized (P0/P1/P2) recommendations with:
- What to fix
- Estimated memory savings
- Concrete Android code-level suggestions

### 5. Deep Dive (Optional)

If the user wants deeper analysis on specific classes:
- The script output shows shallow size only. Explain that retained size (the real impact) is usually much larger.
- Suggest using Android Studio Memory Profiler or Eclipse MAT for dominator tree analysis.
- Offer to search the codebase for specific classes to trace the root cause.

## Key Concepts for Interpretation

- **Shallow size**: Memory consumed by the object itself (fields only)
- **Retained size**: Memory that would be freed if this object were garbage collected (includes referenced objects)
- **Dominator**: The object whose removal would free the most retained memory
- A single `byte[]` of 60MB could be one large buffer or millions of small ones — the count column tells you which
- `LinkedTreeMap$Node` in large numbers almost always means Gson/JSON deserialized into untyped Maps — look for `MutableMap<String, Any?>` or `Object` in data classes.
- High `String` count often correlates with JSON payload parsing — each JSON key/value becomes a new String object.

## Common Android Memory Patterns

1. **Unbounded Caches** — Collections (`HashMap`, `ArrayList`) or `LruCache` growing continuously without proper size configurations.
2. **Context/View Leaks** — Asynchronous operations, animations, or Runnables holding static references to `Activity`, `Fragment`, or `View` preventing GC.
3. **JSON to Map mappings** — Caching API responses as untyped `Map<String, Object>` creating thousands of small objects.
4. **Bitmap caches without trim** — Image downloading libraries without proper `ComponentCallbacks2.onTrimMemory` integration.
5. **Static Companion Object Caches** — Holding onto large states globally without `WeakReference` or explicit lifecycle eviction.
6. **RecyclerView ViewHolder Leaks** — Retaining ViewHolders outside the Adapter context or improper pool sizes.
