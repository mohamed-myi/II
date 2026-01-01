"""
Shared constants for IssueIndex ingestion pipeline;
centralized for maintainability across services
"""

# Languages targeted by the Scout for repository discovery
SCOUT_LANGUAGES: list[str] = [
    "TypeScript",
    "Python",
    "Java",
    "JavaScript",
    "C++",
    "C#",
    "Go",
    "Rust",
    "Kotlin",
    "SQL",
]

# Language-specific tech keywords for Q-Score entity detection (E component)
# Gatherer pulls subset based on repo.primary_language
TECH_KEYWORDS_BY_LANGUAGE: dict[str, frozenset[str]] = {
    "Python": frozenset({
        "TypeError", "ImportError", "AttributeError", "KeyError", "ValueError",
        "RuntimeError", "asyncio", "async", "await", "FastAPI", "Django", "Flask",
        "pytest", "pip", "venv", "traceback", "Pydantic",
    }),
    "TypeScript": frozenset({
        "TypeError", "ReferenceError", "Promise", "async", "await", "React",
        "Node", "ESLint", "tsx", "interface", "type", "undefined", "null",
        "webpack", "Vite", "Next.js", "Angular",
    }),
    "JavaScript": frozenset({
        "TypeError", "ReferenceError", "Promise", "async", "await", "React",
        "Node", "Express", "npm", "undefined", "null", "callback", "fetch",
        "webpack", "Vite", "Vue",
    }),
    "Java": frozenset({
        "NullPointerException", "ClassCastException", "IllegalArgumentException",
        "Spring", "Maven", "Gradle", "JUnit", "Hibernate", "JVM", "OutOfMemoryError",
        "StackOverflowError", "IOException", "thread", "synchronized",
    }),
    "Go": frozenset({
        "goroutine", "channel", "panic", "defer", "context", "nil", "error",
        "interface", "struct", "go mod", "concurrency", "deadlock", "race",
    }),
    "Rust": frozenset({
        "unwrap", "Result", "Option", "panic", "async", "tokio", "cargo",
        "borrow", "lifetime", "ownership", "unsafe", "Send", "Sync", "Arc", "Mutex",
    }),
    "C++": frozenset({
        "segfault", "nullptr", "CMake", "template", "RAII", "memory leak",
        "undefined behavior", "std::", "vector", "pointer", "reference",
        "constructor", "destructor", "SIGSEGV",
    }),
    "C#": frozenset({
        "NullReferenceException", "ArgumentException", "async", "await", "Task",
        "LINQ", "dotnet", "Entity Framework", "ASP.NET", "Unity", "garbage collection",
    }),
    "Kotlin": frozenset({
        "coroutine", "suspend", "Flow", "Gradle", "Spring", "null safety",
        "lateinit", "by lazy", "sealed", "data class", "Android", "Ktor",
    }),
    "SQL": frozenset({
        "JOIN", "INDEX", "deadlock", "transaction", "query", "SELECT", "INSERT",
        "UPDATE", "DELETE", "foreign key", "constraint", "performance", "slow query",
    }),
}

# Fallback keywords for languages not in TECH_KEYWORDS_BY_LANGUAGE
DEFAULT_TECH_KEYWORDS: frozenset[str] = frozenset({
    "error", "bug", "crash", "exception", "fail", "issue", "problem",
    "traceback", "stacktrace", "FATAL", "CRITICAL", "panic",
})

# Template headers indicating structured issue reports (H component)
TEMPLATE_HEADERS: frozenset[str] = frozenset({
    "## Description",
    "## Steps to Reproduce",
    "## Expected Behavior",
    "## Actual Behavior",
    "## Environment",
    "### Bug Report",
    "### Feature Request",
    "## Reproduction",
    "## Context",
    "### Describe the bug",
    "### To Reproduce",
    "### Expected behavior",
})

# Junk patterns indicating low-quality issues (P component)
JUNK_PATTERNS: tuple[str, ...] = (
    "+1",
    "me too",
    "same issue",
    "same here",
    "bump",
    "any update",
    "any progress",
)

