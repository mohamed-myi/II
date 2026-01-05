"""
Shared constants for services, centralized for maintainability
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



# Supported languages for profile
PROFILE_LANGUAGES: list[str] = SCOUT_LANGUAGES

# Stack areas for Quick Start onboarding
STACK_AREAS: dict[str, str] = {
    "backend": "APIs, servers, databases",
    "frontend": "UI, web, mobile",
    "data_engineering": "Pipelines, ETL, warehousing",
    "machine_learning": "Models, training, inference",
    "devops": "CI/CD, cloud, containers",
    "security": "Auth, encryption, vulnerabilities",
    "cli_tooling": "Developer tools, automation",
    "systems": "Low-level, embedded, performance",
}

# Minimal skill taxonomy for resume parsing normalization
# Keys are lowercase for matching; values contain standard form and aliases
SKILL_TAXONOMY: dict[str, dict] = {
    # Languages (map to canonical names)
    "python": {"canonical": "Python", "aliases": ["python3", "py"], "category": "language"},
    "typescript": {"canonical": "TypeScript", "aliases": ["ts"], "category": "language"},
    "javascript": {"canonical": "JavaScript", "aliases": ["js", "node.js", "nodejs"], "category": "language"},
    "java": {"canonical": "Java", "aliases": [], "category": "language"},
    "go": {"canonical": "Go", "aliases": ["golang"], "category": "language"},
    "rust": {"canonical": "Rust", "aliases": [], "category": "language"},
    "c++": {"canonical": "C++", "aliases": ["cpp", "c plus plus"], "category": "language"},
    "c#": {"canonical": "C#", "aliases": ["csharp", "c sharp"], "category": "language"},
    "kotlin": {"canonical": "Kotlin", "aliases": [], "category": "language"},
    "sql": {"canonical": "SQL", "aliases": ["mysql", "postgresql", "postgres"], "category": "language"},
    
    # Frontend frameworks
    "react": {"canonical": "React", "aliases": ["react.js", "reactjs"], "category": "frontend_framework"},
    "vue": {"canonical": "Vue", "aliases": ["vue.js", "vuejs"], "category": "frontend_framework"},
    "angular": {"canonical": "Angular", "aliases": ["angularjs"], "category": "frontend_framework"},
    "next.js": {"canonical": "Next.js", "aliases": ["nextjs", "next"], "category": "frontend_framework"},
    "svelte": {"canonical": "Svelte", "aliases": ["sveltekit"], "category": "frontend_framework"},
    
    # Backend frameworks
    "fastapi": {"canonical": "FastAPI", "aliases": [], "category": "backend_framework"},
    "django": {"canonical": "Django", "aliases": [], "category": "backend_framework"},
    "flask": {"canonical": "Flask", "aliases": [], "category": "backend_framework"},
    "express": {"canonical": "Express", "aliases": ["express.js", "expressjs"], "category": "backend_framework"},
    "spring": {"canonical": "Spring", "aliases": ["spring boot", "springboot"], "category": "backend_framework"},
    
    # Databases
    "postgresql": {"canonical": "PostgreSQL", "aliases": ["postgres", "psql"], "category": "database"},
    "mongodb": {"canonical": "MongoDB", "aliases": ["mongo"], "category": "database"},
    "redis": {"canonical": "Redis", "aliases": [], "category": "database"},
    "elasticsearch": {"canonical": "Elasticsearch", "aliases": ["elastic"], "category": "database"},
    
    # DevOps / Infrastructure
    "docker": {"canonical": "Docker", "aliases": [], "category": "devops"},
    "kubernetes": {"canonical": "Kubernetes", "aliases": ["k8s"], "category": "devops"},
    "terraform": {"canonical": "Terraform", "aliases": [], "category": "devops"},
    "aws": {"canonical": "AWS", "aliases": ["amazon web services"], "category": "cloud"},
    "gcp": {"canonical": "GCP", "aliases": ["google cloud", "google cloud platform"], "category": "cloud"},
    "azure": {"canonical": "Azure", "aliases": ["microsoft azure"], "category": "cloud"},
    
    # ML / Data
    "pytorch": {"canonical": "PyTorch", "aliases": ["torch"], "category": "ml_framework"},
    "tensorflow": {"canonical": "TensorFlow", "aliases": ["tf"], "category": "ml_framework"},
    "pandas": {"canonical": "Pandas", "aliases": [], "category": "data_library"},
    "numpy": {"canonical": "NumPy", "aliases": [], "category": "data_library"},
    "scikit-learn": {"canonical": "scikit-learn", "aliases": ["sklearn"], "category": "ml_framework"},
}


def normalize_skill(raw_skill: str) -> str | None:
    """
    Normalize a raw skill string to its canonical form.
    Returns None if skill is not in taxonomy.
    """
    key = raw_skill.lower().strip()

    if key in SKILL_TAXONOMY:
        return SKILL_TAXONOMY[key]["canonical"]

    for skill_key, skill_data in SKILL_TAXONOMY.items():
        if key in [alias.lower() for alias in skill_data["aliases"]]:
            return skill_data["canonical"]
    
    return None

