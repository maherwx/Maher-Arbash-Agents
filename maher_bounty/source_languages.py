"""Language inventory and syntax-independent candidate checks for text source."""
import re


EXTENSIONS = {
    "python": "py pyi pyw", "javascript": "js jsx mjs cjs", "typescript": "ts tsx mts cts",
    "java": "java", "kotlin": "kt kts", "scala": "scala sc", "go": "go", "rust": "rs",
    "c": "c h", "cpp": "cc cpp cxx hpp hh hxx", "csharp": "cs", "fsharp": "fs fsx",
    "php": "php phtml", "ruby": "rb rake gemspec", "swift": "swift", "objective_c": "m mm",
    "dart": "dart", "lua": "lua", "perl": "pl pm", "r": "r rmd", "julia": "jl",
    "elixir": "ex exs", "erlang": "erl hrl", "haskell": "hs lhs", "ocaml": "ml mli",
    "clojure": "clj cljs cljc edn", "lisp": "lisp lsp el scm", "groovy": "groovy gradle",
    "shell": "sh bash zsh fish", "powershell": "ps1 psm1 psd1", "sql": "sql",
    "solidity": "sol", "vyper": "vy", "zig": "zig", "nim": "nim", "d": "d",
    "pascal": "pas pp", "fortran": "f f90 f95", "cobol": "cob cbl", "ada": "adb ads",
    "html": "html htm", "css": "css scss sass less", "vue": "vue", "svelte": "svelte",
    "yaml": "yml yaml", "json": "json jsonc", "toml": "toml", "xml": "xml xsd xsl",
    "terraform": "tf tfvars", "protobuf": "proto", "graphql": "graphql gql", "make": "mk",
}
BY_EXTENSION = {"." + suffix: language for language, suffixes in EXTENSIONS.items() for suffix in suffixes.split()}

CHECKS = [
    ("embedded-private-key", "CWE-798", "Private key material marker in source", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("disabled-tls-check", "CWE-295", "Certificate verification appears disabled", r"\b(?:verify|rejectUnauthorized|InsecureSkipVerify|CURLOPT_SSL_VERIFYPEER)\s*[:=,]\s*(?:False|false|true|0)\b"),
    ("dynamic-evaluation", "CWE-95", "Dynamic evaluation call requires input review", r"\b(?:eval|exec|ExecuteScript|Invoke-Expression)\s*\("),
    ("legacy-memory-copy", "CWE-120", "Unbounded memory/string API requires bounds review", r"\b(?:strcpy|strcat|gets|sprintf)\s*\("),
    ("raw-html-write", "CWE-79", "Raw HTML sink requires input review", r"\b(?:innerHTML|outerHTML)\s*=|\bdocument\s*\.\s*write\s*\("),
]


def language_for(path, text):
    if path.name in {"Dockerfile", "Containerfile"}:
        return "dockerfile"
    if path.name in {"Makefile", "GNUmakefile"}:
        return "make"
    language = BY_EXTENSION.get(path.suffix.lower())
    if language:
        return language
    first = text.split("\n", 1)[0][:200]
    if first.startswith("#!"):
        for marker, language in (("python", "python"), ("node", "javascript"), ("ruby", "ruby"), ("perl", "perl"), ("sh", "shell")):
            if marker in first:
                return language
    return "other_text"


def generic_candidates(text, relative, digest):
    rows = []
    for identifier, cwe, title, pattern in CHECKS:
        for match in re.finditer(pattern, text):
            # Avoid the ambiguous truth value in the cross-language TLS check.
            if identifier == "disabled-tls-check":
                token = match.group(0)
                if "InsecureSkipVerify" in token:
                    if not re.search(r"\btrue\s*$", token):
                        continue
                elif re.search(r"\btrue\s*$", token):
                    continue
            rows.append({"title": title, "cwe": cwe, "rule_id": identifier, "file": relative,
                         "file_sha256": digest, "line": text.count("\n", 0, match.start()) + 1,
                         "source": "local_generic_text", "validated": False, "status": "needs_review",
                         "confidence": "heuristic", "evidence": "Textual risk marker only; no dataflow or runtime proof"})
            if len(rows) >= 200:
                return rows
    return rows
