const express = require("express");
const prettier = require("prettier");
const { execFile } = require("child_process");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Languages supported by Prettier
const prettierLanguages = {
    javascript: "babel",
    js: "babel",
    jsx: "babel",
    typescript: "typescript",
    ts: "typescript",
    tsx: "typescript",
    json: "json",
    json5: "json5",
    html: "html",
    css: "css",
    scss: "scss",
    less: "less",
    markdown: "markdown",
    md: "markdown",
    yaml: "yaml",
    yml: "yaml"
};

// External formatter commands
const externalFormatters = {
    python: {
        command: "black",
        args: ["-q", "-"],
        stdin: true
    },

    py: {
        command: "black",
        args: ["-q", "-"],
        stdin: true
    },

    go: {
        command: "gofmt",
        args: [],
        stdin: true
    },

    rust: {
        command: "rustfmt",
        args: [],
        stdin: true
    },

    java: {
        command: "google-java-format",
        args: ["-"],
        stdin: true
    },

    c: {
        command: "clang-format",
        args: [],
        stdin: true
    },

    cpp: {
        command: "clang-format",
        args: [],
        stdin: true
    },

    csharp: {
        command: "dotnet-format",
        args: [],
        stdin: true
    },

    php: {
        command: "php-cs-fixer",
        args: ["fix", "--stdin"],
        stdin: true
    },

    sql: {
        command: "sql-formatter",
        args: [],
        stdin: true
    }
};

/**
 * Execute an external formatter.
 */
function runExternalFormatter(formatter, code) {
    return new Promise((resolve, reject) => {
        const child = execFile(
            formatter.command,
            formatter.args,
            {
                timeout: 15000,
                maxBuffer: 10 * 1024 * 1024
            },
            (error, stdout, stderr) => {
                if (error) {
                    reject(
                        new Error(
                            stderr ||
                            error.message ||
                            `Formatter "${formatter.command}" failed`
                        )
                    );
                    return;
                }

                resolve(stdout);
            }
        );

        if (formatter.stdin) {
            child.stdin.write(code);
            child.stdin.end();
        }
    });
}

/**
 * Format code using Prettier.
 */
async function formatWithPrettier(code, parser) {
    return await prettier.format(code, {
        parser,
        semi: true,
        singleQuote: true,
        tabWidth: 4,
        useTabs: false,
        trailingComma: "es5",
        printWidth: 100
    });
}

/**
 * POST /format
 *
 * Body:
 * {
 *   "language": "javascript",
 *   "code": "const x={a:1};"
 * }
 */
app.post("/format", async (req, res) => {
    try {
        const { language, code } = req.body;

        if (!language) {
            return res.status(400).json({
                success: false,
                error: "Language is required."
            });
        }

        if (typeof code !== "string") {
            return res.status(400).json({
                success: false,
                error: "Code must be a string."
            });
        }

        const normalizedLanguage = language
            .toLowerCase()
            .trim()
            .replace(/\./g, "");

        let formattedCode;

        // -----------------------------
        // Prettier
        // -----------------------------
        if (prettierLanguages[normalizedLanguage]) {
            formattedCode = await formatWithPrettier(
                code,
                prettierLanguages[normalizedLanguage]
            );
        }

        // -----------------------------
        // External formatters
        // -----------------------------
        else if (externalFormatters[normalizedLanguage]) {
            formattedCode = await runExternalFormatter(
                externalFormatters[normalizedLanguage],
                code
            );
        }

        // -----------------------------
        // Unsupported language
        // -----------------------------
        else {
            return res.status(400).json({
                success: false,
                error: `No formatter configured for "${language}".`
            });
        }

        return res.json({
            success: true,
            language: normalizedLanguage,
            code: formattedCode
        });

    } catch (error) {
        console.error("Formatting error:", error);

        return res.status(500).json({
            success: false,
            error: error.message || "Unable to format code."
        });
    }
});

/**
 * GET /languages
 *
 * Returns all languages supported by this server.
 */
app.get("/languages", (req, res) => {
    const prettier = Object.keys(prettierLanguages);
    const external = Object.keys(externalFormatters);

    const languages = [...new Set([...prettier, ...external])].sort();

    res.json({
        success: true,
        languages
    });
});

/**
 * Health check
 */
app.get("/health", (req, res) => {
    res.json({
        success: true,
        server: "Code Beautifier",
        status: "running",
        url: `http://localhost:${PORT}`
    });
});

/**
 * Serve frontend
 */
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

/**
 * Start server
 */
app.listen(PORT, () => {
    console.log("");
    console.log("========================================");
    console.log("       LOCAL CODE BEAUTIFIER");
    console.log("========================================");
    console.log("");
    console.log(`Server running at:`);
    console.log(`http://localhost:${PORT}`);
    console.log("");
    console.log("API:");
    console.log(`POST http://localhost:${PORT}/format`);
    console.log(`GET  http://localhost:${PORT}/languages`);
    console.log(`GET  http://localhost:${PORT}/health`);
    console.log("");
});
