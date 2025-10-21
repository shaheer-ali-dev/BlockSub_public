import type { Express, Request, Response } from "express";
import fs from "fs";
import path from "path";
import { marked } from "marked";

function readApiDocMarkdown(): string {
  const mdPath = path.resolve(process.cwd(), "API_DOCUMENTATION.md");
  if (!fs.existsSync(mdPath)) {
    // Return empty placeholder when docs are removed
    return '# API Documentation\n\nDocumentation is not available.';
  }
  return fs.readFileSync(mdPath, "utf8");
}

function wrapHtml(body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BlockSub API Documentation</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary-color: #8b5cf6;
      --primary-hover: #7c3aed;
      --secondary-color: #06b6d4;
      --success-color: #10b981;
      --warning-color: #f59e0b;
      --error-color: #ef4444;
      --text-primary: #1f2937;
      --text-secondary: #6b7280;
      --bg-primary: #ffffff;
      --bg-secondary: #f9fafb;
      --bg-code: #f3f4f6;
      --border-color: #e5e7eb;
      --border-light: #f3f4f6;
      color-scheme: light;
    }
    
    @media (prefers-color-scheme: dark) {
      :root {
        --text-primary: #f9fafb;
        --text-secondary: #9ca3af;
        --bg-primary: #111827;
        --bg-secondary: #1f2937;
        --bg-code: #1f2937;
        --border-color: #374151;
        --border-light: #374151;
        color-scheme: dark;
      }
    }
    
    * {
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      margin: 0;
      padding: 0;
      line-height: 1.7;
      color: var(--text-primary);
      background-color: var(--bg-primary);
      font-size: 16px;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    /* Typography */
    h1, h2, h3, h4, h5, h6 {
      line-height: 1.3;
      margin-top: 2rem;
      margin-bottom: 1rem;
      font-weight: 600;
      color: var(--text-primary);
    }
    
    h1 {
      font-size: 2.5rem;
      margin-top: 0;
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      background-clip: text;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }
    
    h2 {
      font-size: 1.875rem;
      margin-top: 3rem;
      padding-bottom: 0.5rem;
      border-bottom: 2px solid var(--border-light);
    }
    
    h3 {
      font-size: 1.5rem;
      margin-top: 2rem;
      color: var(--primary-color);
    }
    
    h4 {
      font-size: 1.25rem;
      margin-top: 1.5rem;
    }
    
    /* Paragraphs and text */
    p {
      margin-bottom: 1.5rem;
      color: var(--text-secondary);
    }
    
    p:first-of-type {
      font-size: 1.125rem;
      color: var(--text-secondary);
    }
    
    /* Code styling */
    code {
      font-family: 'SF Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
      background: var(--bg-code);
      padding: 0.125rem 0.375rem;
      border-radius: 0.25rem;
      font-size: 0.875rem;
      font-weight: 500;
      border: 1px solid var(--border-color);
    }
    
    pre {
      background: var(--bg-code);
      padding: 1.5rem;
      border-radius: 0.75rem;
      overflow: auto;
      border: 1px solid var(--border-color);
      margin: 1.5rem 0;
      position: relative;
    }
    
    pre code {
      background: none;
      padding: 0;
      border: none;
      font-size: 0.875rem;
    }
    
    /* Tables */
    table {
      border-collapse: collapse;
      width: 100%;
      margin: 1.5rem 0;
      border-radius: 0.5rem;
      overflow: hidden;
      border: 1px solid var(--border-color);
    }
    
    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }
    
    th {
      background: var(--bg-secondary);
      font-weight: 600;
      color: var(--text-primary);
    }
    
    tr:last-child td {
      border-bottom: none;
    }
    
    /* Links */
    a {
      color: var(--primary-color);
      text-decoration: none;
      font-weight: 500;
      transition: color 0.2s ease;
    }
    
    a:hover {
      color: var(--primary-hover);
      text-decoration: underline;
    }
    
    /* Lists */
    ul, ol {
      margin: 1rem 0;
      padding-left: 1.5rem;
    }
    
    li {
      margin-bottom: 0.5rem;
      color: var(--text-secondary);
    }
    
    /* Table of Contents */
    .toc {
      background: var(--bg-secondary);
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin: 2rem 0;
      border: 1px solid var(--border-color);
    }
    
    .toc h2 {
      margin-top: 0;
      border-bottom: none;
    }
    
    /* Status badges */
    .status-badge {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .status-success {
      background-color: rgba(16, 185, 129, 0.1);
      color: var(--success-color);
    }
    
    .status-warning {
      background-color: rgba(245, 158, 11, 0.1);
      color: var(--warning-color);
    }
    
    .status-error {
      background-color: rgba(239, 68, 68, 0.1);
      color: var(--error-color);
    }
    
    /* HTTP methods */
    .http-method {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.75rem;
      border-radius: 0.375rem;
      font-size: 0.875rem;
      font-weight: 600;
      font-family: 'SF Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
    }
    
    .http-post {
      background-color: rgba(34, 197, 94, 0.1);
      color: #16a34a;
    }
    
    .http-get {
      background-color: rgba(59, 130, 246, 0.1);
      color: #2563eb;
    }
    
    /* Checkboxes in lists */
    li:has(input[type="checkbox"]) {
      list-style: none;
      margin-left: -1.5rem;
    }
    
    input[type="checkbox"] {
      margin-right: 0.5rem;
    }
    
    /* Separators */
    hr {
      border: none;
      height: 1px;
      background: var(--border-color);
      margin: 3rem 0;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
      .container {
        padding: 1rem;
      }
      
      h1 {
        font-size: 2rem;
      }
      
      h2 {
        font-size: 1.5rem;
      }
      
      h3 {
        font-size: 1.25rem;
      }
      
      pre {
        padding: 1rem;
        overflow-x: scroll;
      }
      
      table {
        font-size: 0.875rem;
      }
      
      th, td {
        padding: 0.5rem;
      }
    }
    
    /* Scroll behavior */
    html {
      scroll-behavior: smooth;
    }
  </style>
</head>
<body>
  <div class="container">${body}</div>
  <script>
    (function() {
      function postHeight() {
        try {
          var h = document.documentElement.scrollHeight || document.body.scrollHeight || 0;
          parent.postMessage({ type: 'blocksub-docs-height', height: h }, '*');
        } catch (e) {}
      }
      window.addEventListener('load', postHeight);
      window.addEventListener('resize', function(){ setTimeout(postHeight, 50); });
      window.addEventListener('message', function(event) {
        try {
          if (event && event.data && event.data.type === 'blocksub-docs-request-height') {
            postHeight();
          }
        } catch (e) {}
      });
      // Also periodically post height in case of content that expands after load
      setInterval(postHeight, 1000);
    })();
  </script>
</body>
</html>`;
}

export function registerDocsRoutes(app: Express) {
  // Raw markdown
  app.get("/api/docs/raw", (_req: Request, res: Response) => {
    try {
      const md = readApiDocMarkdown();
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(md);
    } catch (e: any) {
      res.status(404).json({ error: "not_found", message: e?.message || "Docs not found" });
    }
  });

  // Rendered HTML
  app.get("/api/docs/html", (_req: Request, res: Response) => {
    try {
      const md = readApiDocMarkdown();
      const html = marked.parse(md);
      const page = wrapHtml(String(html));
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(page);
    } catch (e: any) {
      res.status(404).send("Documentation not found");
    }
  });
}
