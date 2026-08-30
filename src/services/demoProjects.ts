import type { DemoProject } from '@/types';

// ============================================================
// Demo Projects - Intentionally vulnerable and secure examples
// These are LOCAL demo applications created for testing.
// No real-world exploitation is performed.
// ============================================================

const vulnerableFastAPIApp = `# vulnerable_app.py
# FastAPI SQL Injection Demo Service
# WARNING: This file is intentionally vulnerable for security testing.
# Do NOT deploy this in production.

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import sqlite3
import uvicorn

app = FastAPI(title="Vulnerable FastAPI SQL Service")

DB_PATH = ":memory:"
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_cursor = _conn.cursor()
_cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)")
_cursor.execute("INSERT INTO users (username, email, role) VALUES ('admin', 'admin@demo.local', 'admin')")
_cursor.execute("INSERT INTO users (username, email, role) VALUES ('user1', 'user1@demo.local', 'user')")
_cursor.execute("INSERT INTO users (username, email, role) VALUES ('user2', 'user2@demo.local', 'user')")
_conn.commit()


@app.get("/api/users/search")
async def search_users(username: str = ""):
    # VULNERABLE: User input is directly concatenated into SQL query
    # This is a classic SQL Injection vulnerability.
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    
    try:
        _cursor.execute(query)
        results = _cursor.fetchall()
        if not results:
            raise HTTPException(status_code=404, detail="No users found")
        
        users = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in results]
        return JSONResponse(content={"users": users})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    # This endpoint uses parameterized queries (safe)
    _cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    result = _cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": result[0], "username": result[1], "email": result[2], "role": result[3]}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
`;

const secureFastAPIApp = `# secure_app.py
# FastAPI Secure SQL Service
# This version uses parameterized queries to prevent SQL injection.

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import sqlite3
import uvicorn

app = FastAPI(title="Secure FastAPI SQL Service")

DB_PATH = ":memory:"
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_cursor = _conn.cursor()
_cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)")
_cursor.execute("INSERT INTO users (username, email, role) VALUES ('admin', 'admin@demo.local', 'admin')")
_cursor.execute("INSERT INTO users (username, email, role) VALUES ('user1', 'user1@demo.local', 'user')")
_cursor.execute("INSERT INTO users (username, email, role) VALUES ('user2', 'user2@demo.local', 'user')")
_conn.commit()


@app.get("/api/users/search")
async def search_users(username: str = ""):
    # SECURE: Uses parameterized query with placeholder
    # User input is never concatenated into the SQL string.
    _cursor.execute(
        "SELECT id, username, email, role FROM users WHERE username = ?",
        (username,)
    )
    results = _cursor.fetchall()
    if not results:
        raise HTTPException(status_code=404, detail="No users found")
    
    users = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in results]
    return JSONResponse(content={"users": users})


@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    _cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    result = _cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": result[0], "username": result[1], "email": result[2], "role": result[3]}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
`;

const vulnerableNodeApp = `// vulnerable_server.js
// Express SQL Injection Demo Service
// WARNING: This file is intentionally vulnerable for security testing.

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = 3000;

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)");
  db.run("INSERT INTO products (name, price, category) VALUES ('Laptop', 999.99, 'electronics')");
  db.run("INSERT INTO products (name, price, category) VALUES ('Mouse', 29.99, 'electronics')");
  db.run("INSERT INTO products (name, price, category) VALUES ('Book', 14.99, 'books')");
});

app.get('/api/products/search', (req, res) => {
  const category = req.query.category || '';
  
  // VULNERABLE: Direct string concatenation into SQL query
  const query = "SELECT id, name, price, category FROM products WHERE category = '" + category + "'";
  
  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ products: rows });
  });
});

app.listen(port, () => {
  console.log(\`Vulnerable server running on port \${port}\`);
});
`;

const vulnerableCmdInjectionApp = `# vulnerable_cmd.py
# FastAPI Command Injection Demo Service
# WARNING: This file is intentionally vulnerable for security testing.
# Do NOT deploy this in production.

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import subprocess
import uvicorn

app = FastAPI(title="Vulnerable Command Execution Service")


@app.get("/api/ping")
async def ping_host(host: str = "127.0.0.1"):
    # VULNERABLE: User input is directly passed to os.system
    # This is a classic Command Injection vulnerability.
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Ping failed: {result.stderr}")
    return JSONResponse(content={"host": host, "output": result.stdout})


@app.get("/api/dns-lookup")
async def dns_lookup(domain: str = "example.com"):
    # VULNERABLE: User input concatenated into shell command
    result = subprocess.run(
        f"nslookup {domain}",
        shell=True,
        capture_output=True,
        text=True
    )
    return JSONResponse(content={"domain": domain, "output": result.stdout})


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
`;

const vulnerablePathTraversalApp = `# vulnerable_traversal.py
# FastAPI Path Traversal Demo Service
# WARNING: This file is intentionally vulnerable for security testing.

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import os
import uvicorn

app = FastAPI(title="Vulnerable File Access Service")

BASE_DIR = "/var/www/uploads"


@app.get("/api/files")
async def get_file(filename: str = "index.txt"):
    # VULNERABLE: User input directly concatenated into file path
    # Allows path traversal with ../ sequences
    filepath = os.path.join(BASE_DIR, filename)
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return JSONResponse(content={"filename": filename, "content": content})
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
`;

export const demoProjects: DemoProject[] = [
  {
    id: 'demo-vuln-fastapi-sqli',
    name: 'Vulnerable FastAPI SQL Service',
    description: 'A Python FastAPI application with an intentional SQL injection vulnerability in the user search endpoint. User input is directly concatenated into a SQL query string.',
    language: 'Python',
    framework: 'FastAPI',
    vulnerable: true,
    vulnerabilityClass: 'SQL_INJECTION',
    tags: ['sqli', 'python', 'fastapi', 'owasp-a03'],
    files: [
      {
        id: 'file-vuln-main',
        filename: 'app.py',
        path: 'app.py',
        language: 'python',
        content: vulnerableFastAPIApp,
        lineCount: vulnerableFastAPIApp.split('\n').length,
      },
    ],
  },
  {
    id: 'demo-secure-fastapi-sqli',
    name: 'Secure FastAPI SQL Service',
    description: 'A Python FastAPI application that uses parameterized queries to safely handle user input. This is the secure counterpart to the vulnerable demo.',
    language: 'Python',
    framework: 'FastAPI',
    vulnerable: false,
    tags: ['secure', 'python', 'fastapi', 'parameterized-queries'],
    files: [
      {
        id: 'file-secure-main',
        filename: 'app.py',
        path: 'app.py',
        language: 'python',
        content: secureFastAPIApp,
        lineCount: secureFastAPIApp.split('\n').length,
      },
    ],
  },
  {
    id: 'demo-vuln-node-sqli',
    name: 'Vulnerable Express SQL Service',
    description: 'A Node.js Express application with an intentional SQL injection vulnerability in the product search endpoint.',
    language: 'JavaScript',
    framework: 'Express',
    vulnerable: true,
    vulnerabilityClass: 'SQL_INJECTION',
    tags: ['sqli', 'nodejs', 'express', 'owasp-a03'],
    files: [
      {
        id: 'file-vuln-node-main',
        filename: 'server.js',
        path: 'server.js',
        language: 'javascript',
        content: vulnerableNodeApp,
        lineCount: vulnerableNodeApp.split('\n').length,
      },
    ],
  },
];

export function getDemoProject(id: string): DemoProject | undefined {
  return demoProjects.find((p) => p.id === id);
}
