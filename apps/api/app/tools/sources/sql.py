"""Read-only SQL over a sandboxed SQLite database.

Three layers stop a write, and all three are deliberate:

1. **The policy engine** rejects anything that is not a SELECT-style statement
   before the tool is reached (``constraints.read_only`` in the ruleset).
2. **The tool opens the database read-only** -- ``mode=ro`` on a file URI, so the
   connection physically cannot write. This is the layer that matters: policy
   decides intent from a query string, and a string can be crafted, but a
   read-only connection cannot be talked into a write.
3. **``PRAGMA query_only``** as a third guard, in case the URI form is unavailable
   on an older SQLite build.

The practical difference from the archived implementation: that one blocked writes
purely by matching verbs against the query text, which is a decision made by
pattern-matching user input. Layers 2 and 3 make the guarantee structural.

The database is seeded on demand from a fixture so a fresh checkout has something
real to query without shipping a binary file.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from app.core.errors import ToolArgumentError, ToolExecutionError
from app.tools.sources.local import LocalTool, LocalToolSource

MAX_ROWS = 200
DEFAULT_ROW_LIMIT = 50

SCHEMA = """
CREATE TABLE orders (
    order_id     TEXT PRIMARY KEY,
    customer     TEXT NOT NULL,
    status       TEXT NOT NULL,
    total_cents  INTEGER NOT NULL,
    placed_on    TEXT NOT NULL,
    delivered_on TEXT
);
CREATE TABLE refunds (
    refund_id  TEXT PRIMARY KEY,
    order_id   TEXT NOT NULL REFERENCES orders(order_id),
    amount_cents INTEGER NOT NULL,
    state      TEXT NOT NULL,
    created_on TEXT NOT NULL
);
"""

SEED_ORDERS = [
    ("ORD-1001", "张伟", "delivered", 25900, "2026-06-01", "2026-06-04"),
    ("ORD-1002", "李娜", "shipped", 8900, "2026-06-11", None),
    ("ORD-1003", "王强", "pending", 129900, "2026-06-20", None),
    ("ORD-1004", "赵敏", "delivered", 4900, "2026-05-02", "2026-05-06"),
    ("ORD-1005", "陈静", "returned", 15900, "2026-04-18", "2026-04-22"),
]

SEED_REFUNDS = [
    ("REF-01", "ORD-1005", 15900, "draft", "2026-04-25"),
    ("REF-02", "ORD-1001", 25900, "rejected", "2026-06-10"),
]


def seed_database(path: Path) -> None:
    """Create the database if it does not exist. Idempotent."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # The seed connection is the only writable one, and it exists solely to build
    # the fixture.
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA)
        connection.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?)", SEED_ORDERS)
        connection.executemany("INSERT INTO refunds VALUES (?,?,?,?,?)", SEED_REFUNDS)
        connection.commit()
    finally:
        connection.close()


def build_sql_source(database: Path) -> LocalToolSource:
    seed_database(database)
    uri = f"file:{database.as_posix()}?mode=ro"

    def query_sql(arguments: dict[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", "")).strip()
        if not query:
            raise ToolArgumentError("query must be a non-empty string")
        if len(query) > 4000:
            raise ToolArgumentError("query is too long")

        raw_limit = arguments.get("row_limit", DEFAULT_ROW_LIMIT)
        try:
            row_limit = int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise ToolArgumentError("row_limit must be an integer") from exc
        row_limit = max(1, min(row_limit, MAX_ROWS))

        # `mode=ro` protects *this* database. `ATTACH` opens a second one whose
        # permissions are the filesystem's, and `VACUUM INTO` writes a file too, so
        # both are refused here rather than left to the policy layer. This test
        # reached the tool directly and passed on Windows only because `/tmp` did
        # not exist there; CI on Linux showed an attached database being created.
        first_word = query.lstrip("( \t\r\n").split(None, 1)[0].lower() if query.strip() else ""
        if first_word in {"attach", "detach", "vacuum"}:
            raise ToolExecutionError(
                f"{first_word.upper()} is refused: a read-only connection protects the "
                "database it opened, not one attached afterwards"
            )

        try:
            # uri=True plus mode=ro is the structural guarantee: this connection
            # cannot perform a write even if the statement somehow got past the
            # policy engine.
            connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        except sqlite3.Error as exc:
            raise ToolExecutionError(f"could not open the database read-only: {exc}") from exc

        try:
            connection.execute("PRAGMA query_only = ON")
            cursor = connection.execute(query)
            columns = [description[0] for description in cursor.description or []]
            rows = cursor.fetchmany(row_limit)
        except sqlite3.OperationalError as exc:
            # A read-only connection reports a write attempt as an operational
            # error; surfacing it as INVALID_ARGS keeps it distinguishable from an
            # outage, and the message names the refusal.
            message = str(exc)
            if "readonly" in message or "query_only" in message or "attempt to write" in message:
                raise ToolExecutionError(
                    f"the database refused this statement in read-only mode: {message}"
                ) from exc
            raise ToolArgumentError(f"SQL error: {message}") from exc
        except sqlite3.Error as exc:
            raise ToolArgumentError(f"SQL error: {exc}") from exc
        finally:
            connection.close()

        return {
            "columns": columns,
            "rows": [list(row) for row in rows],
            "row_count": len(rows),
            "row_limit": row_limit,
            "truncated": len(rows) == row_limit,
        }

    def describe_schema(arguments: dict[str, Any]) -> dict[str, Any]:
        """Show tables and columns, so an agent can write a valid query.

        Takes no arguments. Extra ones are refused rather than ignored: silently
        accepting a ``query`` here and not running it would make the tool look like
        it honoured a request it discarded.
        """
        if arguments:
            raise ToolArgumentError(f"sql_schema takes no arguments, got {sorted(arguments)}")
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            connection.execute("PRAGMA query_only = ON")
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
            schema: dict[str, list[dict[str, Any]]] = {}
            for table in tables:
                schema[table] = [
                    {
                        "column": row[1],
                        "type": row[2],
                        "nullable": not row[3],
                        "primary_key": bool(row[5]),
                    }
                    for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
                ]
            return {"tables": tables, "schema": schema}
        finally:
            connection.close()

    def execute_write(arguments: dict[str, Any]) -> dict[str, Any]:
        """Registered, reachable, and inert.

        It exists so the ``default_block`` rule in the ruleset has something to block.
        A rule for a tool that does not exist proves nothing: "it did not run" would
        be true for the wrong reason.
        """
        query = str(arguments.get("query", "")).strip()
        if not query:
            raise ToolArgumentError("query must be a non-empty string")
        return {
            "executed": False,
            "query": query,
            "note": (
                "Refused by the tool itself, independently of the policy rule that "
                "should already have blocked this call. The database is opened "
                "read-only, so a write cannot occur here even if invoked directly."
            ),
        }

    return LocalToolSource(
        [
            LocalTool(
                name="sql_query",
                run=query_sql,
                description=(
                    "Run a read-only SELECT against the sample commerce database. "
                    "Writes, schema changes and stacked statements are refused."
                ),
                action_type="read",
                resource_type="database",
                risk_level="medium",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "row_limit": {"type": "integer", "default": DEFAULT_ROW_LIMIT},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
            LocalTool(
                name="sql_schema",
                run=describe_schema,
                description="List the tables and columns available to sql_query.",
                action_type="read",
                resource_type="database",
                risk_level="low",
                parameters={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            LocalTool(
                name="sql_execute_write",
                run=execute_write,
                description="Mutate the database. Blocked by policy; refused by the tool.",
                action_type="destructive",
                resource_type="database",
                risk_level="critical",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
        ],
        name="local:sql",
    )
