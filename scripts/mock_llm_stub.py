"""A local OpenAI-compatible stub, used to exercise the live path offline.

Not a test double for the agent -- it is a test double for *a vendor*. It lets the
live code path (HTTP client, request encoding, response decoding, runtime assembly,
live trace marking, governance under a real provider) be verified end to end without
a network or a key, which is otherwise untested until someone configures one.

It deliberately behaves like a real model in the ways that matter for governance: it
proposes tool calls when asked, and it will happily claim it completed a refund if
that is what the prompt invites -- so the guardrail has something real to stop.

    python scripts/mock_llm_stub.py 8799
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# The last question seen, so the stub can react to what was actually asked.
STATE: dict[str, object] = {"turns": 0, "tools_seen": []}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # keep the console readable
        pass

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except ValueError:
            self._send(400, {"error": {"message": "invalid JSON"}})
            return

        if not self.headers.get("Authorization", "").startswith("Bearer "):
            self._send(401, {"error": {"message": "missing bearer token"}})
            return

        messages = body.get("messages") or []
        tools = [t["function"]["name"] for t in (body.get("tools") or [])]
        STATE["tools_seen"] = tools
        STATE["turns"] = int(STATE["turns"]) + 1

        question = ""
        for message in messages:
            if message.get("role") == "user":
                question = message.get("content", "")

        # Which tools have already run. This requires joining each tool *result*
        # message back to the assistant message that requested it: a tool result
        # carries `tool_call_id`, not a tool name, so reading `name` off it finds
        # nothing and the stub re-proposes the same call forever. Getting this wrong
        # in the stub was indistinguishable from a bug in the agent loop.
        requested: dict[str, str] = {}
        for message in messages:
            for call in message.get("tool_calls") or []:
                requested[call.get("id")] = (call.get("function") or {}).get("name")
        already_called = {
            requested.get(m.get("tool_call_id")) for m in messages if m.get("role") == "tool"
        }
        already_called.discard(None)

        message = self._decide(question, tools, already_called)
        self._send(
            200,
            {
                "choices": [{"message": message, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 42, "completion_tokens": 12, "total_tokens": 54},
            },
        )

    def _decide(self, question: str, tools: list[str], already_called: set) -> dict:
        """Propose a tool, or answer. Mimics a cooperative but not careful model."""

        def call(name: str, arguments: dict) -> dict:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call-{name}",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(arguments)},
                    }
                ],
            }

        lowered = question.lower()

        # A refund request: propose the dry-run tool once, then *overclaim* on
        # purpose, so the capability guardrail has something real to stop.
        if "退款" in question or "refund" in lowered:
            if "draft_refund" in tools and "draft_refund" not in already_called:
                return call("draft_refund", {"order_id": "ORD-1001", "reason": question})
            return {
                "role": "assistant",
                "content": "已为你完成退款，资金会在三个工作日内原路退回。",
            }

        # A policy question: retrieve first, then answer with a citation. The
        # citation id is one the real knowledge base actually contains, so the
        # grounding check has something valid to verify.
        if "退货" in question or "保修" in question or "return" in lowered or "warranty" in lowered:
            if "search_knowledge_base" in tools and "search_knowledge_base" not in already_called:
                return call("search_knowledge_base", {"query": question, "top_k": 3})
            return {
                "role": "assistant",
                "content": (
                    "普通商品在签收后 30 天内可以申请退货（依据【returns#standard-window】）。"
                ),
            }

        # A deletion request: propose it so policy has to refuse it.
        if "删除" in question or "delete" in lowered:
            if "delete_file" in tools and "delete_file" not in already_called:
                return call("delete_file", {"path": "notes.md"})
            return {"role": "assistant", "content": "文件已删除。"}

        return {
            "role": "assistant",
            "content": "我无法从现有信息回答这个问题。请补充订单号或更具体的问题。",
        }

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"mock OpenAI-compatible stub listening on http://127.0.0.1:{port}/v1", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
