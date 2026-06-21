"""
apisec/llm.py
Unified LLM adapter. Supports Claude (Anthropic) and Groq.
The rest of the agent never touches the API directly -- it calls this.

Usage:
    from apisec.llm import LLM
    llm = LLM(provider="groq")     # or "claude"
    response = llm.chat(system=..., messages=..., tools=...)
    # response.text      -- assistant text
    # response.tool_calls -- list of {name, id, input}
    # response.done      -- True if no more tool calls
"""

import os
import json
import httpx
from typing import Optional


# -- Unified response object ---------------------------------------
class LLMResponse:
    def __init__(self, text: str, tool_calls: list, done: bool, raw=None):
        self.text        = text
        self.tool_calls  = tool_calls   # [{name, id, input}]
        self.done        = done
        self.raw         = raw          # original SDK response


# -- Provider: Anthropic (Claude) ---------------------------------
class _ClaudeBackend:
    MODEL = "claude-sonnet-4-6"

    def __init__(self):
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not set.\n"
                "Run: export ANTHROPIC_API_KEY=sk-ant-YOUR_KEY"
            )
        self.client = anthropic.Anthropic(api_key=key)

    def chat(self, system: str, messages: list, tools: list) -> LLMResponse:
        resp = self.client.messages.create(
            model     = self.MODEL,
            max_tokens= 4096,
            system    = system,
            tools     = tools,
            messages  = messages,
        )

        text       = ""
        tool_calls = []
        for blk in resp.content:
            if blk.type == "text":
                text += blk.text
            elif blk.type == "tool_use":
                tool_calls.append({
                    "name":  blk.name,
                    "id":    blk.id,
                    "input": blk.input,
                })

        done = resp.stop_reason == "end_turn" and not tool_calls
        return LLMResponse(text=text, tool_calls=tool_calls, done=done, raw=resp)

    def build_assistant_msg(self, resp: LLMResponse):
        """Return raw content for appending to messages history."""
        return resp.raw.content

    def build_tool_result_msg(self, tool_results: list):
        """tool_results = [{tool_use_id, content}]"""
        return {
            "role": "user",
            "content": [
                {"type": "tool_result",
                 "tool_use_id": r["tool_use_id"],
                 "content": r["content"]}
                for r in tool_results
            ]
        }


# -- Provider: Groq ------------------------------------------------
class _GroqBackend:
    # llama-3.3-70b has the best tool-calling on Groq
    MODEL = "llama-3.3-70b-versatile"

    def __init__(self):
        try:
            from groq import Groq
        except ImportError:
            raise RuntimeError(
                "groq package not installed.\n"
                "Run: pip install groq"
            )
        key = os.environ.get("GROQ_API_KEY")
        if not key:
            raise RuntimeError(
                "GROQ_API_KEY not set.\n"
                "Get a free key at console.groq.com then run:\n"
                "export GROQ_API_KEY=gsk_YOUR_KEY"
            )
        from groq import Groq
        self.client = Groq(api_key=key)

    def _convert_tools(self, tools: list) -> list:
        """
        Convert Anthropic tool schema -> OpenAI/Groq tool schema.
        Anthropic: {name, description, input_schema}
        Groq:      {type:"function", function:{name, description, parameters}}
        """
        converted = []
        for t in tools:
            converted.append({
                "type": "function",
                "function": {
                    "name":        t["name"],
                    "description": t.get("description",""),
                    "parameters":  t.get("input_schema", {"type":"object","properties":{}}),
                }
            })
        return converted

    def _convert_messages(self, messages: list) -> list:
        """
        Convert message history to Groq format.
        Handles tool_result content blocks from Anthropic format.
        """
        out = []
        for msg in messages:
            role    = msg["role"]
            content = msg["content"]

            # Anthropic sends assistant content as a list of blocks
            if isinstance(content, list):
                # Check if it's tool results (user role with tool_result blocks)
                if role == "user" and all(
                    isinstance(b, dict) and b.get("type") == "tool_result"
                    for b in content
                ):
                    # Convert each tool result to Groq tool message
                    for block in content:
                        out.append({
                            "role":         "tool",
                            "tool_call_id": block["tool_use_id"],
                            "content":      block["content"],
                        })
                    continue

                # Assistant content blocks -- extract text + tool calls
                text_parts = []
                tool_calls = []
                for block in content:
                    if hasattr(block, "type"):
                        # Anthropic SDK objects
                        if block.type == "text":
                            text_parts.append(block.text)
                        elif block.type == "tool_use":
                            tool_calls.append({
                                "id":   block.id,
                                "type": "function",
                                "function": {
                                    "name":      block.name,
                                    "arguments": json.dumps(block.input),
                                }
                            })
                    elif isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text",""))
                        elif block.get("type") == "tool_use":
                            tool_calls.append({
                                "id":   block["id"],
                                "type": "function",
                                "function": {
                                    "name":      block["name"],
                                    "arguments": json.dumps(block.get("input",{})),
                                }
                            })

                groq_msg = {"role": role, "content": " ".join(text_parts) or None}
                if tool_calls:
                    groq_msg["tool_calls"] = tool_calls
                out.append(groq_msg)
            else:
                # Plain string content
                entry = {"role": role, "content": content}
                if msg.get("tool_calls"):
                    entry["tool_calls"] = msg["tool_calls"]
                if msg.get("tool_call_id"):
                    entry["tool_call_id"] = msg["tool_call_id"]
                out.append(entry)

        return out

    def chat(self, system: str, messages: list, tools: list) -> LLMResponse:
        groq_messages = [{"role":"system","content":system}] + self._convert_messages(messages)
        groq_tools    = self._convert_tools(tools)

        resp = self.client.chat.completions.create(
            model      = self.MODEL,
            messages   = groq_messages,
            tools      = groq_tools,
            tool_choice= "auto",
            max_tokens = 4096,
        )

        msg        = resp.choices[0].message
        text       = msg.content or ""
        tool_calls = []

        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except Exception:
                    args = {}
                tool_calls.append({
                    "name":  tc.function.name,
                    "id":    tc.id,
                    "input": args,
                })

        done = not tool_calls and resp.choices[0].finish_reason in ("stop", "end_turn")
        return LLMResponse(text=text, tool_calls=tool_calls, done=done, raw=resp)

    def build_assistant_msg(self, resp: LLMResponse):
        """Build assistant message to append to history."""
        msg = resp.raw.choices[0].message
        assistant = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            assistant["tool_calls"] = [
                {
                    "id":   tc.id,
                    "type": "function",
                    "function": {
                        "name":      tc.function.name,
                        "arguments": tc.function.arguments,
                    }
                }
                for tc in msg.tool_calls
            ]
        return assistant

    def build_tool_result_msg(self, tool_results: list):
        """tool_results = [{tool_use_id, content}] -> list of tool messages"""
        # Groq needs separate message per tool result
        return [
            {
                "role":         "tool",
                "tool_call_id": r["tool_use_id"],
                "content":      r["content"],
            }
            for r in tool_results
        ]


# -- Provider: DeepSeek (OpenAI-compatible via httpx) -----------------
class _DeepSeekBackend:
    BASE = "https://api.deepseek.com/v1"
    MODELS = {
        "deepseek-chat":   "deepseek-chat",
        "deepseek-reasoner": "deepseek-reasoner",
        "deepseek-v4-pro":  "deepseek-v4-pro",
        "deepseek-v4-flash": "deepseek-v4-flash",
    }

    def __init__(self, model: str = "deepseek-v4-flash"):
        self.model = self.MODELS.get(model, model)
        key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY not set.\n"
                "Run: export DEEPSEEK_API_KEY=sk-YOUR_KEY"
            )
        self.api_key = key
        self.client = httpx.Client(base_url=self.BASE, timeout=60)

    def _convert_tools(self, tools: list) -> list:
        converted = []
        for t in tools:
            converted.append({
                "type": "function",
                "function": {
                    "name":        t["name"],
                    "description": t.get("description", ""),
                    "parameters":  t.get("input_schema", {"type": "object", "properties": {}}),
                }
            })
        return converted

    def _convert_messages(self, messages: list) -> list:
        out = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if isinstance(content, list):
                if role == "user" and all(
                    isinstance(b, dict) and b.get("type") == "tool_result"
                    for b in content
                ):
                    for block in content:
                        out.append({
                            "role": "tool",
                            "tool_call_id": block["tool_use_id"],
                            "content": block["content"],
                        })
                    continue

                text_parts = []
                tool_calls = []
                for block in content:
                    if hasattr(block, "type"):
                        if block.type == "text":
                            text_parts.append(block.text)
                        elif block.type == "tool_use":
                            tool_calls.append({
                                "id":   block.id,
                                "type": "function",
                                "function": {
                                    "name":      block.name,
                                    "arguments": json.dumps(block.input),
                                }
                            })
                    elif isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_use":
                            tool_calls.append({
                                "id":   block["id"],
                                "type": "function",
                                "function": {
                                    "name":      block["name"],
                                    "arguments": json.dumps(block.get("input", {})),
                                }
                            })

                groq_msg = {"role": role, "content": " ".join(text_parts) or None}
                if tool_calls:
                    groq_msg["tool_calls"] = tool_calls
                out.append(groq_msg)
            else:
                entry = {"role": role, "content": content}
                if msg.get("tool_calls"):
                    entry["tool_calls"] = msg["tool_calls"]
                if msg.get("tool_call_id"):
                    entry["tool_call_id"] = msg["tool_call_id"]
                out.append(entry)

        return out

    def chat(self, system: str, messages: list, tools: list) -> LLMResponse:
        ds_messages = [{"role": "system", "content": system}] + self._convert_messages(messages)
        ds_tools = self._convert_tools(tools) if tools else None

        body = {
            "model": self.model,
            "messages": ds_messages,
            "max_tokens": 4096,
        }
        if ds_tools:
            body["tools"] = ds_tools
            body["tool_choice"] = "auto"

        try:
            r = self.client.post(
                "/chat/completions",
                json=body,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
            if r.status_code != 200:
                return LLMResponse(
                    text=f"API error: HTTP {r.status_code} - {r.text[:200]}",
                    tool_calls=[], done=True, raw=r.json()
                )
            data = r.json()
        except Exception as e:
            return LLMResponse(
                text=f"Request failed: {e}",
                tool_calls=[], done=True, raw=None
            )

        choice = data["choices"][0]
        msg = choice["message"]
        text = msg.get("content") or ""
        tool_calls = []

        if msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                try:
                    args = json.loads(tc["function"]["arguments"])
                except Exception:
                    args = {}
                tool_calls.append({
                    "name":  tc["function"]["name"],
                    "id":    tc["id"],
                    "input": args,
                })

        done = not tool_calls and choice.get("finish_reason") in ("stop", "end_turn")
        return LLMResponse(text=text, tool_calls=tool_calls, done=done, raw=data)

    def build_assistant_msg(self, resp: LLMResponse):
        if not resp.raw:
            return {"role": "assistant", "content": resp.text}
        choice = resp.raw["choices"][0]
        msg = choice["message"]
        assistant = {"role": "assistant", "content": msg.get("content") or ""}
        if msg.get("tool_calls"):
            assistant["tool_calls"] = msg["tool_calls"]
        return assistant

    def build_tool_result_msg(self, tool_results: list):
        return [
            {
                "role": "tool",
                "tool_call_id": r["tool_use_id"],
                "content": r["content"],
            }
            for r in tool_results
        ]


# -- Public LLM class ----------------------------------------------
PROVIDERS = {
    "claude":   _ClaudeBackend,
    "groq":     _GroqBackend,
    "deepseek": _DeepSeekBackend,
}

class LLM:
    """
    Single interface for all providers.
    agent.py uses this exclusively -- never touches Anthropic/Groq SDK directly.
    """
    def __init__(self, provider: str = "groq"):
        provider = provider.lower()
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider '{provider}'. Choose: {list(PROVIDERS)}")
        self._backend  = PROVIDERS[provider]()
        self.provider  = provider
        self.messages  : list = []   # full conversation history

    def reset(self):
        self.messages = []

    def send(self, system: str, user_msg: str, tools: list) -> LLMResponse:
        """First message in a conversation."""
        self.messages = [{"role":"user","content":user_msg}]
        return self._call(system, tools)

    def reply(self, system: str, tool_results: list, tools: list) -> LLMResponse:
        """Continue conversation with tool results."""
        result_msg = self._backend.build_tool_result_msg(tool_results)
        if isinstance(result_msg, list):
            self.messages.extend(result_msg)   # Groq: multiple messages
        else:
            self.messages.append(result_msg)   # Claude: one message
        return self._call(system, tools)

    def _call(self, system: str, tools: list) -> LLMResponse:
        resp = self._backend.chat(system, self.messages, tools)
        # Append assistant response to history
        asst = self._backend.build_assistant_msg(resp)
        if isinstance(asst, list):
            self.messages.extend(asst)
        else:
            self.messages.append(asst)
        return resp
