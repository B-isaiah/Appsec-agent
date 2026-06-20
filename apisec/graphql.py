"""
apisec/graphql.py
GraphQL introspection, schema parsing, mutation/query generation, and targeted fuzzing.
Called by recon.py during discovery and by agent.py for attack guidance.
"""

import json
import re

import httpx

from .term import CHECK, CROSS, WARN, BULLET

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields {
        name
        description
        args {
          name
          description
          type {
            kind
            name
            ofType { kind name ofType { kind name ofType { kind name } } }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
        defaultValue
      }
      interfaces { name }
      enumValues { name description }
      possibleTypes { name }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type { kind name ofType { kind name } }
        defaultValue
      }
    }
  }
}
"""

PING_QUERY = "query { __typename }"
SUGGESTION_QUERY = "query { __typo }"


def _strip_type(t):
    if t is None:
        return None
    k = t.get("kind")
    if k in ("NON_NULL", "LIST"):
        return _strip_type(t.get("ofType"))
    return t.get("name")


def probe_graphql(url: str, client: httpx.Client = None) -> dict:
    """Probe a URL as a possible GraphQL endpoint.

    Returns:
        {
            "url": str,
            "is_graphql": bool,
            "introspection": bool | None,
            "suggestions": bool | None,
            "schema": dict | None,
            "error": str | None,
        }
    """
    close = False
    if client is None:
        client = httpx.Client(timeout=10, verify=False)
        close = True

    result = {"url": url, "is_graphql": False, "introspection": None,
              "suggestions": None, "schema": None, "error": None}
    hdrs = {"Content-Type": "application/json"}

    try:
        r = client.post(url, json={"query": PING_QUERY}, headers=hdrs)
        if r.status_code == 200:
            data = r.json()
            if data.get("data", {}).get("__typename"):
                result["is_graphql"] = True
            elif "errors" in data:
                has_graphql_err = any(
                    "graphql" in str(e).lower() or "query" in str(e).lower()
                    for e in data["errors"]
                )
                if has_graphql_err:
                    result["is_graphql"] = True
    except Exception as e:
        result["error"] = f"Ping failed: {e}"
        if close:
            client.close()
        return result

    if not result["is_graphql"]:
        if close:
            client.close()
        return result

    try:
        r = client.post(url, json={"query": INTROSPECTION_QUERY}, headers=hdrs)
        data = r.json()
        sch = data.get("data", {}).get("__schema")
        if sch:
            result["introspection"] = True
            result["schema"] = _parse_schema(sch)
        elif "errors" in data:
            result["introspection"] = False
            result["introspection_error"] = data["errors"]
    except Exception as e:
        result["introspection"] = False
        result["introspection_error"] = str(e)

    try:
        r = client.post(url, json={"query": SUGGESTION_QUERY}, headers=hdrs)
        data = r.json()
        err_text = json.dumps(data.get("errors", [])).lower()
        if "did you mean" in err_text or "suggestion" in err_text:
            result["suggestions"] = True
    except Exception:
        pass

    if close:
        client.close()
    return result


def _parse_schema(schema: dict) -> dict:
    """Parse raw introspection response into a compact schema summary."""
    result = {
        "query_type": None, "mutation_type": None, "subscription_type": None,
        "queries": [], "mutations": [], "subscriptions": [],
        "types": [], "input_types": [],
    }
    type_map = {}
    for t in schema.get("types", []):
        type_map[t["name"]] = t

    qt = schema.get("queryType") or {}
    mt = schema.get("mutationType") or {}
    st = schema.get("subscriptionType") or {}

    def extract(type_name):
        fields = []
        t = type_map.get(type_name)
        if t and "fields" in t:
            for f in t["fields"]:
                args = []
                for a in f.get("args", []):
                    args.append({
                        "name": a["name"],
                        "type": _strip_type(a.get("type")),
                        "required": a.get("type", {}).get("kind") == "NON_NULL",
                    })
                fields.append({
                    "name": f["name"],
                    "description": (f.get("description") or "")[:120],
                    "args": args,
                    "return_type": _strip_type(f.get("type")) or "_",
                })
        return fields

    if qt.get("name"):
        result["query_type"] = qt["name"]
        result["queries"] = extract(qt["name"])
    if mt.get("name"):
        result["mutation_type"] = mt["name"]
        result["mutations"] = extract(mt["name"])
    if st.get("name"):
        result["subscription_type"] = st["name"]
        result["subscriptions"] = extract(st["name"])

    builtins = {"Query", "Mutation", "Subscription", "String", "Int", "Float",
                "Boolean", "ID", "__Type", "__Field", "__InputValue", "__EnumValue",
                "__Directive", "__Schema", "__DirectiveLocation", "__TypeKind"}

    for t in schema.get("types", []):
        k = t.get("kind")
        n = t["name"]
        if n.startswith("__") or n in builtins:
            continue
        if k == "INPUT_OBJECT":
            fields = []
            for f in t.get("inputFields", []):
                fields.append({
                    "name": f["name"],
                    "type": _strip_type(f.get("type")) or "_",
                    "required": f.get("type", {}).get("kind") == "NON_NULL",
                })
            result["input_types"].append({"name": n, "fields": fields})
        elif k == "OBJECT":
            result["types"].append(n)
        elif k == "ENUM":
            values = [e["name"] for e in t.get("enumValues", [])]
            result.setdefault("enums", []).append({"name": n, "values": values[:20]})

    return result


def format_schema_context(schema: dict) -> str:
    """Render the schema as text for agent's system prompt."""
    lines = ["## GraphQL Schema"]

    if schema["queries"]:
        lines.append(f"\n### Queries ({len(schema['queries'])})")
        for q in schema["queries"]:
            a = ", ".join(f"{a['name']}: {a['type']}{'!' if a['required'] else ''}"
                         for a in q["args"]) if q["args"] else ""
            lines.append(f"- `{q['name']}({a})` -> {q['return_type']}")

    if schema["mutations"]:
        lines.append(f"\n### Mutations ({len(schema['mutations'])})")
        for m in schema["mutations"]:
            a = ", ".join(f"{a['name']}: {a['type']}{'!' if a['required'] else ''}"
                         for a in m["args"]) if m["args"] else ""
            lines.append(f"- `{m['name']}({a})` -> {m['return_type']}")

    if schema["subscriptions"]:
        lines.append(f"\n### Subscriptions ({len(schema['subscriptions'])})")
        for s in schema["subscriptions"]:
            lines.append(f"- `{s['name']}` -> {s['return_type']}")

    if schema.get("input_types"):
        lines.append(f"\n### Input Types")
        for it in schema["input_types"]:
            f = ", ".join(f"{ff['name']}: {ff['type']}{'!' if ff['required'] else ''}"
                         for ff in it["fields"])
            lines.append(f"- `{it['name']}` {{{f}}}")

    if schema.get("enums"):
        lines.append(f"\n### Enums")
        for e in schema["enums"]:
            lines.append(f"- `{e['name']}`: {', '.join(e['values'][:8])}")

    if schema.get("types"):
        lines.append(f"\n### Object Types ({len(schema['types'])})")
        lines.append(", ".join(schema["types"][:15]))
        if len(schema["types"]) > 15:
            lines.append(f"... and {len(schema['types'])-15} more")

    return "\n".join(lines)


def attack_guide() -> str:
    """Return GraphQL-specific testing guidance for the agent."""
    return """
## GraphQL Attack Vectors

| Attack | What to try |
|--------|-------------|
| **Introspection leak** | If __schema is accessible, the full schema is exposed |
| **Auth bypass on mutations** | Try mutations without auth; check if write ops are unprotected |
| **Depth-based DoS** | Try deeply nested queries on connection/relation types |
| **N+1 / Batching** | Send multiple queries in one request: [{"query":"..."},...] |
| **Mass Assignment** | In mutation inputs, set role: "admin", isAdmin: true |
| **Injection in args** | SQLi/NoSQLi in String args of mutations |
| **IDOR in queries** | Pass another user's ID as query arg without auth |
| **Alias abuse** | Use aliases to run same query multiple times in one request |
| **Field duplication** | Request same field 100x via aliases for resource exhaustion |

Test every mutation with and without auth. Test every query that takes an ID
argument for BOLA by swapping IDs across identities.
"""


def sample_input_values(input_type_name: str, input_types: list[dict]) -> dict:
    """Generate sample argument values for an input type."""
    for it in input_types:
        if it["name"] != input_type_name:
            continue
        sample = {}
        for f in it["fields"]:
            t = f["type"] or ""
            if "String" in t or "ID" in t:
                sample[f["name"]] = "test"
            elif "Int" in t:
                sample[f["name"]] = 1
            elif "Float" in t:
                sample[f["name"]] = 1.0
            elif "Boolean" in t:
                sample[f["name"]] = True
            else:
                sample[f["name"]] = None
        return sample
    return {}


def generate_payloads(schema: dict) -> list[dict]:
    """Generate test payloads from a parsed schema for batch use."""
    payloads = []

    for m in schema.get("mutations", []):
        if not m["args"]:
            payloads.append({
                "query": f"mutation {{ {m['name']} {{ __typename }} }}",
                "desc": f"mutation {m['name']}",
            })
        for arg in m["args"]:
            t = arg["type"] or ""
            if "Input" in t:
                sv = sample_input_values(t, schema.get("input_types", []))
                if sv:
                    sj = json.dumps(sv)
                    payloads.append({
                        "query": f"mutation {{ {m['name']}({arg['name']}: {sj}) {{ __typename }} }}",
                        "desc": f"mutation {m['name']} basic",
                    })
                    for role_key in ["role", "isAdmin", "is_admin", "permission"]:
                        if role_key in sv:
                            alt = dict(sv)
                            alt[role_key] = "admin" if isinstance(sv[role_key], str) else True
                            payloads.append({
                                "query": f"mutation {{ {m['name']}({arg['name']}: {json.dumps(alt)}) {{ __typename }} }}",
                                "desc": f"mutation {m['name']} mass-assignment ({role_key})",
                            })
                            break

    for q in schema.get("queries", []):
        if q["args"]:
            payloads.append({
                "query": f"query {{ {q['name']}({q['args'][0]['name']}: 1) {{ __typename }} }}",
                "desc": f"query {q['name']} with arg",
            })

    return payloads
