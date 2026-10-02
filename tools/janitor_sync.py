#!/usr/bin/env python3
"""Discussions bridge for the issue & discussion janitor routine.

Cloud agent sessions can't use GitHub GraphQL, so they can't read or
write Discussions directly. The routine pushes requested operations to
this branch, and the workflow on the branch runs this script with the
Actions token. The script:

1. Applies every op in ops/*.json that applied.json doesn't list yet.
2. Writes snapshot/discussions.json, which holds every discussion and all
   its comments, plus snapshot/meta.json, so the routine can read
   Discussions with `git fetch`.

ops/<UTC ts>-<slug>.json is a JSON array of operations:
  {"op": "comment",      "discussion": N, "body": "..."}
  {"op": "close",        "discussion": N, "reason": "OUTDATED|RESOLVED|DUPLICATE"}
  {"op": "update_body",  "discussion": N, "body": "..."}  # only discussions in owned.json
  {"op": "mark_answer",  "comment_id": "DC_..."}

Every op is safe to re-run. A comment carries a hidden marker, so a retry
after a crash doesn't post it twice. Closing an already-closed discussion
or setting an identical body does nothing. Ops that fail are listed in
applied.json under "failed" with the error, and are not retried.
"""
import datetime
import glob
import json
import os
import subprocess
import sys

OWNER, _, REPO = os.environ.get("GITHUB_REPOSITORY", "SocketDev/socket-patch").partition("/")
DRY = "--dry-run" in sys.argv


def gql(query, **vars):
    cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
    for k, v in vars.items():
        cmd += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    data = json.loads(r.stdout or "{}")
    if r.returncode or data.get("errors"):
        raise RuntimeError(data.get("errors") or r.stderr.strip())
    return data["data"]


COMMENT_FIELDS = "id url author{login} createdAt updatedAt body isAnswer"


def all_discussions():
    q = """query($o:String!,$r:String!,$after:String){repository(owner:$o,name:$r){
      discussions(first:25,after:$after,orderBy:{field:CREATED_AT,direction:ASC}){
        pageInfo{hasNextPage endCursor}
        nodes{id number title url closed stateReason locked createdAt updatedAt
          author{login} category{name} body answer{id}
          comments(first:100){pageInfo{hasNextPage endCursor} nodes{%s}}}}}}""" % COMMENT_FIELDS
    cq = """query($id:ID!,$after:String){node(id:$id){... on Discussion{
      comments(first:100,after:$after){pageInfo{hasNextPage endCursor} nodes{%s}}}}}""" % COMMENT_FIELDS
    out, after = [], None
    while True:
        v = {"o": OWNER, "r": REPO}
        if after:
            v["after"] = after
        page = gql(q, **v)["repository"]["discussions"]
        for d in page["nodes"]:
            cs = d.pop("comments")
            comments = cs["nodes"]
            ca = cs["pageInfo"]
            while ca["hasNextPage"]:
                more = gql(cq, id=d["id"], after=ca["endCursor"])["node"]["comments"]
                comments += more["nodes"]
                ca = more["pageInfo"]
            d["author"] = (d["author"] or {}).get("login")
            d["category"] = d["category"]["name"]
            d["answer_id"] = (d.pop("answer") or {}).get("id")
            for c in comments:
                c["author"] = (c["author"] or {}).get("login")
            d["comments"] = comments
            out.append(d)
        if not page["pageInfo"]["hasNextPage"]:
            return out
        after = page["pageInfo"]["endCursor"]


def main():
    owned = set(json.load(open("owned.json")))
    applied = json.load(open("applied.json")) if os.path.exists("applied.json") else {"done": [], "failed": {}}
    discussions = {d["number"]: d for d in all_discussions()}
    changed = False

    for path in sorted(glob.glob("ops/*.json")):
        name = os.path.basename(path)
        if name in applied["done"] or name in applied["failed"]:
            continue
        errors = []
        try:
            ops = json.load(open(path))
            assert isinstance(ops, list), "ops file must be a JSON array"
        except Exception as e:
            applied["failed"][name] = [f"unreadable: {e}"]
            changed = True
            continue
        for i, op in enumerate(ops):
            try:
                kind = op["op"]
                if kind == "mark_answer":
                    print(f"{name}#{i}: mark_answer {op['comment_id']}")
                    if not DRY:
                        gql("mutation($id:ID!){markDiscussionCommentAsAnswer(input:{id:$id}){discussion{id}}}", id=op["comment_id"])
                    continue
                n = int(op["discussion"])
                d = discussions.get(n)
                if d is None:
                    raise RuntimeError(f"discussion #{n} not found")
                if kind == "comment":
                    marker = f"<!-- janitor-op: {name}#{i} -->"
                    if any(marker in c["body"] for c in d["comments"]):
                        continue
                    print(f"{name}#{i}: comment on #{n}")
                    if not DRY:
                        gql("mutation($d:ID!,$b:String!){addDiscussionComment(input:{discussionId:$d,body:$b}){comment{id}}}",
                            d=d["id"], b=f"{op['body'].rstrip()}\n\n{marker}\n")
                elif kind == "close":
                    reason = op.get("reason", "OUTDATED").upper()
                    if reason not in ("OUTDATED", "RESOLVED", "DUPLICATE"):
                        raise RuntimeError(f"bad close reason {reason}")
                    if d["closed"]:
                        continue
                    print(f"{name}#{i}: close #{n} as {reason}")
                    if not DRY:
                        gql("mutation($d:ID!,$r:DiscussionCloseReason!){closeDiscussion(input:{discussionId:$d,reason:$r}){discussion{id}}}",
                            d=d["id"], r=reason)
                elif kind == "update_body":
                    if n not in owned:
                        raise RuntimeError(f"#{n} is not in owned.json; only owned discussion bodies may be rewritten")
                    if d["body"].replace("\r\n", "\n").strip() == op["body"].strip():
                        continue
                    print(f"{name}#{i}: update body of #{n}")
                    if not DRY:
                        gql("mutation($d:ID!,$b:String!){updateDiscussion(input:{discussionId:$d,body:$b}){discussion{id}}}",
                            d=d["id"], b=op["body"])
                else:
                    raise RuntimeError(f"unknown op {kind!r}")
            except Exception as e:
                print(f"::warning::{name}#{i}: {e}")
                errors.append(f"#{i}: {e}")
        if errors:
            applied["failed"][name] = errors
        else:
            applied["done"].append(name)
        changed = True

    if DRY:
        return
    if changed:
        discussions = {d["number"]: d for d in all_discussions()}
    os.makedirs("snapshot", exist_ok=True)
    snap = [discussions[k] for k in sorted(discussions)]
    with open("snapshot/discussions.json", "w") as f:
        json.dump(snap, f, indent=1, sort_keys=True)
        f.write("\n")
    with open("snapshot/meta.json", "w") as f:
        json.dump({"generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "trigger_sha": os.environ.get("GITHUB_SHA", ""),
                   "discussions": len(snap)}, f, indent=1)
        f.write("\n")
    with open("applied.json", "w") as f:
        json.dump(applied, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
