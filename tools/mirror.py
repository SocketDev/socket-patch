#!/usr/bin/env python3
"""Mirror a ledger branch into GitHub Discussions.

Cloud agent sessions can't use GitHub GraphQL, so agents commit markdown to
a ledger branch, and the workflow on that branch runs this script with the
workflow token.

Layout (relative to the checkout):
  discussions.json          {"<key>": <discussion number>, ...}
  entries/<key>/<ts>*.md    each file is posted once as a discussion comment
  state/<key>.md            replaces the discussion body when it differs

Idempotent: every run reconciles the whole branch tip against the
discussions instead of diffing one push, so a cancelled or failed run loses
nothing; the next run posts whatever is missing. An entry counts as posted
if a comment carries its marker or (for comments posted before markers
existed) has exactly its content.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

OWNER, _, REPO = os.environ.get("GITHUB_REPOSITORY", "SocketDev/socket-patch").partition("/")


def gql(query, fields=None, raw=None):
    cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
    for k, v in (fields or {}).items():
        cmd += ["-F", f"{k}={v}"]
    for k, v in (raw or {}).items():
        cmd += ["-f", f"{k}={v}"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    data = json.loads(out)
    if data.get("errors"):
        raise RuntimeError(data["errors"])
    return data["data"]


def load_discussion(number):
    q = """query($o:String!,$r:String!,$n:Int!,$after:String){
      repository(owner:$o,name:$r){discussion(number:$n){
        id body
        comments(first:100,after:$after){pageInfo{hasNextPage endCursor} nodes{body}}}}}"""
    comments, after, disc = [], None, None
    while True:
        fields = {"n": number}
        raw = {"o": OWNER, "r": REPO}
        if after:
            raw["after"] = after
        disc = gql(q, fields, raw)["repository"]["discussion"]
        if disc is None:
            raise RuntimeError(f"discussion #{number} not found")
        page = disc["comments"]
        comments += [c["body"] for c in page["nodes"]]
        if not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]
    return disc["id"], disc["body"], comments


def norm(s):
    return s.replace("\r\n", "\n").strip()


def body_file(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
    f.write(text)
    f.close()
    return f.name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--since", default="",
                    help="ignore entry files whose name sorts before this (e.g. 20261002T000000Z)")
    args = ap.parse_args()

    with open("discussions.json") as f:
        mapping = json.load(f)
    failures = 0
    for key, number in sorted(mapping.items()):
        try:
            did, body, comments = load_discussion(int(number))
        except Exception as e:  # keep going for the other keys
            print(f"::error::{key} #{number}: {e}")
            failures += 1
            continue
        posted = {norm(c) for c in comments}
        edir = os.path.join("entries", key)
        names = sorted(n for n in os.listdir(edir) if n.endswith(".md")) if os.path.isdir(edir) else []
        for name in names:
            if name < args.since:
                continue
            path = f"entries/{key}/{name}"
            with open(path) as f:
                content = f.read()
            marker = f"<!-- ledger-entry: {path} -->"
            if norm(content) in posted or any(marker in c for c in comments):
                continue
            print(f"post   {key} #{number} <- {path}")
            if not args.dry_run:
                gql("mutation($d:ID!,$b:String!){addDiscussionComment(input:{discussionId:$d,body:$b}){comment{url}}}",
                    {"b": "@" + body_file(f"{norm(content)}\n\n{marker}\n")}, {"d": did})
        spath = f"state/{key}.md"
        if os.path.isfile(spath):
            with open(spath) as f:
                state = f.read()
            if norm(state) != norm(body):
                print(f"update {key} #{number} body <- {spath}")
                if not args.dry_run:
                    gql("mutation($d:ID!,$b:String!){updateDiscussion(input:{discussionId:$d,body:$b}){discussion{url}}}",
                        {"b": "@" + spath}, {"d": did})
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
