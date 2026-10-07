#!/usr/bin/env python3
"""Mirror the arch-audit ledger into its discussion.

1. Post every run entry that a push added as a new discussion comment.
2. Re-render the register comment and the living document (the discussion
   body plus one comment per part) from the branch tip, expanding status
   tokens from the register, and update every target whose text changed.

Tokens: {{E01}} one register row, {{E07-E20}} a range, {{E33,E45}} a list,
{{PROGRESS}} the progress line, {{UPDATED}} the render time.
"""
import argparse
import collections
import datetime
import json
import pathlib
import re
import subprocess
import sys

EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
LIMIT = 64000
REPO = 'SocketDev/socket-patch'
TOKEN = re.compile(r'\{\{([A-Z][A-Z0-9]*(?:[-,][A-Z][A-Z0-9]*)*)\}\}')
ROW = re.compile(r'^\|\s*([A-Z][0-9]+)\s*\|')
# The render time inside the {{UPDATED}} stamp. same() ignores only the time, so
# a target is re-rendered whenever the ledger commit named in its stamp changes.
RENDER_TIME = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC(?= \(ledger `)')
ENTRY_MARKER = re.compile(r'<!-- arch-audit-entry: (\S+) -->')
ORDER = ['fixed', 'partly fixed', 'already fixed', 'in PR', 'filed', 'decision pending', 'to verify',
         'rejected', 'handed off', 'other', 'missing']
warnings = []


def git(*args):
    return subprocess.run(['git', *args], check=True, capture_output=True, text=True).stdout


def graphql(query, variables):
    payload = json.dumps({'query': query, 'variables': variables})
    proc = subprocess.run(['gh', 'api', 'graphql', '--input', '-'], input=payload,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    data = json.loads(proc.stdout)
    if data.get('errors'):
        raise RuntimeError(json.dumps(data['errors']))
    return data['data']


class Tree:
    def __init__(self, ref, worktree):
        self.ref, self.worktree = ref, worktree

    def read(self, path):
        if self.worktree:
            return pathlib.Path(path).read_text(encoding='utf-8')
        return git('show', f'{self.ref}:{path}')

    def ls(self, directory):
        if self.worktree:
            return sorted(str(p) for p in pathlib.Path(directory).glob('*.md'))
        out = git('ls-tree', '--name-only', self.ref, f'{directory}/')
        return sorted(p for p in out.splitlines() if p.endswith('.md'))


# Leading status tokens, longest first. A status cell starts with one of these
# (`filed #595; tracking …`, `in PR #1008`, `fixed (#597); …`), so classify by
# the start of the cell only: a substring match would read `filed #1; fixed
# upstream` as fixed.
STATUS_PREFIXES = [('already fixed', 'already fixed'), ('to verify', 'to verify'),
                   ('handed off', 'handed off'), ('not a defect', 'rejected'),
                   ('decision', 'decision pending'), ('decide', 'decision pending'),
                   ('rejected', 'rejected'), ('in pr', 'in PR'), ('partly fixed', 'partly fixed'),
                   ('fixed', 'fixed'),
                   ('filed', 'filed')]


def classify(status):
    s = status.strip().lstrip('*_`').lower()
    for prefix, label in STATUS_PREFIXES:
        if s.startswith(prefix):
            return label
    return 'other'


def parse_register(tree):
    rows = {}
    for path in tree.ls('register'):
        for line in tree.read(path).splitlines():
            m = ROW.match(line)
            if not m:
                continue
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if m.group(1) in rows:
                warnings.append(f'{m.group(1)} appears twice in the register ({path})')
            rows[m.group(1)] = cells[-1]
    return rows


def expand(spec):
    if spec.count('-') == 1 and ',' not in spec:
        a, b = spec.split('-')
        pa, na = re.match(r'([A-Z]+)([0-9]+)', a).groups()
        pb, nb = re.match(r'([A-Z]+)([0-9]+)', b).groups()
        if pa != pb or int(nb) < int(na):
            return None, f'`{spec}`'
        width = len(na)
        ids = [f'{pa}{n:0{width}d}' for n in range(int(na), int(nb) + 1)]
        return ids, f'`{a}`–`{b}`'
    ids = spec.split(',')
    return ids, ' '.join(f'`{i}`' for i in ids)


def counts_text(statuses):
    counts = collections.Counter(statuses)
    return ' · '.join(f'{counts[k]} {k}' for k in ORDER if counts[k])


def live_counts():
    query = ('query($a:String!,$b:String!,$c:String!,$d:String!){'
             'a:search(type:ISSUE,query:$a){issueCount} b:search(type:ISSUE,query:$b){issueCount} '
             'c:search(type:ISSUE,query:$c){issueCount} d:search(type:ISSUE,query:$d){issueCount}}')
    repo = f'repo:{REPO}'
    try:
        data = graphql(query, {'a': f'{repo} is:issue is:open label:arch-audit',
                               'b': f'{repo} is:issue is:closed label:arch-audit',
                               'c': f'{repo} is:pr is:open label:arch-refactor',
                               'd': f'{repo} is:pr is:merged label:arch-refactor'})
    except RuntimeError as e:
        warnings.append(f'live counts unavailable: {e}')
        return ''
    return (f" **On GitHub:** {data['a']['issueCount']} open and {data['b']['issueCount']} closed "
            f"`arch-audit` issues · {data['c']['issueCount']} open and {data['d']['issueCount']} merged "
            f"`arch-refactor` PRs.")


def render(text, rows, progress, updated):
    def sub(m):
        spec = m.group(1)
        if spec == 'PROGRESS':
            return progress
        if spec == 'UPDATED':
            return updated
        if '-' not in spec and ',' not in spec:
            if spec not in rows:
                warnings.append(f'token {spec} is not in the register')
                return f'`{spec}` · not in the register'
            return f'`{spec}` · {rows[spec]}'
        ids, label = expand(spec)
        if ids is None:
            warnings.append(f'bad token range {spec}')
            return label
        return f'{label}: ' + counts_text(classify(rows[i]) if i in rows else 'missing' for i in ids)
    return TOKEN.sub(sub, text)


def fit(name, text):
    text = text.rstrip() + '\n'
    if len(text) > LIMIT:
        warnings.append(f'{name} is {len(text)} characters; truncated to fit a discussion post')
        text = text[:LIMIT].rsplit('\n', 1)[0] + (
            '\n\n**[truncated: the full text is on the `arch-audit/ledger` branch]**\n')
    return text


def current_body(node_id):
    q = 'query($id:ID!){node(id:$id){... on Discussion{body} ... on DiscussionComment{body}}}'
    return graphql(q, {'id': node_id})['node']['body']


def update(kind, node_id, body):
    if kind == 'discussion_body':
        q = ('mutation($id:ID!,$b:String!){updateDiscussion(input:{discussionId:$id,body:$b})'
             '{discussion{url}}}')
        return graphql(q, {'id': node_id, 'b': body})['updateDiscussion']['discussion']['url']
    q = ('mutation($id:ID!,$b:String!){updateDiscussionComment(input:{commentId:$id,body:$b})'
         '{comment{url}}}')
    return graphql(q, {'id': node_id, 'b': body})['updateDiscussionComment']['comment']['url']


def same(a, b):
    # Ignore the render time but not the ledger commit in the stamp: a target is
    # edited when its content or the commit it was rendered from changed.
    norm = lambda s: RENDER_TIME.sub('', s.replace('\r\n', '\n')).strip()
    return norm(a) == norm(b)


def posted_entries(discussion_number):
    """The entry paths already posted as discussion comments (by their marker)."""
    owner, name = REPO.split('/')
    q = ('query($o:String!,$n:String!,$d:Int!,$c:String){repository(owner:$o,name:$n){'
         'discussion(number:$d){comments(first:100,after:$c){'
         'pageInfo{hasNextPage endCursor} nodes{body}}}}}')
    seen, cursor = set(), None
    while True:
        page = graphql(q, {'o': owner, 'n': name, 'd': discussion_number, 'c': cursor})
        comments = page['repository']['discussion']['comments']
        for node in comments['nodes']:
            seen.update(ENTRY_MARKER.findall(node['body'] or ''))
        if not comments['pageInfo']['hasNextPage']:
            return seen
        cursor = comments['pageInfo']['endCursor']


def post_entries(ledger, before, after, dry_run):
    try:
        git('cat-file', '-e', f'{before}^{{commit}}')
    except subprocess.CalledProcessError:
        before = EMPTY_TREE
    out = git('diff', '--name-only', '--diff-filter=A', '-z', before, after, '--', 'entries/*/*.md')
    paths = sorted(p for p in out.split('\0') if p)
    if not paths:
        return
    # Overlapping runs (or a re-run) can see the same added entry: skip any
    # entry whose marker is already on the discussion, so each posts once.
    try:
        already = posted_entries(ledger['discussion'])
    except RuntimeError as e:
        warnings.append(f'could not list posted entries, posting without the duplicate check: {e}')
        already = set()
    for path in paths:
        if path in already:
            print(f'{path}: already posted')
            continue
        body = git('show', f'{after}:{path}').rstrip() + f'\n\n<!-- arch-audit-entry: {path} -->\n'
        if dry_run:
            print(f'would post {path}')
            continue
        q = ('mutation($d:ID!,$b:String!){addDiscussionComment(input:{discussionId:$d,body:$b})'
             '{comment{url}}}')
        url = graphql(q, {'d': ledger['discussion_node_id'], 'b': fit(path, body)})
        print(url['addDiscussionComment']['comment']['url'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', default='HEAD', help='ledger commit to render from')
    ap.add_argument('--worktree', action='store_true', help='render from files on disk instead')
    ap.add_argument('--entries', nargs=2, metavar=('BEFORE', 'AFTER'),
                    help='post the entries added between two commits')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--out', help='write the rendered targets to this directory')
    args = ap.parse_args()

    tree = Tree(args.ref, args.worktree)
    ledger = json.loads(tree.read('ledger.json'))
    if args.entries:
        post_entries(ledger, *args.entries, args.dry_run)

    rows = parse_register(tree)
    progress = (f"**Progress:** {len(rows)} problems tracked · "
                f"{counts_text(classify(s) for s in rows.values())}.{live_counts()}")
    sha = 'worktree' if args.worktree else git('rev-parse', '--short', args.ref).strip()
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    updated = f'{now} (ledger `{sha}`)'

    targets = [('register', 'comment', ledger['register_comment_id'],
                '\n\n'.join(tree.read(p).rstrip() for p in tree.ls('register')))]
    for path, t in sorted(ledger.get('doc_targets', {}).items()):
        targets.append((path, t['kind'], t['id'], tree.read(path)))

    failed = False
    for name, kind, node_id, text in targets:
        body = fit(name, render(text, rows, progress, updated))
        if args.out:
            out = pathlib.Path(args.out) / (pathlib.Path(name).name + ('.md' if name == 'register' else ''))
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(body, encoding='utf-8')
        try:
            if same(current_body(node_id), body):
                print(f'{name}: unchanged')
                continue
            if args.dry_run:
                print(f'{name}: would update ({len(body)} characters)')
                continue
            print(f'{name}: {update(kind, node_id, body)}')
        except RuntimeError as e:
            failed = True
            print(f'::error::{name}: {e}')
    for w in warnings:
        print(f'::warning::{w}')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
