# awnest

**Prove there is a human before you let them into the nest.**

```bash
pip install awnest
```

```python
from awnest import Nest, HmacKey, Policy

nest = Nest("action:checkout", key=HmacKey(SECRET), policy=Policy(min_score=70))
nest.require(token=attestation, subject=user_id)      # raises NotAdmitted
```

A nest is not a wall. It is a place with doors, and the job is knowing who came
through which one.

## The one thing this is built around

**Every human check ever written fails open.** Not by decision — by arithmetic.
"We could not tell" and "it is fine" reach the caller as the same thing: an empty
result, a `None`, a score of `0`, a 500 somebody catches. The gate then denies
nobody, and it passes every test written for it, because the tests assert that a
bot is refused — and a bot *is* refused, right up until the evaluator has a bad
afternoon.

So the verdict type here has no member meaning "ok":

```python
Verdict.HUMAN      # earned it
Verdict.AGENT      # declared it
Verdict.UNKNOWN    # everything else, including "the check did not run"
```

`UNKNOWN` is what you get from an absent evaluator, an unparseable reply, a stale
attestation, an empty evidence list, and a policy nobody configured. Admission is
granted by naming a verdict, never by failing to reach one.

Two more rules fall out of the same idea:

- **Scored zero is not unscored.** `Evidence(score=None)` means nobody judged it.
  It counts toward nothing and it is reported as nothing — never as a zero, which
  would turn a judge outage into a permanent accusation against real people.
- **A presented-but-invalid credential is not an absent one.** A token that does
  not verify refuses *there*; it never falls through to whatever weaker evidence
  came with it. Forgery is the one event you want to be loud.

## "Human or bot" is the wrong question

If the only way through a door is to be human, every legitimate automation is
taught to imitate one, and you have spent your budget training the thing you are
trying to detect.

```python
from awnest import Evidence, DECLARED_AGENT, assess

assess([Evidence(DECLARED_AGENT, source="nightly-sync")]).verdict   # Verdict.AGENT
```

A caller that declares itself is believed, and a declaration **cannot be
outvoted** by a good score presented alongside it. Honesty has to be the cheaper
path or nobody takes it. Whether the agent door is open is one flag —
`Policy(allow_agents=True)` — decided per door, never inherited.

## Not a CAPTCHA

CAPTCHA asks a machine-solvable question and charges the cost to the human. It is
worst for the people it should serve most, and the machines beat it, so the only
party reliably filtered is the customer.

The bundled challenges ask instead for something a person *has* and a model does
not: a particular life — an embodied sensation, felt time, a real reaction to
being asked. Scoring is somebody else's job (a model, a person, a service), and
this package refuses to pretend otherwise.

```python
from awnest import select, judge_prompt
from awnest.judge import score_answers

issued = select(3)                    # one per category, never the same twice
evidence, judgement = score_answers("http://127.0.0.1:8080", issued, answers,
                                    model="whatever-you-run")
```

**This is not proof, and the honest framing is cost.** A determined operator can
pay a person, or feed a model a real diary. What it does is move a fake account
from free to about a human-minute, which is the entire game for spam economics.
Need more? Stack another signal — the verdict plane takes several and reports the
**weakest**, so adding one can never weaken the answer.

> The judge sees the most personal thing a stranger will ever type into your
> product. `base_url` has no default on purpose: nobody should make that decision
> by inheriting one.

## Attestations: bound, offline-verifiable, one-use

The check and the door are rarely the same process. Calling back to the verifier
makes every gated action depend on it being up; a boolean in a session is a fact
with no provenance. So: a small signed statement.

```python
token = nest.issue(user_id, assessment, ttl_s=3600, method="challenges")
```

The format is shaped by **replay**, which is the real attack — not "bots solve the
puzzle" but "a human solves it once, cheaply, and the result is reused":

| field | drop it and… |
|---|---|
| `sub` | the token is transferable between people |
| `aud` | one solve opens every door that trusts the issuer |
| `ctx` | it can be lifted onto a different commit, request or transfer |
| `nonce` | one solve opens the same door forever (with a `Seen` ledger, it does not) |
| `exp` | the damage is unbounded in time |

`ctx` is **symmetric and unforgiving**: a token carrying a context is refused by
any verifier that does not name the same one, and a verifier that names a context
refuses a token that carries none. A binding either side may decline to check is
not a binding, and forgetting to check is what actually happens.

The token names its algorithm and the **key decides** it — a mismatch is a
refusal. Reading `alg` out of the token is how `alg: none` and HMAC/RSA confusion
emptied a decade of JWT deployments.

`HmacKey` is stdlib and means every verifier is also an issuer: fine inside one
trust domain, wrong the moment a third party verifies. `pip install
awnest[ed25519]` for the asymmetric half.

## Signing commits with it

A signed commit says a *key* was present. When most commits are written by agents
holding the same keys as the humans who run them, that is no longer the
interesting fact. The interesting fact is whether a person stood behind the
change, at what strength, and which person.

```bash
awnest commit-attest --identity "$AWIAM_SUBJECT" --repo acme/widgets \
       --tree "$(git rev-parse HEAD^{tree})" --score 82 --method challenges
# -> Awnest-Attestation: awn1.…   (append it as a trailer)

awnest commit-verify --message .git/COMMIT_EDITMSG --repo acme/widgets \
       --tree "$(git rev-parse HEAD^{tree})"
```

The binding is the **tree**, not the commit sha — an attestation lives inside the
message, so it cannot contain a hash of the commit that contains it. That means it
survives a reword, a rebase and a cherry-pick (same content, still attested) and
does **not** cover the parent. If you need "approved on this branch", that belongs
in the audience: `repo:acme/widgets@release` is a different door.

`verify_commit` re-reads the tree in front of you and compares. A valid
attestation lifted off another commit verifies perfectly; only that comparison
notices.

## What it composes with

Each of these is a door with a name, built rather than typed
(`audience("channel", "#help")`) because an issuer's spelling drift mints tokens
for a door nobody guards — silently, unlike a verifier's, which refuses everyone
and gets fixed in minutes.

| with | the door | the question |
|---|---|---|
| an identity system | — | *who* is this caller (the `sub` in the attestation) |
| an authz system | — | *what* may they do — humanity is an input, not a replacement |
| a chat/relay | `channel:#help` | may this caller **post** here |
| version control | `repo:acme/widgets` | did a person stand behind this change |
| a mesh | `mesh:home` | may this peer **join** |
| a tunnel | `tunnel:api` | may this caller reach a service with no public address |
| an audit trail | — | every verdict, including the refusals, kept where gaps show |

Nothing above is a dependency. awnest holds the verdict, the format and the door;
who you ask and what you do with the answer stay yours.

## Command line

```
awnest challenge -n 3                  issue a set of challenges (JSON)
awnest judge --url … --model … --answers a.json
awnest mint   --subject u_42 --audience action:checkout --score 80
awnest verify TOKEN --audience action:checkout
awnest gate   TOKEN --audience action:checkout --subject u_42
awnest commit-attest / commit-verify   the git trailer, above
awnest --self-test                     prove this package can still fail
```

Exit codes: **0** admitted / ok · **1** refused or broke · **2** you asked wrongly.

## Licence

Apache-2.0.

<!-- aither-ecosystem:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

## The aw family

Standalone tools that share one idea: **replace something you would otherwise have to _trust_ with something you can _check_.**

Each installs on its own, works offline, and needs no account.

| | instead of trusting | you check |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | a framework's idea of how your agents should run | one loop you can read, pointed at a backend you already pay for |
| [awskills](https://github.com/Aitherium/awskills) | that an agent knows your procedure | the procedure written down, versioned, and loadable by any agent |
| [awm](https://github.com/Aitherium/awm) | that memory stayed in its lane | tenant:user:project scopes, so a write cannot cross a boundary |
| [awnode](https://github.com/Aitherium/awnode) | a vendor's cloud with every prompt | a local gateway routing to backends you chose |
| [awgraph](https://github.com/Aitherium/awgraph) | that grep found everything | an AST + tree-sitter call graph an agent can traverse |
| [awgit](https://github.com/Aitherium/awgit) | that no one else is editing this file | a lease, refused at commit time if you do not hold it |
| [awseal](https://github.com/Aitherium/awseal) | that the artifact came from who you think | an Ed25519 seal — the key that verifies is not the key that forges |
| [awshare](https://github.com/Aitherium/awshare) | that the download is intact | content-addressed bundles, verified on fetch |
| **awnest** _(you are here)_ | that there is a person on the other end | a verdict with evidence, where "we could not tell" is not "yes" |
| [awnboard](https://github.com/Aitherium/awnboard) | a share link anyone who sees it can use | an invitation addressed to one person, for one gate, revocable |
| [awnix](https://github.com/Aitherium/awnix) | that the box is what you left it as | an immutable image you built, with atomic rollback |
| [awrecover](https://github.com/Aitherium/awrecover) | that the restore worked | a restore that fully lands or does not land at all |
| [awrelay](https://github.com/Aitherium/awrelay) | a SaaS in the middle of your agents | findings, alerts and coordination over your own transport |
| [awmail](https://github.com/Aitherium/awmail) | a mailbox somebody else can read | mail your agents send and receive over your own server |
| [awfind](https://github.com/Aitherium/awfind) | one vendor's idea of the web | results from whichever providers you configured |
| [awbrowse](https://github.com/Aitherium/awbrowse) | that the page said what you were told | the render, the DOM and the requests it made |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | a vendor's quantisation defaults | sub-byte KV cache kernels you can benchmark yourself |
| [AitherZero](https://github.com/Aitherium/AitherZero) | a pile of scripts nobody has numbered | numbered, discoverable automation with declarative playbooks |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | what a page tells your browser to do | a federated search and desktop bridge you host |
| [awreason](https://github.com/Aitherium/awreason) | a confident paragraph | the phases it went through, and every tool call it made to get there |
| [awrecurse](https://github.com/Aitherium/awrecurse) | that everything you pasted in was actually read | which slices it opened, and what it concluded from each |
| [awprism](https://github.com/Aitherium/awprism) | the first explanation that fits | the ranked alternatives, and the observation that separates them |
| [awrepl](https://github.com/Aitherium/awrepl) | what the agent believes the value is | the value, printed from the live session |
| [awresearch](https://github.com/Aitherium/awresearch) | a summary of pages nobody opened | every claim against the source it came from |
| [awkno](https://github.com/Aitherium/awkno) | that the docs site is up, or that you remember the family | the whole ecosystem in your terminal, with no network at all |

[**awnix**](https://github.com/Aitherium/awnix) is the ground floor — A Linux you can hand to an agent — immutable base, capabilities included.

## The Aitherium ecosystem

Every repository here is public. Each publishes an `aither-manifest.json` beside its page, so any surface can read every sibling's — the network is browsable from any node in it.

| repo | what it is | pages |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | Build AI agent fleets — 3 lines, any backend, local or cloud | [docs](https://aitherium.github.io/awdk/) |
| [awskills](https://github.com/Aitherium/awskills) | Portable agent skills — self-contained procedures an agent loads on demand | [docs](https://aitherium.github.io/awskills/) |
| [awm](https://github.com/Aitherium/awm) | A portable, scoped agent memory | [docs](https://aitherium.github.io/awm/) |
| [awnode](https://github.com/Aitherium/awnode) | A lightweight local gateway — bridges your apps to the AI backends you chose | [docs](https://aitherium.github.io/awnode/) |
| [awrun](https://github.com/Aitherium/awrun) | A priority-aware queue and dispatcher for agentic runs and ad-hoc CI builds | [docs](https://aitherium.github.io/awrun/) |
| [awgraph](https://github.com/Aitherium/awgraph) | A semantic code graph for agents — AST + tree-sitter, call graphs | [docs](https://aitherium.github.io/awgraph/) |
| [awgit](https://github.com/Aitherium/awgit) | Semantic version control on top of git — edit-ops and leases | [docs](https://aitherium.github.io/awgit/) |
| [awseal](https://github.com/Aitherium/awseal) | Sign an artifact so a stranger can verify it | [docs](https://aitherium.github.io/awseal/) |
| [awshare](https://github.com/Aitherium/awshare) | Publish an artifact and fetch it back verified | [docs](https://aitherium.github.io/awshare/) |
| **awnest** _(you are here)_ | Prove there is a human before you let them into the nest | [docs](https://aitherium.github.io/awnest/) |
| [awnboard](https://github.com/Aitherium/awnboard) | A front gate you can put in front of anything, and hand someone the key to | [docs](https://aitherium.github.io/awnboard/) |
| [awnix](https://github.com/Aitherium/awnix) | A Linux you can hand to an agent — immutable base, capabilities included | [docs](https://aitherium.github.io/awnix/) |
| [awrecover](https://github.com/Aitherium/awrecover) | Labelled snapshots with an all-or-nothing restore | [docs](https://aitherium.github.io/awrecover/) |
| [awrelay](https://github.com/Aitherium/awrelay) | Portable agent messaging — findings, alerts, coordination | [docs](https://aitherium.github.io/awrelay/) |
| [awmail](https://github.com/Aitherium/awmail) | Give an agent an email address — send, and actually receive | [docs](https://aitherium.github.io/awmail/) |
| [awfind](https://github.com/Aitherium/awfind) | A portable search client — query, results, ranking | [docs](https://aitherium.github.io/awfind/) |
| [awbrowse](https://github.com/Aitherium/awbrowse) | A portable browser client — navigate, console, network, DOM, screenshot | [docs](https://aitherium.github.io/awbrowse/) |
| [awknowledge](https://github.com/Aitherium/awknowledge) | How to run a coding agent so the result survives — the laws, with evidence | — |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | Near-optimal KV cache quantization for LLM inference — sub-byte compression | [docs](https://aitherium.github.io/aitherkvcache/) |
| [AitherZero](https://github.com/Aitherium/AitherZero) | PowerShell 7+ automation framework — numbered, self-describing scripts | [docs](https://aitherium.github.io/AitherZero/) |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | Browser extension — federated AI search, page context, and the Living OS overlay | [docs](https://aitherium.github.io/AitherConnect/) |
| [awreason](https://github.com/Aitherium/awreason) | A portable reasoning client — sessions, phases, thoughts, and the chain that produced the answer | [docs](https://aitherium.github.io/awreason/) |
| [awrecurse](https://github.com/Aitherium/awrecurse) | Answer a question over a context far larger than the window — recursively, with the trace kept | [docs](https://aitherium.github.io/awrecurse/) |
| [awprism](https://github.com/Aitherium/awprism) | Turn a failure into ranked hypotheses — and say what would confirm each one | [docs](https://aitherium.github.io/awprism/) |
| [awrepl](https://github.com/Aitherium/awrepl) | A REPL an agent can actually use — state that survives between turns | [docs](https://aitherium.github.io/awrepl/) |
| [awresearch](https://github.com/Aitherium/awresearch) | Ask a research question, get a cited report you can check | [docs](https://aitherium.github.io/awresearch/) |
| [awkno](https://github.com/Aitherium/awkno) | The man page for the Aither World — every brick, stack and law, offline | [docs](https://aitherium.github.io/awkno/) |

<div id="aither-constellation" data-self="awnest"></div>
<script src="aither-constellation.js"></script>

<!-- aither-ecosystem:end -->
