# `.tm7` fixtures

`small.tm7` is hand-made (by a throwaway script, not by TMT) in the exact structure of a real
TMT 7.3 file: namespaces, element order, attribute encoding and threat records copied from one.
It holds a customer, a web application with one changed attribute, a data store, an out-of-scope
actor, a boundary box, two flows (one HTTPS) and two TMT threats: one untouched, one marked
Mitigated with a justification. Names and people in it are invented.

Real models live in `tests/fixtures/private/`, which is gitignored; the parity test in
`tests/test_tm7.py` uses them when present.
