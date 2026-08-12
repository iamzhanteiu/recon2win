"""JavaScript vulnerability analyzers.

Each analyzer consumes an acquired asset + its ParsedModule and emits
structured records (DataFlow / Endpoint / raw hits). The candidate engine
(``jsvh.candidates``) turns high-value records into ranked Candidates.

    sources ─┐
    sinks   ─┼─▶ dataflow ─▶ candidates
    endpoints┤
    secrets  │
    postmessage / prototype_pollution / auth / websocket ─▶ candidates
"""
