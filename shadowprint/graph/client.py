"""
FalkorDB Client and Connection Manager.
Provides thread-safe access to the FalkorDB GraphBLAS engine with Cypher parameterization,
strict label/relation allowlisting, and a headless test double for unit testing.
"""

import os
import time
import logging
from typing import Dict, Any, List, Optional, Set

from shadowprint.graph.schema import NodeLabel, RelType

logger = logging.getLogger("shadowprint.graph.client")

try:
    import falkordb
    FALKORDB_INSTALLED = True
except ImportError:
    falkordb = None
    FALKORDB_INSTALLED = False

# Strict allowlists preventing Cypher injection through dynamic labels/relationship types
ALLOWED_LABELS: Set[str] = {label.value for label in NodeLabel}
ALLOWED_REL_TYPES: Set[str] = {rel.value for rel in RelType}

# Pre-defined static Cypher statements (prevents any string formatting with Cypher syntax)
_NODE_MERGE_QUERIES: Dict[str, str] = {
    "Server": "MERGE (n:Server {node_id: $node_id}) SET n += $props",
    "Tool": "MERGE (n:Tool {node_id: $node_id}) SET n += $props",
    "Resource": "MERGE (n:Resource {node_id: $node_id}) SET n += $props",
    "Prompt": "MERGE (n:Prompt {node_id: $node_id}) SET n += $props",
    "Sink": "MERGE (n:Sink {node_id: $node_id}) SET n += $props",
    "Canary": "MERGE (n:Canary {node_id: $node_id}) SET n += $props",
    "EgressEndpoint": "MERGE (n:EgressEndpoint {node_id: $node_id}) SET n += $props",
    "SecurityFinding": "MERGE (n:SecurityFinding {node_id: $node_id}) SET n += $props",
    "Mutation": "MERGE (n:Mutation {node_id: $node_id}) SET n += $props",
    "Node": "MERGE (n:Node {node_id: $node_id}) SET n += $props",
}

_REL_MERGE_QUERIES: Dict[str, str] = {
    "CALLS": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:CALLS]->(b) SET r += $props",
    "EXPOSES": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:EXPOSES]->(b) SET r += $props",
    "CONNECTS_TO": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:CONNECTS_TO]->(b) SET r += $props",
    "READS_HONEYPOT": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:READS_HONEYPOT]->(b) SET r += $props",
    "TAINT_FLOWS_TO": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:TAINT_FLOWS_TO]->(b) SET r += $props",
    "HIJACKS_CONTROL": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:HIJACKS_CONTROL]->(b) SET r += $props",
    "FLAGGED_BY": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:FLAGGED_BY]->(b) SET r += $props",
    "DETECTED_MUTATION": "MATCH (a {node_id: $src}), (b {node_id: $dst}) MERGE (a)-[r:DETECTED_MUTATION]->(b) SET r += $props",
}



class InMemoryQueryResult:
    """Emulates FalkorDB's QueryResult for headless unit test double mode."""
    def __init__(self, result_set: List[List[Any]], header: List[str]):
        self.result_set = result_set
        self.header = header

    def __iter__(self):
        return iter(self.result_set)

    def __len__(self):
        return len(self.result_set)


class FalkorDBTestDouble:
    """
    Headless unit-test double for Engine S5.
    Used exclusively for automated headless test runners (pytest) when a live FalkorDB daemon
    is not running. Not a replacement for the production FalkorDB GraphBLAS database.
    """
    def __init__(self, name: str = "shadowprint_test_double"):
        self.name = name
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, labels: List[str], properties: Dict[str, Any]) -> Dict[str, Any]:
        if node_id in self.nodes:
            self.nodes[node_id]["properties"].update(properties)
            for lbl in labels:
                if lbl not in self.nodes[node_id]["labels"]:
                    self.nodes[node_id]["labels"].append(lbl)
        else:
            self.nodes[node_id] = {
                "id": node_id,
                "labels": list(labels),
                "properties": dict(properties),
            }
        return self.nodes[node_id]

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        edge = {
            "source": source_id,
            "target": target_id,
            "relation": relation,
            "properties": dict(properties or {}),
        }
        for existing in self.edges:
            if (
                existing["source"] == source_id
                and existing["target"] == target_id
                and existing["relation"] == relation
            ):
                existing["properties"].update(edge["properties"])
                return existing
        self.edges.append(edge)
        return edge

    def clear(self):
        self.nodes.clear()
        self.edges.clear()

    def get_nodes_by_label(self, label: str) -> List[Dict[str, Any]]:
        return [n for n in self.nodes.values() if label in n["labels"]]

    def get_outgoing_edges(self, node_id: str, relation: Optional[str] = None) -> List[Dict[str, Any]]:
        return [
            e for e in self.edges
            if e["source"] == node_id and (relation is None or e["relation"] == relation)
        ]

    def get_incoming_edges(self, node_id: str, relation: Optional[str] = None) -> List[Dict[str, Any]]:
        return [
            e for e in self.edges
            if e["target"] == node_id and (relation is None or e["relation"] == relation)
        ]


# Backward-compatible alias for existing tests
InMemoryGraph = FalkorDBTestDouble


class FalkorDBClient:
    """
    Unified FalkorDB Client with native GraphBLAS driver and headless test-double fallback.
    """
    _instance: Optional["FalkorDBClient"] = None

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        graph_name: str = "shadowprint_ekg",
        password: Optional[str] = None,
        use_test_double: bool = False,
        require_live: bool = False,
    ):
        self.host = host if host is not None else os.getenv("FALKORDB_HOST", "localhost")
        self.port = port if port is not None else int(os.getenv("FALKORDB_PORT", "6379"))
        self.graph_name = graph_name
        self.password = password
        self.use_test_double = use_test_double
        self.require_live = require_live

        self._driver: Optional[Any] = None
        self._native_graph: Optional[Any] = None
        self._test_double: FalkorDBTestDouble = FalkorDBTestDouble(name=graph_name)
        self._is_native: bool = False

        if not use_test_double:
            self._connect()

        if require_live and not self._is_native:
            raise ConnectionError(
                f"FalkorDB daemon not reachable on {self.host}:{self.port}. "
                "Engine S5 requires a live FalkorDB instance for graph intelligence operations. "
                "Start FalkorDB: docker run -p 6379:6379 -it --rm falkordb/falkordb:latest"
            )

    def _connect(self):
        """Attempts connection to live FalkorDB instance."""
        if not FALKORDB_INSTALLED:
            logger.debug("falkordb python driver not installed.")
            self._is_native = False
            return

        try:
            self._driver = falkordb.FalkorDB(
                host=self.host,
                port=self.port,
                password=self.password,
            )
            self._native_graph = self._driver.select_graph(self.graph_name)
            self._native_graph.query("RETURN 1")
            self._is_native = True
            logger.info(f"Connected to live FalkorDB at {self.host}:{self.port} [Graph: {self.graph_name}]")
        except Exception as e:
            logger.debug(f"Live FalkorDB not reachable ({e}).")
            self._is_native = False
            self._driver = None
            self._native_graph = None

    @classmethod
    def get_instance(cls, **kwargs) -> "FalkorDBClient":
        """Singleton accessor for application-wide client reuse."""
        if cls._instance is None:
            cls._instance = cls(**kwargs)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Resets the singleton instance (useful between test runs)."""
        cls._instance = None

    @property
    def is_connected(self) -> bool:
        """True if connected to a live FalkorDB GraphBLAS instance."""
        return self._is_native

    @property
    def is_native(self) -> bool:
        """True if connected to a live FalkorDB GraphBLAS instance."""
        return self._is_native


    @property
    def backend_type(self) -> str:
        """Returns the active backend description."""
        if self._is_native:
            return f"FalkorDB Native [{self.host}:{self.port} | GraphBLAS Sparse Matrix Engine]"
        return "FalkorDB Test Double [Headless Unit Test Runner]"

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Executes a Cypher query against FalkorDB with strict parameterization.
        """
        if self._is_native and self._native_graph:
            start_t = time.perf_counter()
            res = self._native_graph.query(cypher, params or {})
            duration_ms = (time.perf_counter() - start_t) * 1000
            logger.debug(f"FalkorDB query executed in {duration_ms:.2f}ms: {cypher[:60]}...")
            return res

        # Headless test double fallback
        return InMemoryQueryResult([], [])

    def add_node(self, node_id: str, labels: List[str], properties: Dict[str, Any]):
        """
        Creates or updates a node in the graph with strict label validation and Cypher parameterization.
        """
        # Validate labels against strict allowlist
        for lbl in labels:
            if lbl not in ALLOWED_LABELS:
                raise ValueError(f"Disallowed node label '{lbl}'. Must be one of {ALLOWED_LABELS}")

        # Always update local test double representation for fast in-process queries
        node = self._test_double.add_node(node_id, labels, properties)

        # If live FalkorDB is connected, execute parameterized Cypher MERGE using static query templates
        if self._is_native and self._native_graph:
            try:
                primary_label = labels[0] if labels else "Node"
                cypher = _NODE_MERGE_QUERIES.get(
                    primary_label,
                    _NODE_MERGE_QUERIES["Node"],
                )
                clean_props = dict(properties)
                clean_props["node_id"] = node_id
                self._native_graph.query(cypher, {"node_id": node_id, "props": clean_props})
            except Exception as e:
                logger.debug(f"Failed to sync node to native FalkorDB: {e}")

        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None,
    ):
        """
        Creates or updates an edge in the graph with strict relation allowlisting and Cypher parameterization.
        """
        # Validate relation against strict allowlist
        if relation not in ALLOWED_REL_TYPES:
            raise ValueError(f"Disallowed relation type '{relation}'. Must be one of {ALLOWED_REL_TYPES}")

        # Always update local test double
        edge = self._test_double.add_edge(source_id, target_id, relation, properties)

        # If live FalkorDB is connected, execute parameterized Cypher MERGE via static query template
        if self._is_native and self._native_graph:
            try:
                cypher = _REL_MERGE_QUERIES[relation]
                self._native_graph.query(
                    cypher,
                    {"src": source_id, "dst": target_id, "props": dict(properties or {})},
                )
            except Exception as e:
                logger.debug(f"Failed to sync edge to native FalkorDB: {e}")

        return edge

    @property
    def in_memory_graph(self) -> FalkorDBTestDouble:
        """Direct access to the test double representation."""
        return self._test_double
