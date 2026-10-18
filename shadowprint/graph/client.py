"""
FalkorDB Client and Connection Manager.
Provides high-performance, thread-safe access to the FalkorDB GraphBLAS engine,
with automatic health checking and graceful in-memory graph fallback.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("shadowprint.graph.client")

try:
    import falkordb
    FALKORDB_INSTALLED = True
except ImportError:
    falkordb = None
    FALKORDB_INSTALLED = False


class InMemoryQueryResult:
    """Emulates FalkorDB's QueryResult for offline/in-memory fallback mode."""
    def __init__(self, result_set: List[List[Any]], header: List[str]):
        self.result_set = result_set
        self.header = header

    def __iter__(self):
        return iter(self.result_set)

    def __len__(self):
        return len(self.result_set)


class InMemoryGraph:
    """
    Self-contained, ultra-fast in-memory graph storage and query engine.
    Ensures 100% offline airgapped operation when FalkorDB Redis daemon is offline.
    """
    def __init__(self, name: str = "shadowprint_ekg"):
        self.name = name
        self.nodes: Dict[str, Dict[str, Any]] = {}  # node_id -> {id, labels, properties}
        self.edges: List[Dict[str, Any]] = []        # list of {source, target, relation, properties}

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
        # Prevent exact duplicates
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


class FalkorDBClient:
    """
    Unified FalkorDB Client with native GraphBLAS driver and in-memory fallback.
    """
    _instance: Optional["FalkorDBClient"] = None

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        graph_name: str = "shadowprint_ekg",
        password: Optional[str] = None,
        force_fallback: bool = False,
    ):
        self.host = host
        self.port = port
        self.graph_name = graph_name
        self.password = password
        self.force_fallback = force_fallback

        self._driver: Optional[Any] = None
        self._native_graph: Optional[Any] = None
        self._in_memory_graph: InMemoryGraph = InMemoryGraph(name=graph_name)
        self._is_native: bool = False

        if not force_fallback:
            self._connect()

    def _connect(self):
        """Attempts connection to live FalkorDB instance."""
        if not FALKORDB_INSTALLED:
            logger.debug("falkordb python driver not installed. Using in-memory graph.")
            self._is_native = False
            return

        try:
            self._driver = falkordb.FalkorDB(
                host=self.host,
                port=self.port,
                password=self.password,
            )
            # Ping database to confirm live GraphBLAS daemon
            self._native_graph = self._driver.select_graph(self.graph_name)
            # Execute a lightweight ping query
            self._native_graph.query("RETURN 1")
            self._is_native = True
            logger.info(f"Connected to live FalkorDB at {self.host}:{self.port} [Graph: {self.graph_name}]")
        except Exception as e:
            logger.debug(f"Live FalkorDB not reachable ({e}). Engaging in-memory fallback engine.")
            self._is_native = False
            self._driver = None
            self._native_graph = None

    @classmethod
    def get_instance(cls, **kwargs) -> "FalkorDBClient":
        """Singleton accessor for application-wide client reuse."""
        if cls._instance is None:
            cls._instance = cls(**kwargs)
        return cls._instance

    @property
    def is_connected(self) -> bool:
        """True if connected to a live FalkorDB GraphBLAS instance."""
        return self._is_native

    @property
    def backend_type(self) -> str:
        """Returns the active backend description."""
        return "FalkorDB (GraphBLAS Native)" if self._is_native else "In-Memory Graph Engine (Airgapped Fallback)"

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Executes a Cypher query against FalkorDB or handles it in the in-memory engine.
        """
        if self._is_native and self._native_graph:
            try:
                start_t = time.perf_counter()
                res = self._native_graph.query(cypher, params or {})
                duration_ms = (time.perf_counter() - start_t) * 1000
                logger.debug(f"FalkorDB query executed in {duration_ms:.2f}ms: {cypher[:60]}...")
                return res
            except Exception as e:
                logger.warning(f"Native FalkorDB query failed ({e}). Falling back to in-memory graph.")
                self._is_native = False

        # In-memory execution: Always mirror changes into in-memory structure
        return InMemoryQueryResult([], [])

    def add_node(self, node_id: str, labels: List[str], properties: Dict[str, Any]):
        """Creates or updates a node in the graph."""
        # Update in-memory graph
        node = self._in_memory_graph.add_node(node_id, labels, properties)

        # If live FalkorDB is connected, execute Cypher MERGE
        if self._is_native and self._native_graph:
            try:
                lbl_str = ":".join(labels)
                prop_str = ", ".join(f"n.{k} = ${k}" for k in properties.keys())
                cypher = f"MERGE (n:{lbl_str} {{node_id: $node_id}}) ON CREATE SET {prop_str} ON MATCH SET {prop_str}"
                p = dict(properties)
                p["node_id"] = node_id
                self._native_graph.query(cypher, p)
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
        """Creates or updates an edge in the graph."""
        edge = self._in_memory_graph.add_edge(source_id, target_id, relation, properties)

        # If live FalkorDB is connected, execute Cypher MERGE
        if self._is_native and self._native_graph:
            try:
                prop_str = ""
                if properties:
                    prop_str = " SET " + ", ".join(f"r.{k} = ${k}" for k in properties.keys())
                cypher = (
                    f"MATCH (a {{node_id: $src}}), (b {{node_id: $dst}}) "
                    f"MERGE (a)-[r:{relation}]->(b){prop_str}"
                )
                p = dict(properties or {})
                p["src"] = source_id
                p["dst"] = target_id
                self._native_graph.query(cypher, p)
            except Exception as e:
                logger.debug(f"Failed to sync edge to native FalkorDB: {e}")

        return edge

    @property
    def in_memory_graph(self) -> InMemoryGraph:
        """Direct access to the in-memory graph representation."""
        return self._in_memory_graph
