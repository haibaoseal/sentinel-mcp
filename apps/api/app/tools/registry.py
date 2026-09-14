"""Registry of tool sources.

The registry answers two questions and nothing else: what tools exist, and how
to run one. It deliberately has no policy logic and no audit logic -- those live
in the firewall, so there is exactly one place where an execution can be
authorised.

Collision handling matters for the MCP phase: a remote server must not be able
to shadow a local tool by advertising the same name. ``describe``/``execute``
resolve the first registered source that claims a name, and sources are appended
in a fixed order with local tools first, so a remote server can never take over
a local name.
"""

from __future__ import annotations

from app.core.contracts import ToolDescriptor, ToolSource
from app.core.errors import ToolNotFoundError


class AmbiguousToolError(Exception):
    def __init__(self, name: str, sources: list[str]) -> None:
        super().__init__(f"tool {name!r} is advertised by multiple sources: {', '.join(sources)}")
        self.name = name
        self.sources = sources


class ToolRegistry:
    def __init__(self, sources: list[ToolSource] | None = None) -> None:
        self._sources: list[ToolSource] = list(sources or [])
        # Precomputed on demand; MCP descriptors can change at runtime, so this
        # is rebuilt rather than cached forever.
        self._descriptor_index: dict[str, ToolDescriptor] = {}
        self._source_index: dict[str, ToolSource] = {}
        # Must build the index here. Storing sources without indexing them made a
        # constructor-built registry silently expose *zero* tools -- the agent
        # would simply do nothing, which is far harder to notice than an error.
        self.refresh()

    def add_source(self, source: ToolSource) -> None:
        self._sources.append(source)
        self.refresh()

    def refresh(self) -> None:
        """Rebuild the name -> source map.

        Raises on a collision rather than silently preferring one source: two
        tools with the same name and different behaviour is exactly the kind of
        ambiguity an attacker benefits from.
        """
        descriptors: dict[str, ToolDescriptor] = {}
        owners: dict[str, ToolSource] = {}
        seen: dict[str, list[str]] = {}

        for source in self._sources:
            for descriptor in source.descriptors():
                seen.setdefault(descriptor.name, []).append(source.name)
                if descriptor.name not in descriptors:
                    descriptors[descriptor.name] = descriptor
                    owners[descriptor.name] = source

        clashes = {name: sources for name, sources in seen.items() if len(sources) > 1}
        if clashes:
            name, sources = next(iter(clashes.items()))
            raise AmbiguousToolError(name, sources)

        self._descriptor_index = descriptors
        self._source_index = owners

    # -- queries ------------------------------------------------------------

    def names(self) -> list[str]:
        return sorted(self._descriptor_index)

    def descriptors(self) -> list[ToolDescriptor]:
        return [self._descriptor_index[name] for name in self.names()]

    def describe(self, name: str) -> ToolDescriptor | None:
        return self._descriptor_index.get(name)

    def source_name(self, name: str) -> str | None:
        source = self._source_index.get(name)
        return source.name if source else None

    # -- execution ----------------------------------------------------------

    def execute(self, name: str, arguments: dict) -> dict:
        """Run a tool. Called only by the firewall."""
        source = self._source_index.get(name)
        if source is None:
            raise ToolNotFoundError(f"tool is not registered: {name}")
        return source.execute(name, arguments)
