"""
Generic list shaping: search, filter, sort, paginate.

This mirrors exactly what a real API is expected to do server-side for any
list endpoint — it is a presentation concern (RULE-004), not analysis. No
value here is computed from cryptographic parameters; it only reorders and
slices records that already carry the fields being filtered on.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

from fastapi import Query


class ListParams:
    def __init__(
        self,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        sort: Optional[str] = Query(None),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        q: Optional[str] = Query(None),
    ) -> None:
        self.page = page
        self.page_size = page_size
        self.sort = sort
        self.order = order
        self.q = (q or "").strip().lower()


def _get(row: dict[str, Any], key: str) -> Any:
    return row.get(key)


def apply_search(rows: list[dict[str, Any]], query: str, fields: list[str]) -> list[dict[str, Any]]:
    if not query:
        return rows
    out = []
    for row in rows:
        haystack = " ".join(str(_get(row, f) or "") for f in fields).lower()
        if query in haystack:
            out.append(row)
    return out


def apply_sort(
    rows: list[dict[str, Any]], sort_key: Optional[str], order: str
) -> list[dict[str, Any]]:
    if not sort_key:
        return rows
    reverse = order != "asc"

    def key(row: dict[str, Any]):
        value = _get(row, sort_key)
        if value is None:
            return (1, "")
        if isinstance(value, (int, float)):
            return (0, value)
        return (0, str(value))

    return sorted(rows, key=key, reverse=reverse)


def paginate(rows: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    total = len(rows)
    start = (page - 1) * page_size
    data = rows[start : start + page_size]
    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "data": data,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total,
            "total_pages": total_pages,
        },
    }
