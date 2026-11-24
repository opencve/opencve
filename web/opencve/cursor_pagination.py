import base64
import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any
from django.core.cache import cache
from django.db.models import F, Q
from django.utils.dateparse import parse_datetime

from opencve.utils import is_valid_uuid

LIST_COUNT_CACHE_TTL = 30
OPAQUE_CURSOR_MAX_LEN = 512
OPAQUE_CURSOR_MAX_DECODED_BYTES = 2048
LIST_PAGINATION_IGNORED_PARAMS = frozenset({"after", "before", "page"})
PAGE_NUMBER_MAX = 9_999_999
CVE_LIST_COUNT_FILTERS = ("q", "vendor", "product", "weakness", "search", "tag")


@dataclass(frozen=True)
class CursorPage:
    """Bidirectional keyset page with opaque cursors."""

    items: list
    has_next: bool
    has_previous: bool
    after: str | None
    before: str | None


def encode_opaque_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_opaque_cursor(token: str | None) -> dict[str, Any] | None:
    if not token or not isinstance(token, str):
        return None
    if len(token) > OPAQUE_CURSOR_MAX_LEN:
        return None
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        if len(raw) > OPAQUE_CURSOR_MAX_DECODED_BYTES:
            return None
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def parse_page_number(raw_value, *, default: int = 1) -> int:
    """Return a safe 1-based page number from a query parameter."""
    if raw_value is None or raw_value == "":
        return default
    if isinstance(raw_value, bool):
        return default
    if not isinstance(raw_value, (int, str)):
        return default
    try:
        page = int(raw_value)
    except (TypeError, ValueError):
        return default
    if page < 1:
        return default
    return min(page, PAGE_NUMBER_MAX)


def cve_list_count_cache_key(request) -> str:
    """
    Cache key for CVE list COUNT queries (not row data).

    Public filter combinations may share an entry. User tag, tag=, and project:
    filters always add an explicit scope so those counts never reuse public keys.
    """
    parts = [
        f"{key}={request.GET[key]}"
        for key in CVE_LIST_COUNT_FILTERS
        if request.GET.get(key)
    ]
    query = request.GET.get("q", "")
    user_scoped = request.GET.get("tag") or "userTag:" in query or "project:" in query
    if user_scoped:
        parts.append("scope=user")
        user = getattr(request, "user", None)
        if getattr(user, "is_authenticated", False):
            parts.append(f"user={user.pk}")
        else:
            parts.append("user=unauthenticated")
        organization = getattr(request, "current_organization", None)
        if organization is not None:
            parts.append(f"org={organization.pk}")
        elif "project:" in query:
            parts.append("org=none")
    else:
        parts.append("scope=public")
    digest = hashlib.sha256("&".join(parts).encode("utf-8")).hexdigest()
    return f"cve_list_count:{digest}"


def weakness_list_count_cache_key(request) -> str:
    search = request.GET.get("search", "")
    digest = hashlib.sha256(f"search={search}".encode("utf-8")).hexdigest()
    return f"weakness_list_count:{digest}"


def cve_list_page_requires_auth(request) -> bool:
    """User-scoped CVE list filters require an authenticated session."""
    query = request.GET.get("q", "")
    if request.GET.get("tag"):
        return True
    return "userTag:" in query or "project:" in query


def cve_list_page_requires_organization(request) -> bool:
    return "project:" in request.GET.get("q", "")


def build_cursor_list_initial_state(*, total_count: int, total_pages_count: int, page):
    return {
        "page": 1,
        "total": total_count,
        "total_pages": total_pages_count,
        "has_next": page.has_next,
        "has_previous": False,
        "after": page.after,
        "before": page.before,
    }


def cached_queryset_count(
    queryset, cache_key: str, *, ttl: int = LIST_COUNT_CACHE_TTL
) -> int:
    count = cache.get(cache_key)
    if count is None:
        count = queryset.count()
        cache.set(cache_key, count, ttl)
    return count


def total_pages(count: int, *, page_size: int) -> int:
    if count <= 0:
        return 0
    return math.ceil(count / page_size)


def _cve_cursor_from_instance(cve) -> str:
    return encode_opaque_cursor({"u": cve.updated_at.isoformat(), "i": str(cve.id)})


def _parse_cve_cursor(token: str | None) -> tuple | None:
    payload = decode_opaque_cursor(token)
    if not payload:
        return None
    updated_raw = payload.get("u")
    row_id = payload.get("i")
    if not updated_raw or not row_id or not is_valid_uuid(row_id):
        return None
    updated_at = parse_datetime(updated_raw)
    if updated_at is None:
        return None
    return updated_at, row_id


def paginate_cve_queryset(
    queryset, *, after: str | None, before: str | None, limit: int = 20
):
    qs = queryset.order_by("-updated_at", "-id")

    if after and before:
        return CursorPage(
            items=[], has_next=False, has_previous=False, after=None, before=None
        )

    if before:
        cursor = _parse_cve_cursor(before)
        if not cursor:
            return _paginate_cve_first_page(qs, limit=limit)
        updated_at, row_id = cursor
        window = list(
            qs.filter(
                Q(updated_at__gt=updated_at) | Q(updated_at=updated_at, id__gt=row_id)
            ).order_by("updated_at", "id")[: limit + 1]
        )
        has_previous = len(window) > limit
        if has_previous:
            window = window[:limit]
        window.reverse()
        return _build_cursor_page(
            window,
            encode_row=_cve_cursor_from_instance,
            has_extra_before=has_previous,
            moving_back=True,
        )

    if after:
        cursor = _parse_cve_cursor(after)
        if not cursor:
            return _paginate_cve_first_page(qs, limit=limit)
        updated_at, row_id = cursor
        qs = qs.filter(
            Q(updated_at__lt=updated_at) | Q(updated_at=updated_at, id__lt=row_id)
        )

    return _paginate_cve_first_page(qs, limit=limit, has_previous=bool(after))


def _paginate_cve_first_page(qs, *, limit: int, has_previous: bool = False):
    window = list(qs[: limit + 1])
    has_next = len(window) > limit
    if has_next:
        window = window[:limit]
    return _build_cursor_page(
        window,
        encode_row=_cve_cursor_from_instance,
        has_extra_before=has_previous,
        has_extra_after=has_next,
    )


def _build_cursor_page(
    items,
    *,
    encode_row,
    has_extra_before: bool = False,
    has_extra_after: bool = False,
    moving_back: bool = False,
):
    if not items:
        return CursorPage(
            items=[],
            has_next=False,
            has_previous=has_extra_before,
            after=None,
            before=None,
        )

    after = encode_row(items[-1]) if has_extra_after else None
    before = encode_row(items[0])
    has_next = True if moving_back else has_extra_after
    has_previous = has_extra_before
    if not moving_back and not has_extra_before:
        has_previous = False

    return CursorPage(
        items=items,
        has_next=has_next,
        has_previous=has_previous,
        after=after,
        before=before,
    )


def _weakness_name_after(name, row_id):
    """Rows that sort after name DESC NULLS LAST, id DESC."""
    if name is None:
        return Q(name__isnull=True, id__lt=row_id)
    return Q(name__lt=name) | Q(name=name, id__lt=row_id) | Q(name__isnull=True)


def _weakness_name_before(name, row_id):
    """Rows that sort before name DESC NULLS LAST, id DESC."""
    if name is None:
        return Q(name__isnull=False) | Q(name__isnull=True, id__gt=row_id)
    return Q(name__gt=name) | Q(name=name, id__gt=row_id)


def _weakness_cursor_from_instance(weakness) -> str:
    return encode_opaque_cursor({"n": weakness.name, "i": str(weakness.id)})


def _parse_weakness_cursor(token: str | None) -> tuple | None:
    payload = decode_opaque_cursor(token)
    if not payload:
        return None
    if "n" not in payload:
        return None
    row_id = payload.get("i")
    if not row_id or not is_valid_uuid(row_id):
        return None
    name = payload["n"]
    if name is not None and not isinstance(name, str):
        return None
    return name, row_id


def paginate_weakness_queryset(
    queryset, *, after: str | None, before: str | None, limit: int = 20
):
    if after and before:
        return CursorPage(
            items=[], has_next=False, has_previous=False, after=None, before=None
        )

    if before:
        cursor = _parse_weakness_cursor(before)
        if not cursor:
            return _paginate_weakness_first_page(queryset, limit=limit)
        name, row_id = cursor
        window = list(
            queryset.filter(_weakness_name_before(name, row_id)).order_by(
                F("name").asc(nulls_first=True), F("id").asc()
            )[: limit + 1]
        )
        has_previous = len(window) > limit
        if has_previous:
            window = window[:limit]
        window.reverse()
        return _build_cursor_page(
            window,
            encode_row=_weakness_cursor_from_instance,
            has_extra_before=has_previous,
            moving_back=True,
        )

    qs = queryset
    if after:
        cursor = _parse_weakness_cursor(after)
        if not cursor:
            return _paginate_weakness_first_page(queryset, limit=limit)
        name, row_id = cursor
        qs = qs.filter(_weakness_name_after(name, row_id))

    return _paginate_weakness_first_page(qs, limit=limit, has_previous=bool(after))


def _paginate_weakness_first_page(qs, *, limit: int, has_previous: bool = False):
    window = list(
        qs.order_by(F("name").desc(nulls_last=True), F("id").desc())[: limit + 1]
    )
    has_next = len(window) > limit
    if has_next:
        window = window[:limit]
    return _build_cursor_page(
        window,
        encode_row=_weakness_cursor_from_instance,
        has_extra_before=has_previous,
        has_extra_after=has_next,
    )


def cursor_page_api_payload(
    page: CursorPage, *, page_number: int, total_count: int, page_size: int
):
    pages = total_pages(total_count, page_size=page_size)
    return {
        "page": page_number,
        "total": total_count,
        "total_pages": pages,
        "has_next": page.has_next,
        "has_previous": page.has_previous,
        "after": page.after,
        "before": page.before,
    }
