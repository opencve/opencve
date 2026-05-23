from dataclasses import dataclass

from django.db.models import Q

from opencve.utils import is_valid_uuid


@dataclass(frozen=True)
class KeysetPage:
    """Result of a forward-only keyset pagination query."""

    items: list
    has_next: bool
    next_cursor: tuple[str, str] | None


def parse_keyset_cursor(name, id_, *, max_name_length=256):
    """Return a validated cursor, or None if invalid or missing."""
    if not name and not id_:
        return None

    if not name or not id_:
        return None

    if not name.strip() or len(name) > max_name_length:
        return None

    if not is_valid_uuid(id_):
        return None

    return name, id_


def paginate_keyset(queryset, *, cursor, limit=20):
    """Fetch the next page ordered by name and id using a keyset cursor."""
    qs = queryset.order_by("name", "id")

    if cursor:
        cursor_name, cursor_id = cursor
        qs = qs.filter(Q(name__gt=cursor_name) | Q(name=cursor_name, id__gt=cursor_id))

    items = list(qs[: limit + 1])
    has_next = len(items) > limit
    if has_next:
        items = items[:limit]

    next_cursor = None
    if has_next:
        last = items[-1]
        next_cursor = (last.name, str(last.id))

    return KeysetPage(items=items, has_next=has_next, next_cursor=next_cursor)


def keyset_cursor_payload(page):
    """Build JSON cursor fields from a KeysetPage."""
    payload = {"has_next": page.has_next, "after": None, "after_id": None}
    if page.next_cursor:
        payload["after"], payload["after_id"] = page.next_cursor
    return payload
