(function ($) {
    "use strict";

    var LIST_IGNORED_PARAMS = ["after", "before", "page"];
    var PAGE_HISTORY_LIMIT = 100;
    var popstateHandlers = [];

    function normalizedQueryString(searchParams) {
        var parts = [];
        searchParams.forEach(function (value, key) {
            if (LIST_IGNORED_PARAMS.indexOf(key) !== -1 || !value) {
                return;
            }
            parts.push([key, value]);
        });
        parts.sort(function (a, b) {
            if (a[0] === b[0]) {
                return a[1].localeCompare(b[1]);
            }
            return a[0].localeCompare(b[0]);
        });
        return parts
            .map(function (pair) {
                return encodeURIComponent(pair[0]) + "=" + encodeURIComponent(pair[1]);
            })
            .join("&");
    }

    function paginationState(page, payload, entryAfter) {
        return {
            page: page,
            after: payload.after || null,
            before: payload.before || null,
            entry_after: entryAfter === undefined ? null : entryAfter,
            total: payload.total,
            total_pages: payload.total_pages,
            has_next: payload.has_next,
            has_previous: payload.has_previous,
        };
    }

    function readStorage(storageKey) {
        try {
            var raw = sessionStorage.getItem(storageKey);
            if (!raw) {
                return null;
            }
            return JSON.parse(raw);
        } catch (e) {
            return null;
        }
    }

    function writeStorage(storageKey, state, queryKey) {
        sessionStorage.setItem(
            storageKey,
            JSON.stringify({
                query: queryKey,
                pagination: state,
            })
        );
        rememberPageEntry(storageKey, queryKey, state);
    }

    function pagesStorageKey(storageKey, queryKey) {
        return storageKey + ":pages:" + queryKey;
    }

    function rememberPageEntry(storageKey, queryKey, state) {
        var pagesKey = pagesStorageKey(storageKey, queryKey);
        var pages = [];
        try {
            pages = JSON.parse(sessionStorage.getItem(pagesKey) || "[]");
        } catch (e) {
            pages = [];
        }
        pages = pages.filter(function (entry) {
            return entry.page !== state.page;
        });
        pages.push({
            page: state.page,
            entry_after: state.entry_after || null,
        });
        if (pages.length > PAGE_HISTORY_LIMIT) {
            pages = pages.slice(-PAGE_HISTORY_LIMIT);
        }
        sessionStorage.setItem(pagesKey, JSON.stringify(pages));
    }

    function lookupEntryAfter(storageKey, queryKey, page) {
        try {
            var pages = JSON.parse(
                sessionStorage.getItem(pagesStorageKey(storageKey, queryKey)) || "[]"
            );
            var match = pages.find(function (entry) {
                return entry.page === page;
            });
            return match ? match.entry_after : null;
        } catch (e) {
            return null;
        }
    }

    function clearStorage(storageKey, queryKey) {
        sessionStorage.removeItem(storageKey);
        if (queryKey) {
            sessionStorage.removeItem(pagesStorageKey(storageKey, queryKey));
        }
    }

    function updateUi($root, state) {
        var $status = $root.find(".opencve-cursor-pagination-status");
        var totalPages = state.total_pages || 0;
        var page = state.page || 1;
        if (totalPages > 0) {
            $status.text(
                "Page " +
                    page +
                    " / " +
                    totalPages.toLocaleString("en-US")
            );
        } else {
            $status.text("Page " + page);
        }

        $root.find('[data-action="previous"]').prop("disabled", !state.has_previous);
        $root.find('[data-action="next"]').prop("disabled", !state.has_next);
        $root.find(".opencve-cve-list-results-count").text(
            (state.total || 0).toLocaleString("en-US")
        );
    }

    function paginationErrorMessage(xhr, fallbackMessage) {
        var status = xhr && xhr.status;
        if (status === 401) {
            return "You must sign in to use this search.";
        }
        if (status === 403) {
            return "You do not have permission to view this page.";
        }
        if (status >= 500) {
            return "A server error occurred. Please try again later.";
        }
        return fallbackMessage;
    }

    function showPaginationError($root, xhr, fallbackMessage) {
        console.error(
            "Cursor pagination request failed",
            xhr ? xhr.status : "unknown",
            xhr
        );
        var message = paginationErrorMessage(xhr, fallbackMessage);
        var $banner = $root.siblings(".opencve-cursor-pagination-error");
        if (!$banner.length) {
            $banner = $(
                '<div class="alert alert-danger alert-dismissible opencve-cursor-pagination-error" role="alert">' +
                    '<button type="button" class="close" data-dismiss="alert" aria-label="Close">' +
                    '<span aria-hidden="true">&times;</span></button>' +
                    '<span class="opencve-cursor-pagination-error-text"></span></div>'
            );
            $root.before($banner);
        }
        $banner.find(".opencve-cursor-pagination-error-text").text(message);
        $banner.show();
    }

    function hidePaginationError($root) {
        $root.siblings(".opencve-cursor-pagination-error").hide();
    }

    function scrollToListTop($root) {
        var $section = $root.closest("section.content");
        var top = 0;
        if ($section.length) {
            top = Math.max(0, $section.offset().top - 70);
        }
        $("html, body").stop(true).animate({ scrollTop: top }, 200);
        var wrapper = document.querySelector(".content-wrapper");
        if (wrapper) {
            wrapper.scrollTop = 0;
        }
    }

    function fetchPage($root, options) {
        var pageUrl = $root.data("page-url");
        var params = new URLSearchParams(window.location.search);
        if (options.after) {
            params.set("after", options.after);
        } else {
            params.delete("after");
        }
        if (options.before) {
            params.set("before", options.before);
        } else {
            params.delete("before");
        }
        params.set("page", String(options.page));

        $root.addClass("is-loading");
        return $.ajax({
            url: pageUrl,
            data: params.toString(),
            dataType: "json",
            type: "GET",
        }).always(function () {
            $root.removeClass("is-loading");
        });
    }

    function mountListPagination($root) {
        var listType = $root.data("list");
        var storageKey = $root.data("storage-key");
        var contentSelector = $root.data("content-target");
        var $content = $(contentSelector);
        var queryKey = normalizedQueryString(new URLSearchParams(window.location.search));
        var initialStateId = $root.data("initial-state-id");
        var initial = null;
        if (initialStateId) {
            var initialNode = document.getElementById(initialStateId);
            if (initialNode) {
                try {
                    initial = JSON.parse(initialNode.textContent);
                } catch (e) {
                    initial = null;
                }
            }
        }
        if (!initial) {
            initial = $root.data("initial-state");
        }
        if (!initial) {
            return;
        }

        function applyResponse(data, state, historyMode) {
            hidePaginationError($root);
            $content.html(data.html);
            updateUi($root, state);
            writeStorage(storageKey, state, queryKey);

            if (historyMode === "push" || historyMode === null) {
                scrollToListTop($root);
            }

            if (historyMode === "push") {
                history.pushState(
                    {
                        opencveList: listType,
                        query: queryKey,
                        pagination: state,
                    },
                    "",
                    window.location.pathname + window.location.search
                );
            } else if (historyMode === "replace") {
                history.replaceState(
                    {
                        opencveList: listType,
                        query: queryKey,
                        pagination: state,
                    },
                    "",
                    window.location.pathname + window.location.search
                );
            }
        }

        function goToState(state, historyMode) {
            var request = {
                page: state.page,
                after: null,
                before: null,
            };
            if (state.page > 1) {
                request.after = state.entry_after;
            }
            return fetchPage($root, request).then(function (data) {
                var entryAfter = state.entry_after;
                if (entryAfter === undefined) {
                    entryAfter = lookupEntryAfter(storageKey, queryKey, state.page);
                }
                var nextState = paginationState(state.page, data, entryAfter);
                applyResponse(data, nextState, historyMode);
            });
        }

        function bootstrap() {
            clearStorage(storageKey, queryKey);

            var startState = paginationState(initial.page, initial, null);
            startState.total = initial.total;
            startState.total_pages = initial.total_pages;
            startState.has_next = initial.has_next;
            startState.has_previous = initial.has_previous;
            startState.after = initial.after;
            startState.before = initial.before;
            startState.entry_after = null;

            updateUi($root, startState);
            writeStorage(storageKey, startState, queryKey);
            history.replaceState(
                {
                    opencveList: listType,
                    query: queryKey,
                    pagination: startState,
                },
                "",
                window.location.pathname + window.location.search
            );
            return $.Deferred().resolve().promise();
        }

        $root.on("click", '[data-action="next"]', function () {
            var current = readStorage(storageKey);
            if (!current || current.query !== queryKey) {
                return;
            }
            var currentState = current.pagination;
            if (!currentState.has_next || !currentState.after) {
                return;
            }
            var nextPage = currentState.page + 1;
            fetchPage($root, { page: nextPage, after: currentState.after })
                .done(function (data) {
                    var nextState = paginationState(
                        nextPage,
                        data,
                        currentState.after
                    );
                    applyResponse(data, nextState, "push");
                })
                .fail(function (xhr) {
                    showPaginationError(
                        $root,
                        xhr,
                        "Unable to load the next page. Please try again."
                    );
                });
        });

        $root.on("click", '[data-action="previous"]', function () {
            var current = readStorage(storageKey);
            if (!current || current.query !== queryKey) {
                return;
            }
            var currentState = current.pagination;
            if (!currentState.has_previous || !currentState.before) {
                return;
            }
            var prevPage = Math.max(1, currentState.page - 1);
            if (prevPage === 1) {
                fetchPage($root, { page: 1, after: null, before: null })
                    .done(function (data) {
                        var firstState = paginationState(1, data, null);
                        applyResponse(data, firstState, "push");
                    })
                    .fail(function (xhr) {
                        showPaginationError(
                            $root,
                            xhr,
                            "Unable to load the previous page. Please try again."
                        );
                    });
                return;
            }
            fetchPage($root, { page: prevPage, before: currentState.before })
                .done(function (data) {
                    var entryAfter = lookupEntryAfter(storageKey, queryKey, prevPage);
                    var prevState = paginationState(prevPage, data, entryAfter);
                    applyResponse(data, prevState, "push");
                })
                .fail(function (xhr) {
                    showPaginationError(
                        $root,
                        xhr,
                        "Unable to load the previous page. Please try again."
                    );
                });
        });

        popstateHandlers.push(function (event) {
            var state = event.originalEvent.state;
            if (!state || state.opencveList !== listType || state.query !== queryKey) {
                if (!state || !state.opencveList) {
                    goToState(paginationState(1, initial, null), null).fail(function () {
                        window.location.reload();
                    });
                }
                return;
            }
            goToState(state.pagination, null).fail(function () {
                window.location.reload();
            });
        });

        $root.closest("section.content").on(
            "submit",
            "form",
            function () {
                if ($(this).find('[name="q"], [name="search"]').length > 0) {
                    clearStorage(storageKey, queryKey);
                }
            }
        );

        bootstrap();
    }

    $(document).ready(function () {
        $(window).on("popstate.opencveCursorPagination", function (event) {
            popstateHandlers.forEach(function (handler) {
                handler(event);
            });
        });

        $(".opencve-cursor-pagination").each(function () {
            mountListPagination($(this));
        });
    });
})(jQuery);