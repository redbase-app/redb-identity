// URL-fragment helpers for UiTabBar deep-linking.
//
// We use the hash fragment (#tab=…) instead of a query string so it does not
// pollute server-side request logs, doesn't trigger a navigation round-trip,
// and matches the WSO2 IS 7.x console behaviour (e.g. .../applications/{id}#tab=1).
//
// Blazor invokes these via IJSRuntime; nothing is wired up automatically here.
(function () {
    function parseTab() {
        const hash = window.location.hash || '';
        const m = hash.match(/(?:^#|&)tab=([^&]+)/);
        return m ? decodeURIComponent(m[1]) : null;
    }

    function buildHash(tabId, existingHash) {
        // Preserve any other fragment params (rare, but possible — e.g. an OIDC implicit
        // response). We only manage the "tab=" segment.
        const base = (existingHash || '').replace(/^#/, '');
        const parts = base.split('&').filter(p => p && !p.startsWith('tab='));
        parts.push('tab=' + encodeURIComponent(tabId));
        return '#' + parts.join('&');
    }

    window.rdbTabBar = {
        // Returns the current tab id from the URL fragment, or null when absent.
        getTab: function () {
            return parseTab();
        },

        // Replace the current URL fragment with the given tab id, preserving any
        // sibling fragment params. Uses history.replaceState so the back button
        // is not polluted with tab switches.
        setTab: function (tabId) {
            const next = buildHash(tabId, window.location.hash);
            history.replaceState(null, '', window.location.pathname + window.location.search + next);
        },

        // Subscribe to hashchange events — Blazor passes a DotNetObjectReference back
        // so we can invoke its OnHashChanged method when the fragment changes
        // (e.g. user navigates the back button across tabs).
        // Returns a cleanup id the caller can pass to unsubscribe later.
        subscribe: function (dotNetRef) {
            const handler = function () {
                const tab = parseTab();
                dotNetRef.invokeMethodAsync('OnHashChanged', tab);
            };
            window.addEventListener('hashchange', handler);
            // Stash handler so unsubscribe can detach the exact same closure.
            const id = '_rdb_tabbar_sub_' + Date.now() + '_' + Math.floor(Math.random() * 1e6);
            window[id] = handler;
            return id;
        },

        unsubscribe: function (id) {
            if (id && window[id]) {
                window.removeEventListener('hashchange', window[id]);
                delete window[id];
            }
        }
    };
})();
