// Theme persistence: stores explicit user preference in localStorage; otherwise
// follows the OS-level prefers-color-scheme value and reacts to live changes.
(function () {
    const STORAGE_KEY = 'rdb-theme';
    const mql = window.matchMedia('(prefers-color-scheme: dark)');

    function storedPreference() {
        const v = localStorage.getItem(STORAGE_KEY);
        return v === 'dark' || v === 'light' ? v : null;
    }

    function resolved() {
        return storedPreference() ?? (mql.matches ? 'dark' : 'light');
    }

    // applyOnly: change the DOM attribute without touching localStorage.
    // This matters so we can distinguish "user has never chosen" from
    // "user explicitly picked the current OS value" \u2014 only an explicit
    // toggle should pin the preference and stop live-following the OS.
    function applyOnly(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    function applyAndStore(theme) {
        applyOnly(theme);
        localStorage.setItem(STORAGE_KEY, theme);
    }

    // N8-2: react to live OS theme changes (e.g. user flips Windows dark mode
    // while the page is open). Only when there's no explicit stored preference,
    // so we never override a deliberate user choice.
    function onSystemChange(e) {
        if (storedPreference() === null) {
            applyOnly(e.matches ? 'dark' : 'light');
        }
    }
    if (typeof mql.addEventListener === 'function') {
        mql.addEventListener('change', onSystemChange);
    } else if (typeof mql.addListener === 'function') {
        // Safari < 14 fallback
        mql.addListener(onSystemChange);
    }

    // Apply immediately to prevent flash; do NOT store on first paint so the
    // OS preference can keep flowing through subsequent visits.
    applyOnly(resolved());

    // Expose toggle for Blazor interop. Toggling is an explicit choice, so
    // we persist it and stop tracking the OS until localStorage is cleared.
    window.rdbTheme = {
        toggle: function () {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            applyAndStore(next);
            return next;
        },
        get: function () {
            return document.documentElement.getAttribute('data-theme') || 'light';
        },
        // Optional: revert to "follow OS" mode by clearing the stored override.
        reset: function () {
            localStorage.removeItem(STORAGE_KEY);
            applyOnly(mql.matches ? 'dark' : 'light');
        }
    };
})();

