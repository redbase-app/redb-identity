// Sidebar collapse / expand persistence.
//
// Mirrors theme.js: we keep an explicit user choice in localStorage and apply
// it on every paint (before Blazor hydrates) so the slim/expanded sidebar does
// not flash. The state is reflected as a class on <html> ('rdb-sidebar-collapsed')
// so CSS in app.css can pick it up without any inline style or Blazor render.
//
// Default: expanded. Mobile narrow viewports (<768px) auto-collapse on first
// paint only — we still respect an explicit toggle after that.
(function () {
    const STORAGE_KEY = 'rdb-sidebar-collapsed';
    const HTML_CLASS = 'rdb-sidebar-collapsed';
    const MOBILE_BREAKPOINT = 768;

    function storedPreference() {
        const v = localStorage.getItem(STORAGE_KEY);
        return v === 'true' || v === 'false' ? v === 'true' : null;
    }

    function resolved() {
        const stored = storedPreference();
        if (stored !== null) return stored;
        // First paint with no choice yet — collapse on mobile widths.
        return window.innerWidth < MOBILE_BREAKPOINT;
    }

    function applyOnly(collapsed) {
        if (collapsed) {
            document.documentElement.classList.add(HTML_CLASS);
        } else {
            document.documentElement.classList.remove(HTML_CLASS);
        }
    }

    function applyAndStore(collapsed) {
        applyOnly(collapsed);
        localStorage.setItem(STORAGE_KEY, String(collapsed));
    }

    // Apply immediately to prevent flash.
    applyOnly(resolved());

    // Expose toggle for Blazor interop.
    window.rdbSidebar = {
        toggle: function () {
            const current = document.documentElement.classList.contains(HTML_CLASS);
            const next = !current;
            applyAndStore(next);
            return next;
        },
        get: function () {
            return document.documentElement.classList.contains(HTML_CLASS);
        },
        // Optional: clear the user choice so the auto-mobile-collapse heuristic
        // takes over again on the next load.
        reset: function () {
            localStorage.removeItem(STORAGE_KEY);
            applyOnly(resolved());
        }
    };
})();
