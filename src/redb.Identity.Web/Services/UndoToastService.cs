namespace redb.Identity.Web.Services;

/// <summary>
/// Optimistic-mutation orchestrator. Replaces "Are you sure?" confirm dialogs
/// for soft / reversible operations (disable, archive, hide).
///
/// Typical use:
///
///     // 1. Optimistic UI update
///     app.Enabled = false;
///     StateHasChanged();
///
///     // 2. Show toast and wait for user verdict
///     var commit = await UndoToast.PromptAsync(
///         $"Application '{app.Name}' disabled",
///         durationMs: 8000);
///
///     if (commit)
///     {
///         // Toast expired — user is fine with it. Persist.
///         await Client.DisableApplicationAsync(app.Id);
///     }
///     else
///     {
///         // User clicked Undo before the timer expired. Roll back the UI.
///         app.Enabled = true;
///         StateHasChanged();
///     }
///
/// Why this pattern instead of confirm-modal:
///   * No modal-overlay disruption — user keeps working.
///   * Optimistic feedback is immediate, server commit is delayed.
///   * The Undo affordance is one-click, not a multi-step modal Q&amp;A.
///
/// One toast at a time: if a second prompt arrives while one is on screen,
/// the first is auto-committed and removed before the second appears. This
/// matches macOS / GMail snackbar semantics.
/// </summary>
public sealed class UndoToastService
{
    /// <summary>
    /// Fired when a new prompt should be rendered. The UI component
    /// (UiUndoToast in MainLayout) subscribes once at app start.
    /// </summary>
    public event Action<UndoPrompt>? OnPrompt;

    /// <summary>
    /// Fired when the active prompt should be dismissed (either user clicked
    /// Undo, timer expired, or a new prompt is replacing it).
    /// </summary>
    public event Action? OnDismiss;

    private UndoPrompt? _current;

    /// <summary>
    /// Display an undoable action toast and wait for the user's verdict.
    /// Returns true if the timer expired (commit), false if the user clicked
    /// Undo (rollback).
    /// </summary>
    public async Task<bool> PromptAsync(string message, int durationMs = 8000)
    {
        // Replace any in-flight prompt — its tcs resolves to true (auto-commit
        // because we couldn't show it any longer). This keeps the UI from
        // stacking toasts when a user makes several quick changes.
        if (_current is not null)
        {
            _current.Tcs.TrySetResult(true);
            OnDismiss?.Invoke();
        }

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var prompt = new UndoPrompt(message, durationMs, tcs);
        _current = prompt;

        OnPrompt?.Invoke(prompt);

        // Race the timer against the user's Undo click. Whoever wins resolves
        // the tcs first; we just await the outcome.
        _ = Task.Run(async () =>
        {
            await Task.Delay(durationMs);
            // Only commit if THIS prompt is still active; otherwise it's been
            // replaced or already resolved by a user click.
            if (_current == prompt && !tcs.Task.IsCompleted)
            {
                tcs.TrySetResult(true);
                _current = null;
                OnDismiss?.Invoke();
            }
        });

        return await tcs.Task;
    }

    /// <summary>
    /// Called by the UI when the user clicks Undo. Resolves the active
    /// prompt with "false" (rollback).
    /// </summary>
    public void Undo()
    {
        if (_current is { } prompt && !prompt.Tcs.Task.IsCompleted)
        {
            prompt.Tcs.TrySetResult(false);
            _current = null;
            OnDismiss?.Invoke();
        }
    }
}

/// <summary>
/// One in-flight undo prompt — message, expected duration, and the
/// completion source the service resolves when the verdict is in.
/// </summary>
/// <param name="Message">Toast text shown to the user.</param>
/// <param name="DurationMs">Total time before auto-commit.</param>
/// <param name="Tcs">Internal completion source — true = commit, false = undo.</param>
public sealed record UndoPrompt(
    string Message,
    int DurationMs,
    TaskCompletionSource<bool> Tcs);
