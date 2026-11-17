package it.blackout.mesh

// Rules of "Lock GoDark" and of the one-tap answers, kept apart from the screens so unit tests run: plain Kotlin,
// no Android dependencies. The iPhone app follows the same ones (BlackoutCore, LockRules.swift).

/** An "I'm safe" from the app shortcut while GoDark is locked: it waits for the unlock, but not for long. */
object WaitingSafe {
    /** Long enough to unlock right after tapping the shortcut, too short for someone else to leave it for later. */
    const val MAX_WAIT_MS = 120_000L

    /** True if a send that started waiting at [at] still goes out at [now], both SystemClock.elapsedRealtime(). */
    fun stillWanted(at: Long, now: Long): Boolean = now >= at && now - at <= MAX_WAIT_MS
}

/** Where a one-tap answer under an "Are you safe?" alert goes. */
sealed interface AnswerTo {
    /** [code]: the saved group's code now; null: the group in use (the alert named no group). */
    data class Group(val code: String?) : AnswerTo
    /** The group that asked isn't saved on this phone any more: the answer goes nowhere, not to another group. */
    object Gone : AnswerTo
}

object AnswerGroup {
    /**
     * [asked]: the group code the alert was made with. [isSaved]: a code saved on this phone. [movedTo]: the code the
     * group of an old code has now, after a removal gave it a new one (spec "Removals and the code"), or null.
     */
    fun of(asked: String?, isSaved: (String) -> Boolean, movedTo: (String) -> String?): AnswerTo = when {
        asked.isNullOrEmpty() -> AnswerTo.Group(null)
        isSaved(asked) -> AnswerTo.Group(asked)
        else -> movedTo(asked)?.takeIf(isSaved)?.let { AnswerTo.Group(it) } ?: AnswerTo.Gone
    }
}
