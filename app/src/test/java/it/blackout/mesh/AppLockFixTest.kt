package it.blackout.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLockFixTest {
    // The "I'm safe" shortcut used while DarkProof is locked.

    @Test fun waitingSafeGoesOutRightAfterTheShortcut() {
        assertTrue(WaitingSafe.stillWanted(at = 1_000, now = 1_000))
        assertTrue(WaitingSafe.stillWanted(at = 1_000, now = 1_000 + 30_000))
        assertTrue(WaitingSafe.stillWanted(at = 1_000, now = 1_000 + WaitingSafe.MAX_WAIT_MS))
    }

    @Test fun waitingSafeIsDroppedWhenTheUnlockComesLater() {
        assertFalse(WaitingSafe.stillWanted(at = 1_000, now = 1_000 + WaitingSafe.MAX_WAIT_MS + 1))
        assertFalse(WaitingSafe.stillWanted(at = 1_000, now = 1_000 + 10 * 60_000)) // ten minutes: the claim's case
        assertFalse(WaitingSafe.stillWanted(at = 1_000, now = 999)) // a time before it started: not trusted
    }

    // Answers under an "Are you safe?" notification.

    private val saved = setOf("NEW-CODE", "IN-USE")
    private val moves = mapOf("OLD-CODE" to "NEW-CODE", "LEFT-CODE" to "NOT-SAVED")
    private fun of(asked: String?) = AnswerGroup.of(asked, { it in saved }, { moves[it] })

    @Test fun answerGoesToTheSavedGroupThatAsked() {
        assertEquals(AnswerTo.Group("NEW-CODE"), of("NEW-CODE"))
        assertEquals(AnswerTo.Group(null), of(null)) // no group named: the group in use, as before
    }

    @Test fun answerFollowsTheAskingGroupToItsNewCode() {
        assertEquals(AnswerTo.Group("NEW-CODE"), of("OLD-CODE"))
    }

    @Test fun answerForAGroupNoLongerSavedGoesNowhere() {
        assertEquals(AnswerTo.Gone, of("UNKNOWN"))
        assertEquals(AnswerTo.Gone, of("LEFT-CODE")) // moved, but its new code isn't saved here either
    }

    @Test fun anEmptyGroupMeansNoneNamed() {
        assertEquals(AnswerTo.Group(null), of("")) // as on the iPhone, where an alert without a group carries ""
    }
}
