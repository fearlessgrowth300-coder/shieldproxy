package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TunOwnerTest {
    @Test
    fun secondStopDoesNotCloseAgain() {
        var closes = 0
        val owner = TunOwner()
        owner.set(AutoCloseable { closes++ })
        owner.closeOnce()
        owner.closeOnce()
        assertEquals(1, closes)
    }

    @Test
    fun restartClosesEachHandleOnce() {
        var first = 0
        var second = 0
        val owner = TunOwner()
        owner.set(AutoCloseable { first++ })
        owner.closeOnce()
        owner.set(AutoCloseable { second++ })
        owner.closeOnce()
        owner.closeOnce()
        assertEquals(1, first)
        assertEquals(1, second)
    }

    @Test
    fun closeBeforeSetIsANoOp() {
        val owner = TunOwner()
        owner.closeOnce()
        owner.closeOnce()
    }

    @Test
    fun mihomoMustNotReceiveKotlinsFd() {
        assertEquals(300, TunOwner.mihomoFd(105, 300))
        assertThrows(IllegalArgumentException::class.java) {
            TunOwner.mihomoFd(105, 105)
        }
    }
}
