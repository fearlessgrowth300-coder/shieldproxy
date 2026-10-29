package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class ElfAlignTest {
    @Test
    fun sixteenKbRealignSelfTest() {
        val script = File("../tools/realign_elf_16k.py")
        val proc = ProcessBuilder("python3", script.absolutePath, "--self-test")
            .redirectErrorStream(true)
            .start()
        val text = proc.inputStream.bufferedReader().readText()
        assertEquals(text, 0, proc.waitFor())
    }
}
