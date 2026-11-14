package com.arcium.messenger.security

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * R-18 (c): the app's data is excluded from cloud backup and from
 * device-to-device transfer, on every Android version. Reads the source
 * manifest and rules file (unit tests run in the module directory); what a
 * device does with them is not checked here.
 */
class BackupRulesTest {
    private val android = "http://schemas.android.com/apk/res/android"

    private fun xml(path: String): Element {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        return factory.newDocumentBuilder().parse(File(path)).documentElement
    }

    @Test
    fun theManifestDisablesBackupAndNamesTheRules() {
        val app = xml("src/main/AndroidManifest.xml").getElementsByTagName("application").item(0) as Element
        assertEquals("false", app.getAttributeNS(android, "allowBackup"))
        assertEquals("@xml/data_extraction_rules", app.getAttributeNS(android, "dataExtractionRules"))
    }

    @Test
    fun everyDomainIsExcludedFromBackupAndTransfer() {
        val domains = setOf(
            "root", "file", "database", "sharedpref", "external",
            "device_root", "device_file", "device_database", "device_sharedpref",
        )
        val rules = xml("src/main/res/xml/data_extraction_rules.xml")
        for (section in listOf("cloud-backup", "device-transfer")) {
            val nodes = rules.getElementsByTagName(section)
            assertEquals("one <$section>", 1, nodes.length)
            val el = nodes.item(0) as Element
            assertEquals("no <include> in <$section>", 0, el.getElementsByTagName("include").length)
            val excluded = (0 until el.getElementsByTagName("exclude").length)
                .map { el.getElementsByTagName("exclude").item(it) as Element }
                .filter { it.getAttribute("path") == "." }
                .map { it.getAttribute("domain") }
                .toSet()
            assertTrue("$section excludes ${domains - excluded}", excluded.containsAll(domains))
        }
    }
}
