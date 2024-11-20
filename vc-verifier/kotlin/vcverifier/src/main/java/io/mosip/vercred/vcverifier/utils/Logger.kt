package io.mosip.vercred.vcverifier.utils

import java.util.logging.Logger
import java.util.logging.Level

object Logger {

    private fun log(loggerName: String, message: String, logLevel: Level) {
        val logger = Logger.getLogger(loggerName)
        logger.log(logLevel, message)
    }

    fun info(loggerName: String, message: String) {
        log(loggerName, message, Level.INFO)
    }

    fun warn(loggerName: String, message: String) {
        log(loggerName, message, Level.WARNING)
    }

    fun error(loggerName: String, message: String) {
        log(loggerName, message, Level.SEVERE)
    }

    fun debug(loggerName: String, message: String) {
        log(loggerName, message, Level.FINE)
    }

    fun trace(loggerName: String, message: String) {
        log(loggerName, message, Level.FINEST)
    }
}
