package com.musheer360.swiftslate.model

import androidx.compose.runtime.Immutable

enum class CommandType {
    AI, TEXT_REPLACER
}

@Immutable
data class Command(
    val trigger: String,
    val prompt: String,
    val isBuiltIn: Boolean = false,
    val type: CommandType = CommandType.AI,
    /**
     * Optional per-command model override (smart upgrades). When set, an AI command runs on
     * this model of the active provider instead of the provider's globally selected model —
     * e.g. a fast model for `?fix`, a smarter one for `?expand`. Null means "use the global
     * model", which is every existing command's behavior.
     */
    val model: String? = null
)
