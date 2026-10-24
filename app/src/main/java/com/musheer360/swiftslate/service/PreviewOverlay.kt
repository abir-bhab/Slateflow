package com.musheer360.swiftslate.service

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.musheer360.swiftslate.R
import com.musheer360.swiftslate.ui.components.SlateToastTokens
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Preview-before-replace card (smart upgrades): a TYPE_ACCESSIBILITY_OVERLAY showing the
 * AI result with Replace / Keep-original actions, so the inline flow can ask before it
 * overwrites the user's text. Sibling of [OverlayToast] — same window type, tokens and
 * bottom-card placement — but touchable and decision-driven instead of auto-dismissing.
 *
 * All view work happens on the main thread via [handler]; [awaitDecision] may be called
 * from any dispatcher and resumes on the main thread.
 */
class PreviewOverlay(private val context: Context, private val handler: Handler) {

    private var currentView: View? = null
    private var timeoutRunnable: Runnable? = null

    private fun dp(value: Int): Int {
        val density = context.resources.displayMetrics.density
        return (value * density + 0.5f).toInt()
    }

    /**
     * Shows [resultText] and suspends until the user decides or [timeoutMs] passes.
     * Returns true for Replace, false for Keep-original and for timeout. If the overlay
     * cannot be shown at all, returns true — falling back to the pre-preview behavior
     * (replace immediately) rather than silently dropping a result the user asked for.
     */
    suspend fun awaitDecision(resultText: String, timeoutMs: Long = DECISION_TIMEOUT_MS): Boolean =
        suspendCancellableCoroutine { cont ->
            var decided = false
            fun decide(value: Boolean) {
                if (decided) return
                decided = true
                dismiss()
                if (cont.isActive) cont.resume(value)
            }
            handler.post {
                if (!show(resultText, onReplace = { decide(true) }, onKeep = { decide(false) })) {
                    decide(true)
                }
            }
            val timeout = Runnable { decide(false) }
            timeoutRunnable = timeout
            handler.postDelayed(timeout, timeoutMs)
            cont.invokeOnCancellation { handler.post { dismiss() } }
        }

    /** Immediately remove the preview card, if any. Main thread. */
    fun dismiss() {
        timeoutRunnable?.let { handler.removeCallbacks(it) }
        timeoutRunnable = null
        currentView?.let { view ->
            try {
                view.visibility = View.GONE
                val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                wm.removeView(view)
            } catch (_: Exception) {}
            currentView = null
        }
    }

    /** Builds and attaches the card. Returns false when the window cannot be added. */
    private fun show(resultText: String, onReplace: () -> Unit, onKeep: () -> Unit): Boolean {
        dismiss()
        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = context.resources.displayMetrics

        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(8))
            background = GradientDrawable().apply {
                setColor(SlateToastTokens.BACKGROUND_ARGB)
                cornerRadius = dp(SlateToastTokens.CORNER_RADIUS_DP).toFloat()
            }
        }

        val title = TextView(context).apply {
            text = context.getString(R.string.preview_title)
            setTextColor(Color.LTGRAY)
            textSize = 12f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        card.addView(title)

        val body = TextView(context).apply {
            text = resultText
            setTextColor(Color.WHITE)
            textSize = SlateToastTokens.TEXT_SIZE_SP.toFloat()
            setPadding(0, dp(6), 0, dp(4))
        }
        val scroll = ScrollView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            addView(body)
        }
        card.addView(scroll)
        // Cap the card so a long generation cannot cover the whole screen.
        scroll.post {
            val maxHeight = (metrics.heightPixels * MAX_HEIGHT_FRACTION).toInt()
            if (scroll.height > maxHeight) {
                scroll.layoutParams = scroll.layoutParams.apply { height = maxHeight }
            }
        }

        val buttonRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        val keepButton = Button(context).apply {
            text = context.getString(R.string.preview_keep_original)
            setTextColor(Color.LTGRAY)
            background = null
            setOnClickListener { onKeep() }
        }
        val replaceButton = Button(context).apply {
            text = context.getString(R.string.preview_replace)
            setTextColor(Color.WHITE)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            background = null
            setOnClickListener { onReplace() }
        }
        buttonRow.addView(keepButton)
        buttonRow.addView(replaceButton)
        card.addView(buttonRow)

        val params = WindowManager.LayoutParams(
            (metrics.widthPixels * MAX_WIDTH_FRACTION).toInt(),
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL
            y = dp(SlateToastTokens.BOTTOM_MARGIN_DP)
            windowAnimations = 0
        }

        return try {
            wm.addView(card, params)
            currentView = card
            true
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        /** Long enough to read a result and decide; expiry keeps the original text. */
        private const val DECISION_TIMEOUT_MS = 30_000L
        private const val MAX_WIDTH_FRACTION = 0.94
        private const val MAX_HEIGHT_FRACTION = 0.4
    }
}
