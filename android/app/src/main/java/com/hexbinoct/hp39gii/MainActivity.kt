package com.hexbinoct.hp39gii

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.TextViewCompat
import com.hexbinoct.hp39gii.databinding.ActivityMainBinding
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    // The Unicorn VM is single-threaded and not reentrant — serialize every
    // native call (boot, key inject, framebuffer read) onto one worker thread.
    private val vm = Executors.newSingleThreadExecutor()

    // shift = blue secondary (printed top of key on the real HP), alpha = red letter.
    // Secondaries are read off the physical HP 39gII face plate; some alpha letters
    // are left blank where the photo is ambiguous — fill them in as confirmed.
    private data class Key(
        val kc: Int, val label: String,
        val shift: String? = null, val alpha: String? = null,
    )
    // Physical HP 39gII face plate. Labels + blue (shift) + red (alpha) read off the
    // photo. KEYCODES are the calc-OS values from the skin files (`key="(",28`, etc.) —
    // the same numbers fed to FN_PRESS_KEY/the 64-bit keymask. The face plate is a clean
    // 5-column grid; the skin's ASCII anchors ( ( ) / 7 8 9 * 4 5 6 - 1 2 3 + 0 ) pin it
    // exactly, so the un-anchored function keys follow by grid position.
    private val keys = listOf(
        Key(0,"F1"),Key(1,"F2"),Key(2,"F3"),Key(3,"F4"),Key(4,"F5"),Key(5,"F6"),
        Key(6,"Symb",shift="Setup"),Key(7,"Plot",shift="Setup"),Key(8,"Num",shift="Setup"),
        Key(11,"Home",shift="Modes"),Key(12,"Apps",shift="Info"),Key(13,"Views",shift="Help"),
        Key(9,"▲"),Key(10,"▶"),Key(14,"◀"),Key(15,"▼"),
        Key(16,"Vars",shift="Chars",alpha="A"),Key(17,"Math",shift="Cmds",alpha="B"),
        Key(18,"a b/c",alpha="C"),Key(19,"X,T,θ,N",shift="EEX",alpha="D"),Key(20,"⌫",shift="Clear"),
        Key(21,"SIN",shift="ASIN",alpha="E"),Key(22,"COS",shift="ACOS",alpha="F"),
        Key(23,"TAN",shift="ATAN",alpha="G"),Key(24,"LN",shift="eˣ",alpha="H"),Key(25,"LOG",shift="10ˣ",alpha="I"),
        Key(26,"x²",shift="√",alpha="J"),Key(27,"xʸ",shift="ⁿ√",alpha="K"),
        Key(28,"(",shift="Copy",alpha="L"),Key(29,")",shift="Paste",alpha="M"),Key(30,"÷",shift="x⁻¹",alpha="N"),
        Key(31,"'",shift="Mem",alpha="O"),Key(32,"7",shift="List",alpha="P"),Key(33,"8",shift="{",alpha="Q"),
        Key(34,"9",shift="}",alpha="R"),Key(35,"×",shift="!",alpha="S"),
        Key(36,"ALPHA"),Key(37,"4",shift="Matrix",alpha="T"),Key(38,"5",shift="[",alpha="U"),
        Key(39,"6",shift="]",alpha="V"),Key(40,"−",shift="∡",alpha="W"),
        Key(41,"SHIFT"),Key(42,"1",shift="Prgm",alpha="X"),Key(43,"2",shift="i",alpha="Y"),
        Key(44,"3",shift="π",alpha="Z"),Key(45,"+",shift="Σ"),
        Key(46,"ON/C",shift="OFF"),Key(47,"0",shift="Notes"),Key(49,".",shift="=",alpha=":"),
        Key(48,"(-)",shift="ABS",alpha=";"),Key(50,"ENTER",shift="ANS"),
    )
    private val byKc = keys.associateBy { it.kc }
    // Light "white" keys on the real device: digits and the four arithmetic operators.
    private val numKc = setOf(32,33,34,37,38,39,42,43,44,47,49,30,35,40,45)
    private val kcShift = 41
    private val kcAlpha = 36

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        buildKeypad()

        vm.execute {
            val ok = try {
                val exe = assets.open("HP39gII.exe").use { it.readBytes() }
                nativeBoot(exe)
                nativeBooted()
            } catch (e: java.io.FileNotFoundException) {
                false
            }
            runOnUiThread {
                binding.statusText.text =
                    if (ok) "HP 39gII — booted under Unicorn"
                    else "HP39gII.exe missing from assets/"
                setKeypadEnabled(ok)
            }
            if (ok) refresh()
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun lighten(c: Int): Int {
        fun up(x: Int) = (x + (255 - x) * 30 / 100).coerceAtMost(255)
        return Color.rgb(up(Color.red(c)), up(Color.green(c)), up(Color.blue(c)))
    }

    private fun keyBackground(base: Int): StateListDrawable {
        fun rect(color: Int) = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(8).toFloat()
            setColor(color)
            setStroke(dp(1), 0xFF5A5A5A.toInt())
        }
        return StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_pressed), rect(lighten(base)))
            addState(intArrayOf(), rect(base))
        }
    }

    private val shiftBlue = 0xFF3FA9E0.toInt()   // HP "Shift" cyan-blue
    private val alphaRed  = 0xFFE0703A.toInt()   // HP "Alpha" orange-red

    /** A key is a FrameLayout: main label centered, blue shift top-left, red alpha top-right. */
    private fun makeKey(k: Key): FrameLayout {
        val accent  = 0xFF2E6CA2.toInt()       // ENTER
        val shiftBg = 0xFF2F6FB5.toInt()       // SHIFT key (HP blue)
        val alphaBg = 0xFFB5601C.toInt()       // ALPHA key (HP orange)
        val numBg   = 0xFF45454C.toInt()       // digits / operators
        val fnBg    = 0xFF2C2C30.toInt()       // function keys
        val base = when {
            k.kc == 50 -> accent
            k.kc == kcShift -> shiftBg
            k.kc == kcAlpha -> alphaBg
            k.kc in numKc -> numBg
            else -> fnBg
        }
        val light = k.kc in numKc || k.kc == 50 || k.kc == kcShift || k.kc == kcAlpha
        val mainColor = if (light) Color.WHITE else 0xFFCBCBCB.toInt()

        // Secondary labels sit in the BOTTOM corners, inset from the edges.
        fun corner(text: String, color: Int, atStart: Boolean) = TextView(this).apply {
            this.text = text
            setTextColor(color)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            includeFontPadding = false
            val g = Gravity.BOTTOM or (if (atStart) Gravity.START else Gravity.END)
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT,
                FrameLayout.LayoutParams.WRAP_CONTENT, g).apply {
                bottomMargin = dp(5)
                if (atStart) marginStart = dp(6) else marginEnd = dp(6)
            }
        }

        // Main label sits near the top, leaving the bottom for the secondaries.
        val main = TextView(this).apply {
            text = k.label
            setTextColor(mainColor)
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            includeFontPadding = false
            setPadding(0, dp(5), 0, 0)
            // Auto-size so long labels (X,T,θ,N, ALPHA, ENTER) never clip.
            TextViewCompat.setAutoSizeTextTypeUniformWithConfiguration(
                this, 9, 16, 1, TypedValue.COMPLEX_UNIT_SP)
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT)
        }

        return FrameLayout(this).apply {
            background = keyBackground(base)
            setPadding(dp(3), dp(2), dp(3), dp(2))
            isEnabled = false
            addView(main)
            k.shift?.let { addView(corner(it, shiftBlue, atStart = true)) }
            k.alpha?.let { addView(corner(it, alphaRed,  atStart = false)) }
            setOnClickListener { onKey(k.kc) }
        }
    }

    private val km by lazy { dp(3) }   // uniform gap between keys

    private fun emptyCell(weight: Float) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, weight)
    }

    /** One horizontal strip of keys (by keycode); pass null for an empty cell. */
    private fun keyRow(kcs: List<Int?>, heightWeight: Float = 1f): LinearLayout {
        val rl = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, heightWeight)
        }
        for (kc in kcs) {
            if (kc == null) { rl.addView(emptyCell(1f)); continue }
            val b = makeKey(byKc.getValue(kc))
            b.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 1f)
                .apply { setMargins(km, km, km, km) }
            rl.addView(b)
        }
        return rl
    }

    /** Symb/Plot/Num over Home/Apps/Views (left) beside a 4-way arrow cross (right). */
    private fun clusterRow(): LinearLayout {
        val left = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 3f)
            addView(keyRow(listOf(6, 7, 8)))
            addView(keyRow(listOf(11, 12, 13)))
        }
        // 3x3 nav cross: arrows at N/E/S/W, empty centre + corners.
        val nav = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 2f)
            addView(keyRow(listOf(null, 9, null)))    // ▲
            addView(keyRow(listOf(14, null, 10)))     // ◀ ▶
            addView(keyRow(listOf(null, 15, null)))    // ▼
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 2f)   // two key-rows tall
            addView(left)
            addView(nav)
        }
    }

    private fun buildKeypad() {
        val pad = binding.keypad
        pad.removeAllViews()
        pad.addView(keyRow(listOf(0, 1, 2, 3, 4, 5)))        // F1–F6
        pad.addView(clusterRow())                             // Symb/.. + nav
        pad.addView(keyRow(listOf(16, 17, 18, 19, 20)))       // Vars Math a b/c X,T,θ,N ⌫
        pad.addView(keyRow(listOf(21, 22, 23, 24, 25)))       // SIN COS TAN LN LOG
        pad.addView(keyRow(listOf(26, 27, 28, 29, 30)))       // x² xʸ ( ) ÷
        pad.addView(keyRow(listOf(31, 32, 33, 34, 35)))       // ' 7 8 9 ×
        pad.addView(keyRow(listOf(36, 37, 38, 39, 40)))       // ALPHA 4 5 6 −
        pad.addView(keyRow(listOf(41, 42, 43, 44, 45)))       // SHIFT 1 2 3 +
        pad.addView(keyRow(listOf(46, 47, 49, 48, 50)))       // ON/C 0 . (-) ENTER
    }

    private fun forEachKey(action: (FrameLayout) -> Unit) {
        fun walk(g: LinearLayout) {
            for (i in 0 until g.childCount) {
                when (val v = g.getChildAt(i)) {
                    is FrameLayout -> action(v)
                    is LinearLayout -> walk(v)
                }
            }
        }
        walk(binding.keypad)
    }

    private fun setKeypadEnabled(on: Boolean) = forEachKey { it.isEnabled = on }

    private fun onKey(kc: Int) {
        vm.execute { nativeInjectKey(kc); refresh() }
    }

    /** Read the framebuffer (on the VM thread) and post the bitmap to the UI. */
    private fun refresh() {
        val w = 256; val h = 127
        val fb = nativeFramebuffer() ?: return
        val px = IntArray(w * h)
        for (i in 0 until w * h) {
            val g = fb[i].toInt() and 0xFF
            px[i] = (0xFF shl 24) or (g shl 16) or (g shl 8) or g
        }
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bmp.setPixels(px, 0, w, 0, 0, w, h)
        val big = Bitmap.createScaledBitmap(bmp, w * 3, h * 3, false)  // crisp pixels
        runOnUiThread { binding.fbImage.setImageBitmap(big) }
    }

    // --- native (libhp39gii.so) ---
    external fun nativeBoot(exe: ByteArray): String
    external fun nativeBooted(): Boolean
    external fun nativeInjectKey(keycode: Int)
    external fun nativeFramebuffer(): ByteArray?

    companion object {
        init { System.loadLibrary("hp39gii") }
    }
}
