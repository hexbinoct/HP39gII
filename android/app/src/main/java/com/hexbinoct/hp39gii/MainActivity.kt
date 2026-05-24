package com.hexbinoct.hp39gii

import android.graphics.Bitmap
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.GridLayout
import androidx.appcompat.app.AppCompatActivity
import com.hexbinoct.hp39gii.databinding.ActivityMainBinding
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    // The Unicorn VM is single-threaded and not reentrant — serialize every
    // native call (boot, key inject, framebuffer read) onto one worker thread.
    private val vm = Executors.newSingleThreadExecutor()

    // (keycode, label) — order/layout mirrors web/main.js KEYS (6 per row).
    private data class Key(val kc: Int, val label: String)
    private val keys = listOf(
        Key(0,"F1"),Key(1,"F2"),Key(2,"F3"),Key(3,"F4"),Key(4,"F5"),Key(5,"F6"),
        Key(6,"Sym"),Key(7,"Plot"),Key(8,"Num"),Key(9,"▲"),Key(10,"▶"),Key(11,"Home"),
        Key(12,"Apps"),Key(13,"View"),Key(14,"◀"),Key(15,"▼"),Key(16,"Vars"),Key(17,"Math"),
        Key(18,"abc"),Key(19,"MENU"),Key(20,"DEL"),Key(21,"Shift"),Key(22,"Alpha"),Key(23,"X,T,θ"),
        Key(24,"("),Key(25,")"),Key(26,","),Key(27,"="),Key(28,"÷"),Key(29,"x²"),
        Key(30,"/"),Key(31,"7"),Key(32,"8"),Key(33,"9"),Key(34,"×"),Key(35,"sin"),
        Key(36,"Tab"),Key(37,"4"),Key(38,"5"),Key(39,"6"),Key(40,"−"),Key(41,"cos"),
        Key(42,"1"),Key(43,"2"),Key(44,"3"),Key(45,"+"),Key(46,"ON"),Key(47,"0"),
        Key(48,"(-)"),Key(49,"."),Key(50,"ENTER"),
    )

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

    private fun buildKeypad() {
        val grid = binding.keypad
        grid.removeAllViews()
        for (k in keys) {
            val b = Button(this).apply {
                text = k.label
                isAllCaps = false
                textSize = 12f
                setPadding(0, 0, 0, 0)
                minHeight = 0; minimumHeight = 0
                isEnabled = false
                setOnClickListener { onKey(k.kc) }
            }
            val lp = GridLayout.LayoutParams().apply {
                width = 0; height = GridLayout.LayoutParams.WRAP_CONTENT
                columnSpec = GridLayout.spec(GridLayout.UNDEFINED, 1f)
                setMargins(3, 3, 3, 3)
            }
            grid.addView(b, lp)
        }
    }

    private fun setKeypadEnabled(on: Boolean) {
        for (i in 0 until binding.keypad.childCount) binding.keypad.getChildAt(i).isEnabled = on
    }

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
