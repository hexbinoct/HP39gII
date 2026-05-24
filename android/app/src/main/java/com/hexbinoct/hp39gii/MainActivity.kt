package com.hexbinoct.hp39gii

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.TextView
import com.hexbinoct.hp39gii.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Phase A self-test + Phase B headless boot of the calc core.
        val selfTest = unicornSelfTest()
        val bootLog = try {
            val exe = assets.open("HP39gII.exe").use { it.readBytes() }
            nativeBoot(exe)
        } catch (e: java.io.FileNotFoundException) {
            "HP39gII.exe not found in assets.\nDrop it in app/src/main/assets/ to boot the calc core."
        }
        binding.sampleText.text = "$selfTest\n\n$bootLog"
    }

    /**
     * A native method that is implemented by the 'hp39gii' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    /** Boots a throwaway Unicorn x86 VM, runs a tiny program, reports status. */
    external fun unicornSelfTest(): String

    /** Loads HP39gII.exe bytes, boots the calc core headless, returns the log. */
    external fun nativeBoot(exe: ByteArray): String

    companion object {
        // Used to load the 'hp39gii' library on application startup.
        init {
            System.loadLibrary("hp39gii")
        }
    }
}