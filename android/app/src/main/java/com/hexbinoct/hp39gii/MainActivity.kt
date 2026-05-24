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

        // Phase A: prove Unicorn is linked and executes x86 on this device.
        binding.sampleText.text = unicornSelfTest()
    }

    /**
     * A native method that is implemented by the 'hp39gii' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    /** Boots a throwaway Unicorn x86 VM, runs a tiny program, reports status. */
    external fun unicornSelfTest(): String

    companion object {
        // Used to load the 'hp39gii' library on application startup.
        init {
            System.loadLibrary("hp39gii")
        }
    }
}