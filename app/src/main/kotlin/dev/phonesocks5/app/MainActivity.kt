package dev.phonesocks5.app

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.security.SecureRandom

class MainActivity : Activity() {
    private lateinit var portField: EditText
    private lateinit var usernameField: EditText
    private lateinit var passwordField: EditText
    private lateinit var statusView: TextView
    private lateinit var toggleButton: Button
    private var passphraseVisible = false
    private var notificationPermissionAsked = false

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = refreshStatus()
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        notificationPermissionAsked = state?.getBoolean("notificationPermissionAsked") ?: false
        val padding = (20 * resources.displayMetrics.density).toInt()
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(padding, padding, padding, padding)
        }

        layout.addView(TextView(this).apply {
            setText(R.string.app_name)
            textSize = 24f
        })
        layout.addView(TextView(this).apply { setText(R.string.requirement) })
        portField = EditText(this).apply {
            setHint(R.string.port_hint)
            inputType = InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            setText(state?.getString("port") ?: DEFAULT_PORT.toString())
        }
        layout.addView(portField)
        usernameField = EditText(this).apply {
            setHint(R.string.username_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
            setText(state?.getString("username") ?: DEFAULT_USERNAME)
        }
        layout.addView(usernameField)
        passwordField = EditText(this).apply {
            setHint(R.string.passphrase_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
            setText(state?.getString("password") ?: ProxyService.currentPassphrase ?: randomPassword())
            transformationMethod = PasswordTransformationMethod.getInstance()
        }
        layout.addView(passwordField)
        layout.addView(Button(this).apply {
            setText(R.string.show_passphrase)
            setOnClickListener {
                passphraseVisible = !passphraseVisible
                passwordField.transformationMethod =
                    if (passphraseVisible) null else PasswordTransformationMethod.getInstance()
                setText(if (passphraseVisible) R.string.hide_passphrase else R.string.show_passphrase)
                passwordField.setSelection(passwordField.length())
            }
        })
        toggleButton = Button(this).apply { setOnClickListener { toggle() } }
        layout.addView(toggleButton)
        statusView = TextView(this).apply { setPadding(0, padding / 2, 0, 0) }
        layout.addView(statusView)
        setContentView(ScrollView(this).apply {
            isFillViewport = true
            addView(layout)
        })
        refreshStatus()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(ProxyService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(statusReceiver, filter)
        }
        refreshStatus()
    }

    override fun onStop() {
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    override fun onSaveInstanceState(state: Bundle) {
        state.putString("port", portField.text.toString())
        state.putString("username", usernameField.text.toString())
        state.putString("password", passwordField.text.toString())
        state.putBoolean("notificationPermissionAsked", notificationPermissionAsked)
        super.onSaveInstanceState(state)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grants: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grants)
        if (requestCode == NOTIFICATION_PERMISSION_REQUEST) toggle()
    }

    private fun toggle() {
        if (ProxyService.running) {
            startService(Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_STOP))
            return
        }
        val port = portField.text.toString().trim().toIntOrNull()
        val username = usernameField.text.toString().trim()
        val passphrase = passwordField.text.toString()
        if (port == null || port !in 1024..65535) {
            portField.error = getString(R.string.port_error)
            return
        }
        if (!USERNAME_PATTERN.matches(username)) {
            usernameField.error = getString(R.string.username_error)
            return
        }
        if (!PASSPHRASE_PATTERN.matches(passphrase)) {
            passwordField.error = getString(R.string.passphrase_error)
            return
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !notificationPermissionAsked
        ) {
            notificationPermissionAsked = true
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
            return
        }
        val start = Intent(this, ProxyService::class.java)
            .setAction(ProxyService.ACTION_START)
            .putExtra(ProxyService.EXTRA_PORT, port)
            .putExtra(ProxyService.EXTRA_USERNAME, username)
            .putExtra(ProxyService.EXTRA_PASSWORD, passphrase)
        startForegroundService(start)
        statusView.setText(R.string.starting)
    }

    private fun refreshStatus() {
        statusView.text = ProxyService.status
        toggleButton.setText(if (ProxyService.running) R.string.stop else R.string.start)
        portField.isEnabled = !ProxyService.running
        usernameField.isEnabled = !ProxyService.running
        passwordField.isEnabled = !ProxyService.running
    }

    companion object {
        private const val DEFAULT_PORT = 10888
        private const val DEFAULT_USERNAME = "phone"
        private const val NOTIFICATION_PERMISSION_REQUEST = 1
        private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        private val USERNAME_PATTERN = Regex("[A-Za-z0-9._-]{1,64}")
        private val PASSPHRASE_PATTERN = Regex("[\\x21-\\x7E]{12,128}")
        private val random = SecureRandom()

        private fun randomPassword() = buildString(20) {
            repeat(20) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
        }
    }
}
