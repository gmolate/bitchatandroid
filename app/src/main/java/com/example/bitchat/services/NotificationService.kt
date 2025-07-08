package com.example.bitchat.services

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.example.bitchat.MainActivity // Ensure this import is correct
import com.example.bitchat.R // Ensure this import is correct (for app icon)

class NotificationService(private val context: Context) {

    companion object {
        private const val TAG = "NotificationService"
        const val MESSAGE_CHANNEL_ID = "BITCHAT_MESSAGE_CHANNEL"
        private const val MESSAGE_CHANNEL_NAME = "BitChat Messages"
        private const val MESSAGE_CHANNEL_DESCRIPTION = "Notifications for new BitChat messages"
    }

    init {
        createMessageNotificationChannel()
    }

    private fun createMessageNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH // Or other importance levels
            val channel = NotificationChannel(MESSAGE_CHANNEL_ID, MESSAGE_CHANNEL_NAME, importance).apply {
                description = MESSAGE_CHANNEL_DESCRIPTION
                // Configure other channel properties if needed (e.g., lights, vibration)
                // enableLights(true)
                // lightColor = Color.CYAN
                // enableVibration(true)
            }
            val notificationManager: NotificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
            Log.d(TAG, "Message notification channel created.")
        }
    }

    fun showNewMessageNotification(sender: String, messageText: String, channelName: String, messageId: Int) {
        // Intent to launch MainActivity when notification is tapped
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            // TODO: Optionally, add extras to navigate to the specific chat/channel
            // putExtra("channel_name", channelName)
        }
        val pendingIntent: PendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = NotificationCompat.Builder(context, MESSAGE_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher) // Replace with your app's notification icon
            .setContentTitle("New message in #$channelName from $sender")
            .setContentText(messageText)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true) // Dismiss notification when tapped
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            // .setGroup(GROUP_KEY_MESSAGES) // Optional: Group notifications

        // TODO: Add actions (e.g., "Reply", "Mark as Read") if desired
        // TODO: For stacked notifications (multiple messages from same channel/sender), use NotificationCompat.MessagingStyle

        with(NotificationManagerCompat.from(context)) {
            // notificationId is a unique int for each notification that you must define
            // Using messageId (or a hash of it) can help update/cancel specific notifications
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                 notify(messageId, builder.build())
                 Log.d(TAG, "New message notification shown for ID: $messageId")
            } else {
                Log.w(TAG, "POST_NOTIFICATIONS permission not granted. Cannot show notification.")
                // The app should request this permission at runtime on Android 13+
            }
        }
    }

    fun cancelNotification(notificationId: Int) {
        with(NotificationManagerCompat.from(context)) {
            cancel(notificationId)
            Log.d(TAG, "Notification cancelled for ID: $notificationId")
        }
    }
}
