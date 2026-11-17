package it.blackout.mesh

import android.app.Activity
import android.content.ClipData
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.widget.Toast
import java.io.File

/**
 * Hands this app's own APK to another Android phone without internet: the Android share sheet offers Quick Share
 * (Nearby Share) and Bluetooth. Needs no library: [ApkProvider] serves the installed APK read-only.
 */
object ApkShare {
    private const val MIME = "application/vnd.android.package-archive"
    val URI: Uri = Uri.parse("content://it.darkproof.mesh.apk/GoDark.apk")

    fun share(a: Activity) {
        if (a.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) { // it has test hooks any app could use
            Toast.makeText(a, "A test build of GoDark can't be shared.", Toast.LENGTH_LONG).show(); return
        }
        if (!a.applicationInfo.splitSourceDirs.isNullOrEmpty()) {
            // Installed as split APKs (e.g. from an app store bundle): the base APK alone would not install.
            Toast.makeText(a, "This copy of GoDark was installed in parts and can't be shared as one file.", Toast.LENGTH_LONG).show()
            return
        }
        val send = Intent(Intent.ACTION_SEND).setType(MIME).putExtra(Intent.EXTRA_STREAM, URI)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .apply { clipData = ClipData.newRawUri("GoDark.apk", URI) } // lets the share sheet itself read it too
        a.startActivity(Intent.createChooser(send, "Share GoDark with Quick Share or Bluetooth"))
        Toast.makeText(a, "On the other phone: open the file and allow installing apps from that source.", Toast.LENGTH_LONG).show()
    }
}

/** Read-only access to the installed APK, so the share sheet can send it. */
class ApkProvider : ContentProvider() {
    private fun apk() = File(context!!.applicationInfo.sourceDir)

    override fun onCreate() = true
    override fun getType(uri: Uri) = "application/vnd.android.package-archive"
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor =
        ParcelFileDescriptor.open(apk(), ParcelFileDescriptor.MODE_READ_ONLY)

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, args: Array<out String>?, sort: String?): Cursor =
        MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)).apply { addRow(arrayOf<Any>("GoDark.apk", apk().length())) }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, args: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, args: Array<out String>?) = 0
}
