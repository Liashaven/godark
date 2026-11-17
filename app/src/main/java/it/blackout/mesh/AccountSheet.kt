package it.blackout.mesh

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

@Composable
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
fun AccountSettingsPage(back: () -> Unit) {
    val context = LocalContext.current
    var account by remember { mutableStateOf<AccountService.Account?>(null) }
    var registering by remember { mutableStateOf(false) }
    var email by remember { mutableStateOf("") }
    var displayName by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var terms by remember { mutableStateOf(false) }
    var privacy by remember { mutableStateOf(false) }
    var analytics by remember { mutableStateOf(false) }
    var diagnostics by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var diagnosticKind by remember { mutableStateOf("app_crash") }
    var deletePrompt by remember { mutableStateOf(false) }
    var deletePassword by remember { mutableStateOf("") }
    val configured = AccountService.configured()

    LaunchedEffect(configured) {
        if (configured && AccountService.storedToken(context) != null) {
            busy = true
            AccountService.account(context) { result ->
                result.onSuccess { snapshot ->
                    account = snapshot.account
                    analytics = snapshot.analyticsOptIn
                    diagnostics = snapshot.diagnosticsOptIn
                }.onFailure { account = null }
                message = if (result.isFailure) result.exceptionOrNull()?.message ?: "Account unavailable" else ""
                busy = false
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Card {
            Txt("Optional account", 18, FontWeight.Bold)
            Txt("Offline messaging works without sign-in. Account and telemetry requests use a separate HTTPS API and never use mesh, message or relay handling.", 14, color = Theme.dim)
            if (!configured) Txt("Accounts are not available in this build: the public API origin has not been configured. Nothing is sent.", 14, FontWeight.SemiBold, Theme.help)
        }
        if (account == null) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                SecondaryButton(if (registering) "Create account" else "Sign in", Modifier.weight(1f), enabled = configured) { registering = !registering; message = "" }
                SecondaryButton(if (registering) "Sign in instead" else "Register", Modifier.weight(1f), enabled = configured) { registering = !registering; message = "" }
            }
            InputField("Email", email, { email = it }, "name@example.com", keyboard = KeyboardOptions(keyboardType = KeyboardType.Email))
            if (registering) InputField("Display name", displayName, { displayName = it.take(80) }, "Your chosen name")
            OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("Password") },
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true, modifier = Modifier.fillMaxWidth())
            if (registering) {
                ConsentCheck("I accept the draft Terms of Service.", terms) { terms = it }
                ConsentCheck("I have read and acknowledge the draft Privacy Policy.", privacy) { privacy = it }
                ConsentCheck("Optional usage analytics: feature names and event timestamps only; no message contents. Off by default; deletion within 12 months.", analytics) { analytics = it }
                ConsentCheck("Optional diagnostics: app/device model, OS/app version, incident type and category hash only. Off by default; deletion within 90 days.", diagnostics) { diagnostics = it }
            }
            PrimaryButton(if (busy) "Working…" else if (registering) "Create account" else "Sign in",
                enabled = configured && !busy && email.isNotBlank() && password.isNotEmpty() && (!registering || (displayName.isNotBlank() && terms && privacy))) {
                busy = true; message = ""
                val result = { r: Result<AccountService.Session> ->
                    busy = false
                    r.fold(onSuccess = { session ->
                        account = session.account
                        analytics = false; diagnostics = false
                        password = ""; message = "Signed in"
                        AccountService.account(context) { refreshed ->
                            refreshed.fold(onSuccess = { snapshot ->
                                account = snapshot.account
                                analytics = snapshot.analyticsOptIn
                                diagnostics = snapshot.diagnosticsOptIn
                            }, onFailure = { error -> message = error.message ?: "Could not refresh account consent" })
                        }
                    }, onFailure = { error -> message = error.message ?: "Account request failed" })
                }
                if (registering) AccountService.register(context, email.trim(), displayName.trim(), password, analytics, diagnostics, result)
                else AccountService.login(context, email.trim(), password, result)
            }
            if (message.isNotEmpty()) Txt(message, 14, color = if (message == "Signed in") Theme.safe else Theme.dim)
        } else {
            Card {
                Txt(account!!.displayName, 20, FontWeight.Bold)
                Txt(account!!.email, 15, color = Theme.dim)
                Txt("Account ID: ${account!!.id}", 13, color = Theme.dim)
                if (account!!.createdAt.isNotBlank()) Txt("Created: ${account!!.createdAt}", 13, color = Theme.dim)
                if (account!!.lastLoginAt.isNotBlank()) Txt("Last sign-in: ${account!!.lastLoginAt}", 13, color = Theme.dim)
            }
            Card {
                Txt("Privacy choices", 18, FontWeight.Bold)
                ConsentCheck("Optional usage analytics: feature names and event timestamps only; no message contents. Off by default; deletion within 12 months.", analytics) { value ->
                    val oldA = analytics; analytics = value; busy = true
                    AccountService.consent(context, value, diagnostics) { result -> busy = false; if (result.isSuccess) AccountService.setConsent(context, value, diagnostics) else { analytics = oldA; message = result.exceptionOrNull()?.message ?: "Could not update consent" } }
                }
                ConsentCheck("Optional diagnostics: app/device model, OS/app version, incident type and category hash only. Off by default; deletion within 90 days.", diagnostics) { value ->
                    val oldD = diagnostics; diagnostics = value; busy = true
                    AccountService.consent(context, analytics, value) { result -> busy = false; if (result.isSuccess) AccountService.setConsent(context, analytics, value) else { diagnostics = oldD; message = result.exceptionOrNull()?.message ?: "Could not update consent" } }
                }
                Txt("Turning a choice off asks the service to remove previously collected optional data. Until the API is configured, these controls cannot save or send account preferences.", 13, color = Theme.dim)
            }
            Card {
                Txt("Manual diagnostics", 18, FontWeight.Bold)
                Txt("Only an incident category and a locally hashed category signature are submitted, alongside app/device model and OS/app version. No stack trace, message, location, contact or group data is inspected or uploaded.", 14, color = Theme.dim)
                IncidentSelector(diagnosticKind, { diagnosticKind = it }, listOf("app_crash", "startup_failure", "freeze", "other"))
                SecondaryButton("Submit diagnostic", enabled = configured && diagnostics && !busy) {
                    busy = true; AccountService.submitDiagnostic(context, diagnosticKind) { r -> busy = false; message = if (r.isSuccess) "Diagnostic submitted" else (r.exceptionOrNull()?.message ?: "Not submitted") }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SecondaryButton("Access / export account data", Modifier.weight(1f), enabled = configured && !busy) {
                    busy = true; AccountService.export(context) { result ->
                        busy = false
                        result.onSuccess { data ->
                            val share = Intent(Intent.ACTION_SEND).setType("application/json").putExtra(Intent.EXTRA_SUBJECT, "GoDark account data export").putExtra(Intent.EXTRA_TEXT, data)
                            context.startActivity(Intent.createChooser(share, "Export account data"))
                        }.onFailure { message = it.message ?: "Export failed" }
                    }
                }
                SecondaryButton("Delete account", Modifier.weight(1f), enabled = configured && !busy) { deletePrompt = true }
            }
            SecondaryButton("Sign out", enabled = configured && !busy) {
                busy = true; AccountService.logout(context) { result -> busy = false; if (result.isSuccess) { account = null; analytics = false; diagnostics = false; message = "Signed out" } else { account = null; analytics = false; diagnostics = false; message = result.exceptionOrNull()?.message ?: "Sign out failed" } }
            }
            if (message.isNotEmpty()) Txt(message, 14, color = Theme.dim)
        }
        if (busy) Txt("Please wait…", 14, color = Theme.dim)
        Txt("Account-service retention is not active in this unconfigured build. The draft policy describes intended limits, not a promise until provider backup retention has been verified.", 13, color = Theme.dim)
    }

    if (deletePrompt) {
        androidx.compose.material3.AlertDialog(onDismissRequest = { deletePrompt = false; deletePassword = "" },
            title = { Text("Delete GoDark account?") },
            text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("This requests deletion of the account and linked optional telemetry. Local messages, group keys, other phones’ copies and relay copies are not deleted.")
                OutlinedTextField(value = deletePassword, onValueChange = { deletePassword = it }, label = { Text("Confirm password") },
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true)
            } },
            confirmButton = { androidx.compose.material3.TextButton(enabled = configured && deletePassword.isNotEmpty() && !busy, onClick = {
                busy = true
                AccountService.delete(context, deletePassword) { result ->
                    busy = false; deletePrompt = false; deletePassword = ""
                    if (result.isSuccess) { account = null; analytics = false; diagnostics = false; message = "Account deleted" }
                    else message = result.exceptionOrNull()?.message ?: "Deletion failed"
                }
            }) { Text("Delete account") } },
            dismissButton = { androidx.compose.material3.TextButton(onClick = { deletePrompt = false; deletePassword = "" }) { Text("Cancel") } })
    }
}

@Composable private fun ConsentCheck(label: String, checked: Boolean, change: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(role = Role.Checkbox) { change(!checked) }, verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked, onCheckedChange = change)
        Txt(label, 14, color = Theme.dim, modifier = Modifier.weight(1f))
    }
}

@Composable
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
private fun IncidentSelector(value: String, set: (String) -> Unit, items: List<String>) {
    var expanded by remember { mutableStateOf(false) }
    androidx.compose.material3.ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        androidx.compose.material3.OutlinedTextField(value = value, onValueChange = {}, readOnly = true, label = { Text("Incident category") },
            modifier = Modifier.menuAnchor().fillMaxWidth())
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            items.forEach { item -> androidx.compose.material3.DropdownMenuItem(text = { Text(item) }, onClick = { set(item); expanded = false }) }
        }
    }
}
