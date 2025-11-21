Technical Report Content: Documenting Vulnerabilities and Mitigations 
               [BY MOHAMED MOHIEY]

1. 🛑 Vulnerability 1: Command Injection
CWE: CWE-77 (Improper Neutralization of Special Elements used in a Command) Affected File: mutillidae/src/dns-lookup.php

🐛 Vulnerable Code Snippet (PHP)
The application passes unsanitized user input ($lTargetHost) directly to the shell_exec() function, allowing an attacker to execute arbitrary system commands by injecting shell metacharacters (e.g., ;, &&).

PHP

// File: mutillidae/src/dns-lookup.php
// Issue: $lTargetHost is directly concatenated into the shell command.
$lTargetHost = $_REQUEST["target_host"];

// Execution of unsanitized command
echo '<pre class="output">'.shell_exec("nslookup " . $lTargetHost).'</pre>'; 
🛡 Secure Mitigation (PHP)
The mitigation involves using the escapeshellarg() function to sanitize the user input. This function properly quotes the input string, ensuring the operating system treats the entire value as a single, safe argument to the command.

PHP

// Mitigation: Using escapeshellarg()
$lTargetHost = $_REQUEST["target_host"];

// Sanitize the user input
$safe_target = escapeshellarg($lTargetHost);

// Execute the command using the safe argument
echo '<pre class="output">'.shell_exec("nslookup " . $safe_target).'</pre>'; 
2. 🚨 Vulnerability 2: SQL Injection
CWE: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) Affected File: mutillidae/src/edit-account-profile.php

🐛 Vulnerable Code Snippet (PHP)
The code constructs an SQL query by manually concatenating user input variables (e.g., $username, $password) into the SQL string. This allows an attacker to manipulate the query structure using special SQL characters (e.g., ', --).

PHP

// File: mutillidae/src/edit-account-profile.php (Example pattern)
$username = $_POST["username"];
$password = $_POST["password"];

// Issue: Manual string concatenation for the SQL query
$sql = "UPDATE users SET password = '$password' WHERE username = '$username'";

// Execution of the vulnerable query
mysqli_query($conn, $sql); 
🛡 Secure Mitigation (PHP)
The secure solution is to use Prepared Statements. This separates the SQL query structure from the user-provided data, ensuring the database treats the input as data only, not as executable commands.

PHP

// Mitigation: Using Prepared Statements (mysqli)
$username = $_POST["username"];
$password = $_POST["password"];

// 1. Prepare the statement with placeholders (?)
$stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");

// 2. Bind the user input variables (s=string)
$stmt->bind_param("ss", $password, $username);

// 3. Execute the statement securely
$stmt->execute();

$stmt->close();
