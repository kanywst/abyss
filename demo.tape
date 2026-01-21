# vhs configuration for Abyss demo

Output demo.gif

# --- Visual Settings ---
Set FontSize 18
Set Width 1200
Set Height 750
Set Padding 40
Set LineHeight 1.2

# --- Theme & Window (Modern Look) ---
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"
Set BorderRadius 12
Set Margin 20
Set MarginFill "#1e1e2e"

# --- Cursor & Typing ---
Set CursorBlink true
Set TypingSpeed 60ms

# --- Setup (Hidden) ---
Hide
# プロンプトをモダンにする設定
Type "export PS1='\[\033[38;2;137;180;250m\]➜ \[\033[38;2;245;224;220m\]abyss \[\033[0m\]'"
Enter
Type "clear"
Enter
Show

# --- Scenario ---

# Title
Type "echo '>>> Initializing Abyss v0.0.2: Total Recall'"
Sleep 200ms
Enter
Sleep 1s
Type "clear"
Enter

# Run Command
Type "abyss -t scanme.nmap.org"
Sleep 500ms
Enter

# Output Waiting (Scanning takes time due to parallel tasks)
Sleep 6s

# Demonstration of JSON Pipeline
Type "clear"
Enter
Sleep 500ms
Type "# Pipeline integration with jq"
Enter
Type "abyss -t scanme.nmap.org --quiet | jq '.geo_intelligence'"
Sleep 500ms
Enter
Sleep 3s

# End
Type "clear"
Enter
Type "echo '>>> Scan Complete. Report generated.'"
Sleep 1s
Enter
Sleep 2s