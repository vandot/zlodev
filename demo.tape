# zlodev TUI demo recording
# Prerequisites: zlodev install && gunicorn httpbin:app -b 0.0.0.0:9000
# Run: vhs demo.tape

Output docs/demo.gif
Output docs/demo.webm

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 50ms
Set WindowBar Colorful
Set WindowBarSize 40

# Start traffic generator in background
Hide
Type "./demo-traffic.sh &"
Enter
Sleep 500ms
Show

# Show the start command
Type "zlodev start --port=9000"
Sleep 500ms
Enter

Sleep 2s
Type "i"
Sleep 2s
Type "req: /put"
Sleep 2s
Enter

Sleep 1s
Enter

Sleep 2s
Type "q"

Sleep 1s
Type "d"

# Wait for TUI to render and traffic to flow
Sleep 6s

Up
Sleep 1s
Up
Sleep 1s
Type "R"

# Let the user see the populated TUI
Sleep 5s
