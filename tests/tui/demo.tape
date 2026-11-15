# The README's terminal demo. Recorded by tests/tui/demo.sh with vhs, against
# a real daemon in a network namespace. Nothing here is sample data.
Output demo.gif
Set Shell bash
Set FontSize 15
Set Width 960
Set Height 560
Set Padding 12
Set TypingSpeed 60ms
Set Theme { "name": "netoxide", "black": "#1b1f27", "red": "#e06c75", "green": "#8fbf7f", "yellow": "#d9b36c", "blue": "#6ca0d9", "magenta": "#b48ead", "cyan": "#6cc2c9", "white": "#c8ccd4", "brightBlack": "#6b7280", "brightRed": "#e06c75", "brightGreen": "#8fbf7f", "brightYellow": "#d9b36c", "brightBlue": "#6ca0d9", "brightMagenta": "#b48ead", "brightCyan": "#6cc2c9", "brightWhite": "#f2f4f8", "background": "#12151b", "foreground": "#c8ccd4", "cursor": "#c8ccd4", "selection": "#2a303b" }

Hide
Type "clear" Enter
Show
Type "netoxide-tui --live" Sleep 600ms Enter
Sleep 2500ms

# Live: what the box is doing right now, from the kernel's own counters.
Type "2"
Sleep 7s

# Add a network for guests, from the Home menu.
Type "1" Sleep 1200ms
Enter
Sleep 1500ms
Type "Guest Wi-Fi" Sleep 400ms
Tab Sleep 300ms Tab Sleep 300ms
Type "30" Sleep 900ms
Screenshot tui-task.png
Enter
Sleep 3500ms
Screenshot tui-review.png

# Apply it safely, check, keep it.
Enter
Sleep 3s
Type "y"
Sleep 1500ms

# Live again: the guest network has traffic of its own, and its attempt
# to reach the inside network is being blocked.
Type "2"
Sleep 11s
Screenshot tui-live.png
Sleep 1500ms
Type "p" Sleep 2s Type "p" Sleep 1s

# Who can reach what.
Type "3"
Sleep 3s
Screenshot tui-access.png

# Is something blocked? Ask the box.
Type "1" Sleep 800ms
Up Sleep 800ms
Enter Sleep 1200ms
Type "192.168.30.50" Tab Sleep 300ms
Type "192.168.10.20" Sleep 600ms
Enter
Sleep 2s
Screenshot tui-home.png
Sleep 3s
