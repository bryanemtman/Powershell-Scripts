Add-Type -Namespace Win -Name Input -MemberDefinition '[DllImport("user32.dll")] public static extern bool BlockInput(bool f);'

$p = @(
  'https://www.youtube.com/watch?v=xvFZjo5PgG0',
  'https://www.youtube.com/watch?v=kutumaLYK18&t=31s',
  'https://youtu.be/B_EPCjcelAE?t=9',
  'https://youtu.be/GgyZi2asm6w?t=18'
)

try {
  [Win.Input]::BlockInput($true) | Out-Null
  foreach ($i in $p) {
    Start-Process $i
    Start-Sleep -Seconds 3
  }
  Start-Sleep -Seconds 10   # how it long stays "locked out"
}
finally {
  [Win.Input]::BlockInput($false) | Out-Null   # re-enable, even on error
}
