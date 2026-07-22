!define FRACTONICA_FIREWALL_RULE "Fractonica Local Network (Private)"

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Allowing Fractonica on Private local networks"
  nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name="${FRACTONICA_FIREWALL_RULE}"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall add rule name="${FRACTONICA_FIREWALL_RULE}" dir=in action=allow program="$INSTDIR\fractonica-node.exe" enable=yes profile=private protocol=TCP localport=8789 edge=no'
  Pop $0
  DetailPrint "Fractonica Windows Firewall command returned $0"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing the Fractonica Private-network firewall rule"
  nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name="${FRACTONICA_FIREWALL_RULE}" program="$INSTDIR\fractonica-node.exe"'
  Pop $0
!macroend
