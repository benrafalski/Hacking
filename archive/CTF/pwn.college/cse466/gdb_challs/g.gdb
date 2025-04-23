run
break *main+620 
commands 
  jump *main+630
  continue 
end
break *main+682
commands
  set $rdx = *(unsigned long long *)($rbp-0x18)
  continue 
end
continue
