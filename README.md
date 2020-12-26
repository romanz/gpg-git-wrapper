# Git wrapper for Signify-based signatures

```
$ PK=`trezor-signify pubkey "Roman Zeyde <me@romanzey.de>" | tail -n1`
$ echo "$PK Myself" > .pubkeys
$ git config --local gpg.program $PWD/gpg-wrapper.py
$ git log --color --graph --pretty=format:'%Cred%h%Creset %C(bold cyan)%G?%Creset %C(bold blue)%an%Creset: %C(yellow)%d%Creset %s %Cgreen(%cr)' --abbrev-commit --show-signature
```